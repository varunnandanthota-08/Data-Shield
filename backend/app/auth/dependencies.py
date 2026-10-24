from datetime import datetime, timezone
from typing import Callable, List, Optional
from fastapi import Cookie, Depends, Header, HTTPException, Request, status
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from app.auth.models import UserResponse, UserRole
from app.auth.repository import token_revocation_repo, user_repo
from app.auth.security import decode_access_token, verify_csrf_token

# Explicit Permission Matrix mapping granular capabilities to roles
PERMISSION_MATRIX = {
    "users:read": [UserRole.ADMIN],
    "users:manage": [UserRole.ADMIN],
    "policies:read": [UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER],
    "policies:write": [UserRole.ADMIN],
    "policies:delete": [UserRole.ADMIN],
    "scan:execute": [UserRole.ADMIN, UserRole.ANALYST],
    "scan:read": [UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER],
    "audit:read": [UserRole.ADMIN, UserRole.ANALYST],
    "audit:verify": [UserRole.ADMIN, UserRole.ANALYST],
    "metrics:read": [UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER],
}


async def get_token_from_header_or_cookie(
    request: Request,
    authorization: Optional[str] = Header(default=None),
    session_token: Optional[str] = Cookie(default=None),
    csrf_token: Optional[str] = Cookie(default=None),
    x_csrf_token: Optional[str] = Header(default=None, alias="X-CSRF-Token"),
) -> str:
    """Extracts and validates bearer token from Authorization header or HttpOnly session cookie.
    Enforces strict CSRF token validation whenever ambient cookie authentication is used
    on state-changing HTTP methods (POST, PUT, DELETE, PATCH).
    """
    # 1. Direct Bearer token in Authorization header (standard programmatic/API client)
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()

    # 2. HttpOnly session cookie authentication (browser client)
    if session_token:
        # State-changing operations via cookie auth must supply valid matching CSRF token
        if request.method.upper() in {"POST", "PUT", "DELETE", "PATCH"}:
            if not verify_csrf_token(x_csrf_token, csrf_token):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="CSRF token validation failed for cookie-authenticated request",
                )
        return session_token.strip()

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_current_user(
    token: str = Depends(get_token_from_header_or_cookie),
) -> UserResponse:
    """Validates JWT access token, verifies signature, revocation status, active user state,
    and user-level session invalidation timestamps in SQLite.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    expired_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication token has expired",
        headers={"WWW-Authenticate": "Bearer"},
    )
    revoked_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication token has been revoked or invalidated",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = decode_access_token(token)
        user_id: Optional[str] = payload.get("sub")
        jti: Optional[str] = payload.get("jti")
        token_iat: Optional[int] = payload.get("iat")
        if not user_id:
            raise credentials_exception
    except ExpiredSignatureError:
        raise expired_exception
    except (InvalidTokenError, Exception):
        raise credentials_exception

    # 1. Check if token's unique ID (jti) has been explicitly revoked in SQLite
    if jti and token_revocation_repo.is_revoked(jti):
        raise revoked_exception

    # 2. Check user existence and active status in database
    user_data = user_repo.get_by_id(user_id)
    if not user_data or not user_data.get("is_active"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive or not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 3. Check if user's sessions were invalidated prior to token issue (e.g. password change, deactivation)
    tokens_revoked_before = user_data.get("tokens_revoked_before")
    if tokens_revoked_before and token_iat:
        try:
            revoked_dt = datetime.fromisoformat(tokens_revoked_before.replace("Z", "+00:00"))
            revoked_ts = revoked_dt.timestamp()
            if float(token_iat) < revoked_ts:
                raise revoked_exception
        except (ValueError, TypeError):
            pass

    return UserResponse(
        id=user_data["id"],
        username=user_data["username"],
        email=user_data["email"],
        role=UserRole(user_data["role"]),
        org_id=user_data["org_id"],
        is_active=bool(user_data["is_active"]),
        created_at=user_data["created_at"],
        updated_at=user_data["updated_at"],
        last_login_at=user_data.get("last_login_at"),
    )


def require_roles(allowed_roles: List[UserRole]) -> Callable:
    """Factory creating an authorization dependency restricting endpoints to specified roles."""
    async def role_checker(current_user: UserResponse = Depends(get_current_user)) -> UserResponse:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions for this operation. Required role: {', '.join(r.value for r in allowed_roles)}",
            )
        return current_user
    return role_checker


def require_permission(permission: str) -> Callable:
    """Factory creating an authorization dependency checking the explicit permission matrix."""
    allowed_roles = PERMISSION_MATRIX.get(permission, [UserRole.ADMIN])
    return require_roles(allowed_roles)


# Common Role Dependencies
require_admin = require_roles([UserRole.ADMIN])
require_analyst_or_admin = require_roles([UserRole.ADMIN, UserRole.ANALYST])
require_authenticated = require_roles([UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER])
