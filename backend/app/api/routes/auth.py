import uuid
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from app.auth.models import (
    BootstrapStatusResponse,
    LoginRequest,
    RegisterRequest,
    RegistrationStatusResponse,
    SetupAdminRequest,
    TokenResponse,
    UserResponse,
    UserRole,
)
from app.auth.dependencies import get_current_user, get_token_from_header_or_cookie
from app.auth.rate_limiter import auth_rate_limiter, get_client_ip
from app.auth.repository import token_revocation_repo, user_repo
from app.auth.security import (
    create_access_token,
    decode_access_token,
    generate_csrf_token,
    hash_password,
    verify_dummy_password,
    verify_password,
)
from app.core.config import settings

router = APIRouter(prefix="/v1/auth", tags=["Authentication & Identity"])


@router.get(
    "/bootstrap-status",
    response_model=BootstrapStatusResponse,
    summary="Check Administrator Bootstrap Status",
    description="Indicates whether initial system administrator setup is required (zero users in database).",
)
async def check_bootstrap_status() -> BootstrapStatusResponse:
    user_count = user_repo.count_users()
    return BootstrapStatusResponse(
        requires_bootstrap=(user_count == 0),
        user_count=user_count,
    )


@router.get(
    "/registration-status",
    response_model=RegistrationStatusResponse,
    summary="Check Account Registration Status",
    description="Indicates whether public self-registration is enabled by policy or if accounts are administrator-managed.",
)
async def get_registration_status() -> RegistrationStatusResponse:
    user_count = user_repo.count_users()
    return RegistrationStatusResponse(
        allow_public_registration=settings.ALLOW_PUBLIC_REGISTRATION,
        requires_bootstrap=(user_count == 0),
        user_creation_model="public_self_registration" if settings.ALLOW_PUBLIC_REGISTRATION else "administrator_managed",
        registration_mode="public" if settings.ALLOW_PUBLIC_REGISTRATION else "admin_provisioned",
    )


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Public User Registration",
    description="Registers a new user account with Viewer role when enabled by policy. Disabled by default in enterprise SOC.",
)
async def register_user(
    payload: RegisterRequest,
    request: Request,
) -> UserResponse:
    # 1. Enforce policy check: public self-registration must be explicitly enabled
    if not settings.ALLOW_PUBLIC_REGISTRATION:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Public self-registration is disabled by enterprise security policy. User accounts must be provisioned by a Security Administrator.",
        )

    # 2. Rate limiting check per client IP to prevent abuse/enumeration
    client_ip = get_client_ip(request)
    rate_key = f"register_ip:{client_ip}"
    if auth_rate_limiter.is_locked(rate_key)[0]:
        _, remaining = auth_rate_limiter.is_locked(rate_key)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many registration requests. Please wait {remaining} seconds before attempting again.",
        )

    # 3. Check duplicate username or email
    if user_repo.get_by_username(payload.username.strip()):
        auth_rate_limiter.record_failure(rate_key)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Username '{payload.username}' is already in use.",
        )
    if user_repo.get_by_email(payload.email.strip().lower()):
        auth_rate_limiter.record_failure(rate_key)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Email '{payload.email}' is already registered.",
        )

    # 4. Hash password with Argon2id and create user with safe default role (viewer)
    pwd_hash = hash_password(payload.password)
    user_id = f"usr_viewer_{uuid.uuid4().hex[:12]}"
    created = user_repo.create_user(
        user_id=user_id,
        username=payload.username.strip(),
        email=payload.email.strip().lower(),
        password_hash=pwd_hash,
        role=UserRole.VIEWER.value,
        org_id=payload.org_id or "default",
    )

    auth_rate_limiter.record_success(rate_key)

    return UserResponse(
        id=created["id"],
        username=created["username"],
        email=created["email"],
        role=UserRole(created["role"]),
        org_id=created["org_id"],
        is_active=bool(created["is_active"]),
        created_at=created["created_at"],
        updated_at=created["updated_at"],
        last_login_at=created.get("last_login_at"),
    )



@router.get(
    "/csrf-token",
    summary="Retrieve CSRF Token",
    description="Returns a cryptographically random CSRF token and sets the csrf_token cookie for browser clients.",
)
async def get_csrf_token(response: Response) -> dict:
    token = generate_csrf_token()
    response.set_cookie(
        key="csrf_token",
        value=token,
        httponly=False,  # Accessible to client JS for custom header submission
        max_age=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite=settings.COOKIE_SAMESITE,
        secure=settings.is_cookie_secure,
    )
    return {"csrf_token": token}


@router.post(
    "/setup-admin",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Initial Administrator Setup",
    description="Creates the initial system administrator account. Only available when zero users exist in database.",
)
async def setup_initial_admin(
    payload: SetupAdminRequest,
    response: Response,
) -> TokenResponse:
    user_count = user_repo.count_users()
    if user_count > 0:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="System is already bootstrapped. Initial administrator setup is permanently disabled.",
        )

    # Hash administrator password with Argon2id
    pwd_hash = hash_password(payload.password)
    user_id = f"usr_admin_{uuid.uuid4().hex[:12]}"

    created = user_repo.create_user(
        user_id=user_id,
        username=payload.username.strip(),
        email=payload.email.strip().lower(),
        password_hash=pwd_hash,
        role=UserRole.ADMIN.value,
        org_id="default",
    )

    access_token = create_access_token(
        user_id=created["id"],
        username=created["username"],
        role=created["role"],
        org_id=created["org_id"],
    )

    # Generate and set CSRF cookie
    csrf_token = generate_csrf_token()
    response.set_cookie(
        key="csrf_token",
        value=csrf_token,
        httponly=False,
        max_age=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite=settings.COOKIE_SAMESITE,
        secure=settings.is_cookie_secure,
    )

    # Set secure HttpOnly session cookie
    response.set_cookie(
        key="session_token",
        value=access_token,
        httponly=True,
        max_age=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite=settings.COOKIE_SAMESITE,
        secure=settings.is_cookie_secure,
    )

    user_resp = UserResponse(
        id=created["id"],
        username=created["username"],
        email=created["email"],
        role=UserRole(created["role"]),
        org_id=created["org_id"],
        is_active=bool(created["is_active"]),
        created_at=created["created_at"],
        updated_at=created["updated_at"],
        last_login_at=created.get("last_login_at"),
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in_minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES,
        user=user_resp,
    )


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate User and Issue Token",
    description="Validates username and password with Argon2id, enforces rate limiting, and issues JWT access token.",
)
async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
) -> TokenResponse:
    # 1. Rate Limiting based on verified client IP and username (preventing header spoofing)
    client_ip = get_client_ip(request)
    rate_key = f"ip:{client_ip}_user:{payload.username.strip().lower()}"

    is_locked, remaining_secs = auth_rate_limiter.is_locked(rate_key)
    if is_locked:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed login attempts. Account temporarily locked. Please try again in {remaining_secs} seconds.",
        )

    # 2. Database Lookup (support login by either username or email)
    user_record = user_repo.get_by_username(payload.username.strip()) or user_repo.get_by_email(payload.username.strip())

    # 3. Timing-attack resistant verification
    if not user_record:
        # Run dummy Argon2 hash verification to match timing
        verify_dummy_password(payload.password)
        auth_rate_limiter.record_failure(rate_key)
        # Return generic error that does NOT reveal whether username exists
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user_record.get("is_active"):
        # Inactive user: timing-attack mitigation and identical error message
        verify_dummy_password(payload.password)
        auth_rate_limiter.record_failure(rate_key)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 4. Verify password against stored hash
    is_valid = verify_password(payload.password, user_record["password_hash"])
    if not is_valid:
        auth_rate_limiter.record_failure(rate_key)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 5. Success: Reset rate limiter and update last login
    auth_rate_limiter.record_success(rate_key)
    user_repo.update_last_login(user_record["id"])

    # 6. Issue JWT access token
    access_token = create_access_token(
        user_id=user_record["id"],
        username=user_record["username"],
        role=user_record["role"],
        org_id=user_record["org_id"],
    )

    # 7. Generate and set CSRF cookie
    csrf_token = generate_csrf_token()
    response.set_cookie(
        key="csrf_token",
        value=csrf_token,
        httponly=False,
        max_age=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite=settings.COOKIE_SAMESITE,
        secure=settings.is_cookie_secure,
    )

    # 8. Set secure HttpOnly session cookie
    response.set_cookie(
        key="session_token",
        value=access_token,
        httponly=True,
        max_age=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite=settings.COOKIE_SAMESITE,
        secure=settings.is_cookie_secure,
    )

    user_resp = UserResponse(
        id=user_record["id"],
        username=user_record["username"],
        email=user_record["email"],
        role=UserRole(user_record["role"]),
        org_id=user_record["org_id"],
        is_active=bool(user_record["is_active"]),
        created_at=user_record["created_at"],
        updated_at=user_record["updated_at"],
        last_login_at=user_record.get("last_login_at"),
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in_minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES,
        user=user_resp,
    )


@router.post(
    "/logout",
    summary="Logout User",
    description="Revokes the active JWT access token in the persistent store and clears session cookies.",
)
async def logout(
    request: Request,
    response: Response,
) -> dict:
    # Extract token to revoke its jti
    token: Optional[str] = None
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.lower().startswith("bearer "):
        token = auth_header[7:].strip()
    elif "session_token" in request.cookies:
        token = request.cookies.get("session_token")

    if token:
        try:
            payload = decode_access_token(token)
            jti = payload.get("jti")
            sub = payload.get("sub")
            exp = payload.get("exp")
            if jti and sub and exp:
                token_revocation_repo.revoke_token(
                    jti=jti,
                    user_id=sub,
                    expires_at=int(exp),
                    reason="user_logout",
                )
        except Exception:
            # Even if token is already expired or malformed, proceed to clear cookies
            pass

    response.delete_cookie(key="session_token")
    response.delete_cookie(key="csrf_token")
    return {"message": "Successfully logged out and session revoked"}


@router.post(
    "/revoke-all-sessions",
    summary="Revoke All Active Sessions",
    description="Invalidates all existing tokens for the authenticated user.",
)
async def revoke_all_sessions(
    response: Response,
    current_user: UserResponse = Depends(get_current_user),
) -> dict:
    user_repo.revoke_user_tokens(current_user.id)
    response.delete_cookie(key="session_token")
    response.delete_cookie(key="csrf_token")
    return {"message": "All active sessions have been revoked. Please log in again."}


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get Current User Profile",
    description="Returns authenticated user claims and profile details.",
)
async def get_current_user_profile(
    current_user: UserResponse = Depends(get_current_user),
) -> UserResponse:
    return current_user
