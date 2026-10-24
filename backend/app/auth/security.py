import hmac
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from app.core.config import settings

# Configure Argon2id hasher with recommended security profile
password_hasher = PasswordHasher(
    time_cost=2,          # 2 iterations
    memory_cost=19456,    # 19 MiB memory
    parallelism=1,        # 1 thread
    hash_len=32,          # 32 byte hash
)

# Pre-computed dummy hash to run constant-time check if user does not exist
# Prevents timing attack username enumeration
DUMMY_ARGON2_HASH = password_hasher.hash("dummy_constant_time_string_for_timing_mitigation_2026")


def hash_password(password: str) -> str:
    """Hashes password using Argon2id. Never stores plaintext."""
    return password_hasher.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies plain password against stored Argon2id hash."""
    try:
        return password_hasher.verify(hashed_password, plain_password)
    except (VerifyMismatchError, InvalidHashError, Exception):
        return False


def verify_dummy_password(plain_password: str) -> bool:
    """Executes a constant-time verification when a user is not found,
    preventing side-channel timing enumeration.
    """
    try:
        password_hasher.verify(DUMMY_ARGON2_HASH, plain_password)
    except Exception:
        pass
    return False


def generate_csrf_token() -> str:
    """Generates a cryptographically strong, URL-safe CSRF token."""
    return secrets.token_urlsafe(32)


def verify_csrf_token(header_token: Optional[str], cookie_token: Optional[str]) -> bool:
    """Validates that header-submitted CSRF token matches cookie using constant-time comparison."""
    if not header_token or not cookie_token:
        return False
    return hmac.compare_digest(header_token.strip(), cookie_token.strip())


def create_access_token(
    user_id: str,
    username: str,
    role: str,
    org_id: str,
    expires_delta: Optional[timedelta] = None,
    jti: Optional[str] = None,
) -> str:
    """Generates signed JWT access token with unique jti, user claims, and expiration."""
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)

    token_jti = jti or str(uuid.uuid4())

    payload: Dict[str, Any] = {
        "jti": token_jti,
        "sub": user_id,
        "username": username,
        "role": role,
        "org_id": org_id,
        "token_type": "access",
        "iat": now.timestamp(),
        "exp": expire.timestamp(),
        "iss": "datashield-ai",
    }

    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decodes and cryptographically verifies JWT access token signature, issuer, algorithm, and required claims."""
    return jwt.decode(
        token,
        settings.JWT_SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
        issuer="datashield-ai",
        options={
            "verify_signature": True,
            "verify_exp": True,
            "verify_iat": True,
            "verify_iss": True,
            "require": ["sub", "username", "role", "org_id", "iat", "exp", "iss"],
        },
    )

