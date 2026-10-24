import os
from typing import List, Optional, Union
from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


class Settings(BaseSettings):
    """Application configuration loaded from environment or .env file."""

    PROJECT_NAME: str = "DataShield AI"
    VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    HOST: str = "127.0.0.1"
    PORT: int = 8001
    CORS_ORIGINS: Union[List[str], str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
    ]
    SQLITE_DB_PATH: str = "datashield.db"
    GEMINI_API_KEY: str | None = None
    GEMINI_MODEL: str = "gemini-3.1-flash-lite"
    GEMINI_TIMEOUT_SECONDS: float = 10.0
    GEMINI_MAX_RETRIES: int = 2
    MAX_UPLOAD_SIZE_BYTES: int = 5 * 1024 * 1024  # 5 MB
    MAX_EXTRACTED_CHARS: int = 500_000
    JWT_SECRET_KEY: str = "datashield-dev-jwt-secret-replace-in-production-2026-secure-key"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    AUTH_RATE_LIMIT_MAX_ATTEMPTS: int = 5
    AUTH_RATE_LIMIT_WINDOW_SECONDS: int = 60
    AUTH_RATE_LIMIT_LOCKOUT_SECONDS: int = 300
    RATE_LIMIT_STORAGE_BACKEND: str = "sqlite"  # "sqlite" for shared persistent storage, "memory" for local test
    SCAN_RATE_LIMIT_PER_MINUTE: int = 60
    # Daily AI Usage Budget Controls (Rolling 24-Hour Window)
    AI_BUDGET_ENABLED: bool = True
    AI_BUDGET_USER_DAILY_LIMIT: int = 200
    AI_BUDGET_TENANT_DAILY_LIMIT: int = 2500
    AI_BUDGET_WINDOW_SECONDS: int = 86400  # Rolling 24 hours
    COOKIE_SECURE: Optional[bool] = None  # None auto-enables in production, allows explicit False in dev
    COOKIE_SAMESITE: str = "lax"
    TRUST_FORWARDED_FOR: bool = False
    TRUSTED_PROXIES: List[str] = ["127.0.0.1", "::1"]
    ENABLE_PROD_DOCS: bool = False
    ALLOW_PUBLIC_REGISTRATION: bool = False  # Enterprise Zero-Trust default: admin-provisioned users only

    model_config = SettingsConfigDict(
        env_file=(".env", os.path.join(BACKEND_DIR, ".env")),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @field_validator(
        "AI_BUDGET_USER_DAILY_LIMIT",
        "AI_BUDGET_TENANT_DAILY_LIMIT",
        "AI_BUDGET_WINDOW_SECONDS",
        mode="after",
    )
    @classmethod
    def validate_budget_limits(cls, v: int) -> int:
        if v <= 0:
            raise ValueError(
                f"Daily AI budget configuration error: Value must be a positive integer (> 0), got {v}."
            )
        return v

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            if v.startswith("[") and v.endswith("]"):
                import json

                try:
                    return json.loads(v)
                except Exception:
                    pass
            return [i.strip() for i in v.split(",") if i.strip()]
        return v

    @model_validator(mode="after")
    def validate_production_security(self) -> "Settings":
        """Enforces critical production and staging security invariants."""
        is_strict = self.ENVIRONMENT.lower() in ("production", "staging")

        if is_strict:
            # 1. Require strong, non-default JWT secret in production/staging
            insecure_markers = ["replace", "dev", "change-me", "default", "example"]
            secret_lower = self.JWT_SECRET_KEY.lower()
            if len(self.JWT_SECRET_KEY) < 32 or any(m in secret_lower for m in insecure_markers):
                raise ValueError(
                    f"CRITICAL SECURITY CONFIGURATION ERROR: Insecure or default JWT_SECRET_KEY detected in {self.ENVIRONMENT}. "
                    "Production/staging requires a cryptographically secure random key of at least 32 characters."
                )

            # 2. DEBUG must be False in production/staging
            if self.DEBUG:
                raise ValueError(
                    f"CRITICAL SECURITY CONFIGURATION ERROR: DEBUG mode must be disabled (False) in {self.ENVIRONMENT}."
                )

            # 3. Reject wildcard CORS origin when credentials are enabled
            if isinstance(self.CORS_ORIGINS, list) and "*" in self.CORS_ORIGINS:
                raise ValueError(
                    f"CRITICAL SECURITY CONFIGURATION ERROR: Wildcard CORS origin ('*') is disallowed "
                    f"in {self.ENVIRONMENT} when credential support is enabled."
                )

        return self

    @property
    def is_cookie_secure(self) -> bool:
        """Determines whether HttpOnly cookies require the Secure flag."""
        if self.COOKIE_SECURE is not None:
            return self.COOKIE_SECURE
        return self.ENVIRONMENT.lower() == "production"

    @property
    def is_llm_configured(self) -> bool:
        """Determines if an LLM key is configured without exposing the secret."""
        key = self.GEMINI_API_KEY or os.environ.get("GEMINI_API_KEY")
        return bool(key and len(key.strip()) > 0)


settings = Settings()
