from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, EmailStr, Field


class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50, description="Username for authentication")
    password: str = Field(min_length=8, max_length=128, description="Password")


class SetupAdminRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50, description="Administrator username")
    email: EmailStr = Field(description="Administrator email address")
    password: str = Field(min_length=10, max_length=128, description="Strong administrative password")


class UserCreateRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50, description="Username")
    email: EmailStr = Field(description="User email address")
    password: str = Field(min_length=8, max_length=128, description="Password")
    role: UserRole = Field(default=UserRole.ANALYST, description="Assigned role")
    org_id: str = Field(default="default", max_length=64, description="Tenant organization ID")


class UserUpdateRequest(BaseModel):
    email: Optional[EmailStr] = None
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None
    password: Optional[str] = Field(default=None, min_length=8, max_length=128)
    org_id: Optional[str] = Field(default=None, max_length=64)


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    role: UserRole
    org_id: str = "default"
    is_active: bool = True
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_login_at: Optional[str] = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in_minutes: int
    user: UserResponse


class BootstrapStatusResponse(BaseModel):
    requires_bootstrap: bool
    user_count: int


class RegistrationStatusResponse(BaseModel):
    allow_public_registration: bool
    requires_bootstrap: bool
    user_creation_model: str = "administrator_managed"
    registration_mode: str = "admin_provisioned"


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50, description="Desired username")
    email: EmailStr = Field(description="User email address")
    password: str = Field(min_length=8, max_length=128, description="Password (min 8 characters)")
    org_id: str = Field(default="default", max_length=64, description="Tenant organization ID")

