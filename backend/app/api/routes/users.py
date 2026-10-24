import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from app.auth.models import (
    UserCreateRequest,
    UserResponse,
    UserRole,
    UserUpdateRequest,
)
from app.auth.dependencies import require_admin
from app.auth.repository import user_repo
from app.auth.security import hash_password

router = APIRouter(prefix="/v1/users", tags=["User & Identity Governance [Admin-Only]"])


@router.get(
    "",
    response_model=List[UserResponse],
    summary="List Organization Users",
    description="Returns all users in the system or scoped tenant organization. Restricted to Admin.",
)
async def list_users(
    org_id: Optional[str] = Query(default=None, description="Optional organization filter"),
    current_admin: UserResponse = Depends(require_admin),
) -> List[UserResponse]:
    effective_org = current_admin.org_id if current_admin.org_id != "default" else org_id
    users_data = user_repo.list_users(org_id=effective_org)
    return [
        UserResponse(
            id=u["id"],
            username=u["username"],
            email=u["email"],
            role=UserRole(u["role"]),
            org_id=u["org_id"],
            is_active=bool(u["is_active"]),
            created_at=u["created_at"],
            updated_at=u["updated_at"],
            last_login_at=u.get("last_login_at"),
        )
        for u in users_data
    ]


@router.post(
    "",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create New User",
    description="Provisions a new user with an assigned role. Restricted to Admin.",
)
async def create_user(
    payload: UserCreateRequest,
    current_admin: UserResponse = Depends(require_admin),
) -> UserResponse:
    # Check if username or email already exists
    if user_repo.get_by_username(payload.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Username '{payload.username}' is already in use.",
        )
    if user_repo.get_by_email(payload.email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Email '{payload.email}' is already registered.",
        )

    pwd_hash = hash_password(payload.password)
    user_id = f"usr_{payload.role.value}_{uuid.uuid4().hex[:12]}"
    target_org = current_admin.org_id if current_admin.org_id != "default" else (payload.org_id or current_admin.org_id)

    created = user_repo.create_user(
        user_id=user_id,
        username=payload.username.strip(),
        email=payload.email.strip().lower(),
        password_hash=pwd_hash,
        role=payload.role.value,
        org_id=target_org,
    )

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
    "/{user_id}",
    response_model=UserResponse,
    summary="Get User Detail",
    description="Returns detailed user record. Restricted to Admin.",
)
async def get_user_detail(
    user_id: str,
    current_admin: UserResponse = Depends(require_admin),
) -> UserResponse:
    u = user_repo.get_by_id(user_id)
    if not u or (current_admin.org_id != "default" and u["org_id"] != current_admin.org_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID '{user_id}' not found.",
        )
    return UserResponse(
        id=u["id"],
        username=u["username"],
        email=u["email"],
        role=UserRole(u["role"]),
        org_id=u["org_id"],
        is_active=bool(u["is_active"]),
        created_at=u["created_at"],
        updated_at=u["updated_at"],
        last_login_at=u.get("last_login_at"),
    )


@router.put(
    "/{user_id}",
    response_model=UserResponse,
    summary="Update User Attributes",
    description="Updates role, active status, email, or password for a user. Restricted to Admin.",
)
async def update_user(
    user_id: str,
    payload: UserUpdateRequest,
    current_admin: UserResponse = Depends(require_admin),
) -> UserResponse:
    target = user_repo.get_by_id(user_id)
    if not target or (current_admin.org_id != "default" and target["org_id"] != current_admin.org_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID '{user_id}' not found.",
        )

    # Prevent admin from demoting or deactivating their own account
    if target["id"] == current_admin.id:
        if payload.role and payload.role != UserRole.ADMIN:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Administrators cannot demote their own account role.",
            )
        if payload.is_active is False:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Administrators cannot deactivate their own account.",
            )

    pwd_hash = hash_password(payload.password) if payload.password else None
    target_org = current_admin.org_id if current_admin.org_id != "default" else payload.org_id

    updated = user_repo.update_user(
        user_id=user_id,
        email=str(payload.email) if payload.email else None,
        role=payload.role.value if payload.role else None,
        is_active=payload.is_active,
        password_hash=pwd_hash,
        org_id=target_org,
    )

    if not updated:
        raise HTTPException(status_code=500, detail="Failed to update user record")

    return UserResponse(
        id=updated["id"],
        username=updated["username"],
        email=updated["email"],
        role=UserRole(updated["role"]),
        org_id=updated["org_id"],
        is_active=bool(updated["is_active"]),
        created_at=updated["created_at"],
        updated_at=updated["updated_at"],
        last_login_at=updated.get("last_login_at"),
    )


@router.delete(
    "/{user_id}",
    summary="Delete User",
    description="Permanently deletes user account. Restricted to Admin.",
)
async def delete_user(
    user_id: str,
    current_admin: UserResponse = Depends(require_admin),
) -> dict:
    if user_id == current_admin.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Administrators cannot delete their own account.",
        )

    target = user_repo.get_by_id(user_id)
    if not target or (current_admin.org_id != "default" and target["org_id"] != current_admin.org_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID '{user_id}' not found.",
        )

    deleted = user_repo.delete_user(user_id, org_id=current_admin.org_id if current_admin.org_id != "default" else None)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID '{user_id}' not found.",
        )
    return {"message": f"User '{user_id}' successfully deleted."}
