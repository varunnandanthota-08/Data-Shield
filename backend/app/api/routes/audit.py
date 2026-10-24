from typing import List
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from app.audit.service import audit_service
from app.policy.schemas import AuditEvent, AuditVerificationResult
from app.auth.dependencies import require_analyst_or_admin
from app.auth.models import UserResponse

router = APIRouter(
    prefix="/v1/audit",
    tags=["Tamper-Evident Audit Trails"],
    responses={
        200: {"description": "Successful operation"},
    },
)


class AuditEventsPage(BaseModel):
    items: List[AuditEvent]
    total: int
    limit: int
    offset: int


@router.get(
    "/events",
    response_model=AuditEventsPage,
    summary="List Audit Log Events",
    description="Returns paginated, append-only SHA-256 hash-chained audit events. Accessible to Analysts and Admins only.",
)
async def list_audit_events(
    limit: int = Query(default=50, ge=1, le=500, description="Number of events to retrieve"),
    offset: int = Query(default=0, ge=0, description="Offset for pagination"),
    current_user: UserResponse = Depends(require_analyst_or_admin),
) -> AuditEventsPage:
    user_org = current_user.org_id if current_user.org_id != "default" else None
    items, total = audit_service.list_events(limit=limit, offset=offset, org_id=user_org)
    return AuditEventsPage(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/verify",
    response_model=AuditVerificationResult,
    summary="Verify Audit Chain Integrity",
    description="Cryptographically verifies sequence numbers, hash links, and recomputes SHA-256 digests across all events to detect tampering. Accessible to Analysts and Admins only.",
)
async def verify_audit_chain(
    current_user: UserResponse = Depends(require_analyst_or_admin),
) -> AuditVerificationResult:
    user_org = current_user.org_id if current_user.org_id != "default" else None
    return audit_service.verify_chain(org_id=user_org)
