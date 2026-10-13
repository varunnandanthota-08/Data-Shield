from typing import List
from fastapi import APIRouter, Query
from pydantic import BaseModel
from app.audit.service import audit_service
from app.policy.schemas import AuditEvent, AuditVerificationResult

router = APIRouter(prefix="/v1/audit", tags=["Tamper-Evident Audit Trails"])


class AuditEventsPage(BaseModel):
    items: List[AuditEvent]
    total: int
    limit: int
    offset: int


@router.get(
    "/events",
    response_model=AuditEventsPage,
    summary="List Audit Log Events",
    description="Returns paginated, append-only SHA-256 hash-chained audit events. Contains sanitized metadata only; zero raw secrets.",
)
async def list_audit_events(
    limit: int = Query(default=50, ge=1, le=500, description="Number of events to retrieve"),
    offset: int = Query(default=0, ge=0, description="Offset for pagination"),
) -> AuditEventsPage:
    items, total = audit_service.list_events(limit=limit, offset=offset)
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
    description="Cryptographically verifies sequence numbers, hash links, and recomputes SHA-256 digests across all events to detect tampering.",
)
async def verify_audit_chain() -> AuditVerificationResult:
    return audit_service.verify_chain()
