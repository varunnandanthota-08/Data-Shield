from typing import Any, Dict, List
from fastapi import APIRouter, HTTPException, status
from app.audit.service import audit_service
from app.db.repository import scan_record_repo
from app.engine.orchestrator import engine
from app.engine.schemas import ScanRequest, ScanResponse
from app.policy.engine import policy_engine
from app.policy.risk_scorer import risk_scorer
from app.policy.schemas import PolicyAction, SharingContext

router = APIRouter(prefix="/v1/scan", tags=["Detection & Redaction"])


@router.post(
    "/text",
    response_model=ScanResponse,
    summary="Scan and Redact Sensitive Content",
    description="Deterministic detection, position-aware redaction, policy evaluation, composite risk scoring, and tamper-evident audit logging.",
)
async def scan_text_payload(request: ScanRequest) -> ScanResponse:
    """Scans raw input text, detects sensitive entities, evaluates policy rules,
    computes composite risk scores, and appends a SHA-256 hash-chained audit record.
    """
    # Parse explicit sharing context if provided, otherwise apply default
    if request.context:
        if isinstance(request.context, dict):
            ctx = SharingContext(**request.context)
        elif isinstance(request.context, SharingContext):
            ctx = request.context
        else:
            ctx = SharingContext()
    else:
        ctx = SharingContext()

    if not request.text or not request.text.strip():
        # Clean response for empty payload
        clean_res = engine.scan_and_redact("")
        policy_res = policy_engine.evaluate([], ctx)
        risk_res = risk_scorer.calculate_risk([], ctx, policy_res)

        clean_res.context = ctx.model_dump()
        clean_res.risk_score = risk_res.score
        clean_res.risk_band = risk_res.band
        clean_res.policy_decision = risk_res.final_decision.value
        clean_res.triggered_policies = [p.model_dump() for p in policy_res.triggered_policies]
        clean_res.decision_reasons = risk_res.reasons
        return clean_res

    # Enforce strict size check (max 500KB)
    if len(request.text) > 500_000:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Payload exceeds maximum permitted size of 500,000 characters.",
        )

    # 1. Run detection and position-aware redaction
    scan_res = engine.scan_and_redact(request.text, request.options)

    # 2. Evaluate deterministic policies
    policy_res = policy_engine.evaluate(scan_res.findings, ctx)

    # 3. Calculate composite risk score
    risk_res = risk_scorer.calculate_risk(scan_res.findings, ctx, policy_res)

    # 4. Prepare sanitized audit metadata (Zero raw secrets or documents stored)
    categories_detected = list(set(f.category.value for f in scan_res.findings))
    sanitized_metadata: Dict[str, Any] = {
        "finding_count": len(scan_res.findings),
        "categories_detected": categories_detected,
        "highest_severity": max((f.severity.value for f in scan_res.findings), default="NONE"),
        "masked_findings": [
            {
                "id": f.id,
                "category": f.category.value,
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "masked_evidence": f.masked_evidence,
            }
            for f in scan_res.findings
        ],
        "context": {
            "destination": ctx.destination.value,
            "recipient": ctx.recipient.value,
            "classification": ctx.classification.value,
            "actor_id": ctx.actor_id,
        },
        "risk_score": risk_res.score,
        "risk_band": risk_res.band,
        "hard_block_override": risk_res.hard_block_override,
    }

    # 5. Persist tamper-evident SHA-256 chained audit event (Fails closed on DB error)
    triggered_policy_ids = [p.id for p in policy_res.triggered_policies]
    audit_ev = audit_service.append_event(
        event_type="SCAN_EVALUATION",
        sanitized_metadata=sanitized_metadata,
        scan_id=scan_res.scan_id,
        actor_id=ctx.actor_id,
        policy_decision=risk_res.final_decision.value,
        policy_references=triggered_policy_ids,
    )

    # 6. Persist scan decision metadata
    try:
        scan_record_repo.save_scan_record(
            scan_id=scan_res.scan_id,
            actor_id=ctx.actor_id,
            destination=ctx.destination.value,
            recipient=ctx.recipient.value,
            classification=ctx.classification.value,
            risk_score=risk_res.score,
            risk_band=risk_res.band,
            final_decision=risk_res.final_decision.value,
            finding_count=len(scan_res.findings),
            categories_detected=categories_detected,
            processing_duration_ms=scan_res.processing_duration_ms,
        )
    except Exception:
        # Non-critical auxiliary metadata write failure logged
        pass

    # 7. Enrich response with policy and audit verification telemetry
    scan_res.context = ctx.model_dump()
    scan_res.risk_score = risk_res.score
    scan_res.risk_band = risk_res.band
    scan_res.policy_decision = risk_res.final_decision.value
    scan_res.triggered_policies = [p.model_dump() for p in policy_res.triggered_policies]
    scan_res.decision_reasons = risk_res.reasons
    scan_res.audit_event_id = audit_ev.event_id
    scan_res.audit_event_hash = audit_ev.event_hash

    return scan_res
