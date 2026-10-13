import json
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel
from app.audit.service import audit_service
from app.db.connection import get_db_cursor
from app.db.repository import scan_record_repo
from app.engine.orchestrator import engine
from app.engine.schemas import ScanOptions, ScanRequest, ScanResponse
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
        from app.ai.service import ai_analysis_service
        ai_res = ai_analysis_service.analyze_context("", [], ctx, policy_res, risk_res)

        clean_res.context = ctx.model_dump()
        clean_res.risk_score = risk_res.score
        clean_res.risk_band = risk_res.band
        clean_res.policy_decision = risk_res.final_decision.value
        clean_res.triggered_policies = [p.model_dump() for p in policy_res.triggered_policies]
        clean_res.decision_reasons = risk_res.reasons
        clean_res.ai_analysis = ai_res.model_dump()
        return clean_res

    # Enforce strict size check (max 500KB)
    if len(request.text) > 500_000:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Payload exceeds maximum permitted size of 500,000 characters.",
        )

    # 1. Run detection and position-aware redaction with enforced security baseline options
    scan_options = request.options or ScanOptions()
    safe_options = ScanOptions(
        enable_entropy=True,
        entropy_threshold=scan_options.entropy_threshold,
        min_entropy_len=scan_options.min_entropy_len,
        redaction_mode=scan_options.redaction_mode,
    )
    scan_res = engine.scan_and_redact(request.text, safe_options)

    # 2. Evaluate deterministic policies
    policy_res = policy_engine.evaluate(scan_res.findings, ctx)

    # 3. Calculate composite risk score
    risk_res = risk_scorer.calculate_risk(scan_res.findings, ctx, policy_res)

    # 4. Run AI context analysis & least-privilege remediation (Advisory explanation layer)
    from app.ai.service import ai_analysis_service
    ai_result = ai_analysis_service.analyze_context(
        sanitized_text=scan_res.redacted_text,
        findings=scan_res.findings,
        context=ctx,
        policy_result=policy_res,
        risk_result=risk_res,
    )

    # 5. Prepare sanitized audit metadata (Zero raw secrets, unredacted documents, or prompts stored)
    categories_detected = list(set(f.category.value for f in scan_res.findings))
    from app.engine.schemas import SeverityLevel
    severity_order = {
        SeverityLevel.CRITICAL: 5,
        SeverityLevel.HIGH: 4,
        SeverityLevel.MEDIUM: 3,
        SeverityLevel.LOW: 2,
        SeverityLevel.INFORMATIONAL: 1,
    }
    highest_sev = max((f.severity for f in scan_res.findings), key=lambda s: severity_order.get(s, 0), default=None)
    highest_severity_str = highest_sev.value if highest_sev else "NONE"

    sanitized_metadata: Dict[str, Any] = {
        "finding_count": len(scan_res.findings),
        "categories_detected": categories_detected,
        "highest_severity": highest_severity_str,
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
        "ai_analysis": {
            "attempted": True,
            "status": ai_result.ai_status,
            "model": ai_result.model_identifier,
            "recommendation_count": len(ai_result.remediation_recommendations),
            "recommendation_ids": [r.id for r in ai_result.remediation_recommendations],
            "human_review_recommended": ai_result.human_review_recommended,
        },
    }

    scan_record_data = {
        "scan_id": scan_res.scan_id,
        "actor_id": ctx.actor_id,
        "destination": ctx.destination.value,
        "recipient": ctx.recipient.value,
        "classification": ctx.classification.value,
        "risk_score": risk_res.score,
        "risk_band": risk_res.band,
        "final_decision": risk_res.final_decision.value,
        "finding_count": len(scan_res.findings),
        "categories_detected": categories_detected,
        "processing_duration_ms": scan_res.processing_duration_ms,
    }

    # 6. Atomically persist tamper-evident SHA-256 chained audit event and scan record (Fails closed on DB error)
    triggered_policy_ids = [p.id for p in policy_res.triggered_policies]
    audit_ev = audit_service.append_event(
        event_type="SCAN_EVALUATION",
        sanitized_metadata=sanitized_metadata,
        scan_id=scan_res.scan_id,
        actor_id=ctx.actor_id,
        policy_decision=risk_res.final_decision.value,
        policy_references=triggered_policy_ids,
        scan_record_data=scan_record_data,
    )

    # 7. Enrich response with policy, risk, AI analysis, and audit verification telemetry
    scan_res.context = ctx.model_dump()
    scan_res.risk_score = risk_res.score
    scan_res.risk_band = risk_res.band
    scan_res.policy_decision = risk_res.final_decision.value
    scan_res.triggered_policies = [p.model_dump() for p in policy_res.triggered_policies]
    scan_res.decision_reasons = risk_res.reasons
    scan_res.audit_event_id = audit_ev.event_id
    scan_res.audit_event_hash = audit_ev.event_hash
    scan_res.ai_analysis = ai_result.model_dump()

    return scan_res


@router.post(
    "/explain",
    response_model=dict,
    summary="Generate AI-Assisted Security Explanation & Remediation",
    description="Typed endpoint for standalone explainability and least-privilege remediation advice.",
)
async def explain_transfer_context(request: ScanRequest) -> dict:
    """Provides plain-language explanation and actionable least-privilege recommendations."""
    scan_res = await scan_text_payload(request)
    return scan_res.ai_analysis or {}


class ScanRecordsPage(BaseModel):
    items: List[Dict[str, Any]]
    total: int
    limit: int
    offset: int


@router.get(
    "/records",
    response_model=ScanRecordsPage,
    summary="List Persisted Scan Records",
    description="Returns paginated historical scan evaluations with safe metadata, risk scores, and decisions.",
)
async def list_scan_records(
    limit: int = Query(default=50, ge=1, le=500, description="Page limit"),
    offset: int = Query(default=0, ge=0, description="Offset for pagination"),
    action: Optional[str] = Query(default=None, description="Filter by final policy action"),
    risk_band: Optional[str] = Query(default=None, description="Filter by risk band"),
    destination: Optional[str] = Query(default=None, description="Filter by destination"),
) -> ScanRecordsPage:
    items, total = scan_record_repo.list_scan_records(
        limit=limit, offset=offset, action=action, risk_band=risk_band, destination=destination
    )
    return ScanRecordsPage(items=items, total=total, limit=limit, offset=offset)


@router.get(
    "/records/{scan_id}",
    response_model=Dict[str, Any],
    summary="Get Scan Record Detail",
    description="Returns detailed persisted scan evaluation and associated safe audit metadata.",
)
async def get_scan_record_detail(scan_id: str) -> Dict[str, Any]:
    record = scan_record_repo.get_scan_record(scan_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record '{scan_id}' not found.",
        )
    with get_db_cursor(audit_service.db_path) as cursor:
        cursor.execute("SELECT * FROM audit_events WHERE scan_id = ?", (scan_id,))
        audit_row = cursor.fetchone()
        if audit_row:
            record["audit_event_id"] = audit_row["event_id"]
            record["audit_event_hash"] = audit_row["event_hash"]
            try:
                record["audit_metadata"] = json.loads(audit_row["sanitized_metadata"])
            except Exception:
                record["audit_metadata"] = {}
    return record


@router.get(
    "/metrics",
    response_model=Dict[str, Any],
    summary="Get SOC Console Overview Metrics",
    description="Returns real aggregate metrics calculated from persisted scan records.",
)
async def get_soc_metrics() -> Dict[str, Any]:
    return scan_record_repo.get_metrics()
