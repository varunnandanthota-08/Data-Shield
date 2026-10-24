import json
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from pydantic import BaseModel
from app.audit.service import audit_service
from app.auth.dependencies import require_analyst_or_admin, require_authenticated
from app.auth.models import UserResponse, UserRole
from app.auth.rate_limiter import scan_rate_limiter
from app.db.connection import get_db_cursor
from app.db.repository import scan_record_repo
from app.engine.file_extractor import (
    MAX_FILE_SIZE_BYTES,
    FileExtractionError,
    extract_file_content,
    sanitize_filename,
)
from app.engine.orchestrator import engine
from app.engine.schemas import ScanOptions, ScanRequest, ScanResponse, SeverityLevel
from app.policy.engine import policy_engine
from app.policy.risk_scorer import risk_scorer
from app.policy.schemas import (
    DataClassification,
    DestinationType,
    PolicyAction,
    RecipientType,
    SharingContext,
)

router = APIRouter(prefix="/v1/scan", tags=["Detection & Redaction"])


async def _execute_scan_pipeline(
    text: str,
    ctx: SharingContext,
    scan_options: ScanOptions,
    source_meta: Optional[Dict[str, Any]] = None,
    user_id: Optional[str] = None,
) -> ScanResponse:
    """Core deterministic scanning, policy evaluation, risk scoring, AI context analysis,
    and atomic SHA-256 chained audit persistence. Shared by both text and file endpoints.
    """
    source_meta = source_meta or {"source_type": "text"}
    source_type = source_meta.get("source_type", "text")
    filename = source_meta.get("filename")
    file_size_bytes = source_meta.get("file_size_bytes")
    extraction_note = source_meta.get("extraction_note")

    # Clean response for empty payload
    if not text or not text.strip():
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
        clean_res.source_type = source_type
        clean_res.filename = filename
        clean_res.file_size_bytes = file_size_bytes
        clean_res.extraction_note = extraction_note
        return clean_res

    # Enforce strict size check (max 500KB characters for text scanning)
    if len(text) > 500_000:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail="Payload exceeds maximum permitted size of 500,000 characters.",
        )

    # 1. Run detection and position-aware redaction with enforced baseline options
    safe_options = ScanOptions(
        enable_entropy=True,
        entropy_threshold=scan_options.entropy_threshold,
        min_entropy_len=scan_options.min_entropy_len,
        redaction_mode=scan_options.redaction_mode,
    )
    scan_res = engine.scan_and_redact(text, safe_options)

    # 2. Evaluate deterministic policies with organization scoping
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
        user_id=user_id,
        scan_id=scan_res.scan_id,
    )

    # 5. Prepare sanitized audit metadata (Zero raw secrets, unredacted documents, or prompts stored)
    categories_detected = list(set(f.category.value for f in scan_res.findings))
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
            "org_id": ctx.org_id,
        },
        "source": {
            "source_type": source_type,
            "filename": filename,
            "file_size_bytes": file_size_bytes,
        },
        "risk_score": risk_res.score,
        "risk_band": risk_res.band,
        "hard_block_override": risk_res.hard_block_override,
        "ai_analysis": {
            "attempted": True,
            "status": ai_result.ai_status,
            "model": ai_result.model_identifier,
            "operation": ai_result.usage.operation if ai_result.usage else "context_policy_remediation",
            "api_calls_count": ai_result.usage.api_calls_count if ai_result.usage else 0,
            "prompt_tokens": ai_result.usage.prompt_tokens if ai_result.usage else None,
            "candidates_tokens": ai_result.usage.candidates_tokens if ai_result.usage else None,
            "total_tokens": ai_result.usage.total_tokens if ai_result.usage else None,
            "cached_tokens": ai_result.usage.cached_tokens if ai_result.usage else None,
            "is_estimated": ai_result.usage.is_estimated if ai_result.usage else False,
            "latency_ms": ai_result.usage.latency_ms if ai_result.usage else None,
            "retries_attempted": ai_result.usage.retries_attempted if ai_result.usage else 0,
            "rate_limit_encountered": ai_result.usage.rate_limit_encountered if ai_result.usage else False,
            "timeout_encountered": ai_result.usage.timeout_encountered if ai_result.usage else False,
            "error_type": ai_result.usage.error_type if ai_result.usage else None,
            "fallback_reason": ai_result.usage.fallback_reason if ai_result.usage else None,
            "budget_exhausted": getattr(ai_result.usage, "budget_exhausted", False) if ai_result.usage else False,
            "budget_scope": getattr(ai_result.usage, "budget_scope", None) if ai_result.usage else None,
            "recommendation_count": len(ai_result.remediation_recommendations),
            "recommendation_ids": [r.id for r in ai_result.remediation_recommendations],
            "human_review_recommended": ai_result.human_review_recommended,
        },
    }

    scan_record_data = {
        "scan_id": scan_res.scan_id,
        "actor_id": ctx.actor_id,
        "org_id": ctx.org_id,
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

    # 6. Atomically persist tamper-evident SHA-256 chained audit event and scan record
    triggered_policy_ids = [p.id for p in policy_res.triggered_policies]
    audit_ev = audit_service.append_event(
        event_type="FILE_SCAN_EVALUATION" if source_type == "file" else "SCAN_EVALUATION",
        sanitized_metadata=sanitized_metadata,
        scan_id=scan_res.scan_id,
        actor_id=ctx.actor_id,
        policy_decision=risk_res.final_decision.value,
        policy_references=triggered_policy_ids,
        scan_record_data=scan_record_data,
        org_id=ctx.org_id,
    )

    # 7. Enrich response with telemetry and source attribution
    scan_res.context = ctx.model_dump()
    scan_res.risk_score = risk_res.score
    scan_res.risk_band = risk_res.band
    scan_res.policy_decision = risk_res.final_decision.value
    scan_res.triggered_policies = [p.model_dump() for p in policy_res.triggered_policies]
    scan_res.decision_reasons = risk_res.reasons
    scan_res.audit_event_id = audit_ev.event_id
    scan_res.audit_event_hash = audit_ev.event_hash
    scan_res.ai_analysis = ai_result.model_dump()
    scan_res.source_type = source_type
    scan_res.filename = filename
    scan_res.file_size_bytes = file_size_bytes
    scan_res.extraction_note = extraction_note

    return scan_res


@router.post(
    "/text",
    response_model=ScanResponse,
    summary="Scan and Redact Sensitive Content",
    description="Deterministic detection, position-aware redaction, policy evaluation, composite risk scoring, and tamper-evident audit logging. Accessible to Analysts and Admins.",
)
async def scan_text_payload(
    request: ScanRequest,
    current_user: UserResponse = Depends(require_analyst_or_admin),
) -> ScanResponse:
    """Scans raw input text, detects sensitive entities, evaluates policy rules,
    computes composite risk scores, and appends a SHA-256 hash-chained audit record.
    """
    # Enforce scan rate limiting per user / tenant to prevent compute exhaustion
    rate_key = f"scan_rate_user:{current_user.id}_org:{current_user.org_id}"
    is_limited, retry_after = scan_rate_limiter.check_rate_limit(rate_key)
    if is_limited:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Scan rate limit exceeded. Please wait {retry_after} seconds before submitting more scans.",
            headers={"Retry-After": str(retry_after)},
        )

    if request.context:
        if isinstance(request.context, dict):
            ctx = SharingContext(**request.context)
        elif isinstance(request.context, SharingContext):
            ctx = request.context
        else:
            ctx = SharingContext()
    else:
        ctx = SharingContext()

    if not ctx.actor_id or ctx.actor_id == "analyst_workbench":
        ctx.actor_id = current_user.username
    # Force verified server tenant identity for non-default tenants; default admin can specify target org
    if current_user.org_id != "default":
        ctx.org_id = current_user.org_id
    else:
        ctx.org_id = ctx.org_id or "default"

    scan_options = request.options or ScanOptions()
    return await _execute_scan_pipeline(
        text=request.text or "",
        ctx=ctx,
        scan_options=scan_options,
        source_meta={"source_type": "text"},
        user_id=current_user.id,
    )


@router.post(
    "/file",
    response_model=ScanResponse,
    summary="Scan and Redact Uploaded File",
    description="Safely extracts plain text from supported documents, configs, code, and logs, running full DLP inspection. Accessible to Analysts and Admins.",
)
async def scan_file_payload(
    file: UploadFile = File(...),
    destination: DestinationType = Form(default=DestinationType.UNSPECIFIED),
    recipient: RecipientType = Form(default=RecipientType.UNKNOWN),
    classification: DataClassification = Form(default=DataClassification.INTERNAL),
    actor_id: str = Form(default="analyst_workbench"),
    org_id: str = Form(default="default"),
    redaction_mode: str = Form(default="placeholder"),
    enable_entropy: bool = Form(default=True),
    context_json: Optional[str] = Form(default=None),
    options_json: Optional[str] = Form(default=None),
    current_user: UserResponse = Depends(require_analyst_or_admin),
) -> ScanResponse:
    """Safely reads uploaded file into bounded memory, validates extension allowlist,
    extracts text content, and executes the complete deterministic DLP scan pipeline.
    """
    # Enforce scan rate limiting per user / tenant
    rate_key = f"scan_rate_user:{current_user.id}_org:{current_user.org_id}"
    is_limited, retry_after = scan_rate_limiter.check_rate_limit(rate_key)
    if is_limited:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Scan rate limit exceeded. Please wait {retry_after} seconds before submitting more scans.",
            headers={"Retry-After": str(retry_after)},
        )

    safe_name = sanitize_filename(file.filename)

    # Read bounded content
    try:
        raw_bytes = await file.read(MAX_FILE_SIZE_BYTES + 1024)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read uploaded file: {str(e)}",
        )

    if len(raw_bytes) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"Uploaded file exceeds maximum permitted size of {MAX_FILE_SIZE_BYTES:,} bytes (5 MB).",
        )

    try:
        extracted = extract_file_content(safe_name, raw_bytes)
    except FileExtractionError as err:
        raise HTTPException(
            status_code=err.status_code,
            detail=err.message,
        )

    resolved_actor_id = actor_id if (actor_id and actor_id != "analyst_workbench") else current_user.username
    if current_user.org_id != "default":
        resolved_org_id = current_user.org_id
    else:
        resolved_org_id = org_id or "default"

    # Resolve sharing context (prioritizing context_json if provided)
    if context_json:
        try:
            parsed_ctx = json.loads(context_json)
            ctx = SharingContext(**parsed_ctx)
            if not ctx.actor_id or ctx.actor_id == "analyst_workbench":
                ctx.actor_id = resolved_actor_id
            if current_user.org_id != "default":
                ctx.org_id = current_user.org_id
            else:
                ctx.org_id = ctx.org_id or resolved_org_id
        except Exception:
            ctx = SharingContext(
                destination=destination,
                recipient=recipient,
                classification=classification,
                actor_id=resolved_actor_id,
                org_id=resolved_org_id,
            )
    else:
        ctx = SharingContext(
            destination=destination,
            recipient=recipient,
            classification=classification,
            actor_id=resolved_actor_id,
            org_id=resolved_org_id,
        )

    # Resolve scan options
    if options_json:
        try:
            parsed_opt = json.loads(options_json)
            scan_options = ScanOptions(**parsed_opt)
        except Exception:
            scan_options = ScanOptions(
                enable_entropy=enable_entropy,
                redaction_mode=redaction_mode,
            )
    else:
        scan_options = ScanOptions(
            enable_entropy=enable_entropy,
            redaction_mode=redaction_mode,
        )

    source_meta = {
        "source_type": "file",
        "filename": extracted.filename,
        "file_size_bytes": extracted.size_bytes,
        "extension": extracted.extension,
        "extraction_note": extracted.extraction_note,
    }

    return await _execute_scan_pipeline(
        text=extracted.text_content,
        ctx=ctx,
        scan_options=scan_options,
        source_meta=source_meta,
        user_id=current_user.id,
    )


@router.post(
    "/explain",
    response_model=dict,
    summary="Generate AI-Assisted Security Explanation & Remediation",
    description="Typed endpoint for standalone explainability and least-privilege remediation advice. Accessible to Analysts and Admins.",
)
async def explain_transfer_context(
    request: ScanRequest,
    current_user: UserResponse = Depends(require_analyst_or_admin),
) -> dict:
    """Provides plain-language explanation and actionable least-privilege recommendations."""
    scan_res = await scan_text_payload(request, current_user=current_user)
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
    description="Returns paginated historical scan evaluations with safe metadata, risk scores, and decisions. Accessible to all authenticated users.",
)
async def list_scan_records(
    limit: int = Query(default=50, ge=1, le=500, description="Page limit"),
    offset: int = Query(default=0, ge=0, description="Offset for pagination"),
    action: Optional[str] = Query(default=None, description="Filter by final policy action"),
    risk_band: Optional[str] = Query(default=None, description="Filter by risk band"),
    destination: Optional[str] = Query(default=None, description="Filter by destination"),
    current_user: UserResponse = Depends(require_authenticated),
) -> ScanRecordsPage:
    user_org = current_user.org_id if current_user.org_id != "default" else None
    items, total = scan_record_repo.list_scan_records(
        limit=limit, offset=offset, action=action, risk_band=risk_band, destination=destination, org_id=user_org
    )
    return ScanRecordsPage(items=items, total=total, limit=limit, offset=offset)


@router.get(
    "/records/{scan_id}",
    response_model=Dict[str, Any],
    summary="Get Scan Record Detail",
    description="Returns detailed persisted scan evaluation and associated safe audit metadata. Accessible to all authenticated users.",
)
async def get_scan_record_detail(
    scan_id: str,
    current_user: UserResponse = Depends(require_authenticated),
) -> Dict[str, Any]:
    user_org = current_user.org_id if current_user.org_id != "default" else None
    record = scan_record_repo.get_scan_record(scan_id, org_id=user_org)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record '{scan_id}' not found.",
        )
    with get_db_cursor(audit_service.db_path) as cursor:
        if user_org:
            cursor.execute("SELECT * FROM audit_events WHERE scan_id = ? AND org_id = ?", (scan_id, user_org))
        else:
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
    description="Returns real aggregate metrics calculated from persisted scan records. Accessible to all authenticated users.",
)
async def get_soc_metrics(
    current_user: UserResponse = Depends(require_authenticated),
) -> Dict[str, Any]:
    user_org = current_user.org_id if current_user.org_id != "default" else None
    return scan_record_repo.get_metrics(org_id=user_org)


@router.get(
    "/ai-budget",
    response_model=Dict[str, Any],
    summary="Get Daily AI Advisory Usage Budget Status",
    description="Returns authenticated rolling 24-hour Gemini advisory usage, remaining quota, and reset window. Accessible to authenticated users with strict tenant isolation.",
)
async def get_ai_budget_status(
    current_user: UserResponse = Depends(require_authenticated),
) -> Dict[str, Any]:
    from app.ai.budget import ai_budget_service
    target_org = current_user.org_id
    summary = ai_budget_service.get_usage_summary(
        user_id=current_user.id,
        org_id=target_org,
    )
    if current_user.role == UserRole.ADMIN:
        summary["user_breakdown"] = ai_budget_service.get_tenant_user_breakdown(org_id=target_org)
    return summary
