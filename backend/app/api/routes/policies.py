import re
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field
from app.audit.service import audit_service
from app.db.repository import policy_repo
from app.engine.orchestrator import engine
from app.engine.schemas import Finding, ScanOptions
from app.policy.engine import policy_engine
from app.policy.risk_scorer import risk_scorer
from app.policy.schemas import (
    PolicyEvaluationResult,
    PolicyRule,
    RiskScoreResult,
    SharingContext,
)

router = APIRouter(
    prefix="/v1/policies",
    tags=["Policy Engine & Rules [Development-Only]"],
    responses={
        200: {"description": "Successful operation"},
    },
)

# Built-in baseline rule IDs that cannot be deleted
PROTECTED_BASELINE_POLICY_IDS = {"POL-001", "POL-002", "POL-003", "POL-004", "POL-005"}


class PolicyEvaluateRequest(BaseModel):
    text: Optional[str] = Field(default=None, description="Optional raw text to scan and evaluate")
    findings: Optional[List[Finding]] = Field(default=None, description="Optional pre-extracted findings")
    context: Optional[SharingContext] = Field(default=None, description="Explicit transfer context")
    options: Optional[ScanOptions] = Field(default=None, description="Optional scan options")


class PolicyEvaluateResponse(BaseModel):
    policy_evaluation: PolicyEvaluationResult
    risk_scoring: RiskScoreResult
    findings_evaluated: int


class TogglePolicyRequest(BaseModel):
    enabled: bool = Field(description="New enabled status for the policy")


@router.get(
    "",
    response_model=List[PolicyRule],
    summary="List Security & Privacy Policies [Development-Only]",
    description="Returns active or configured deterministic policy rules scoped by organization. Development-only capability.",
)
async def list_policies(
    org_id: Optional[str] = Query(default=None, description="Filter policies by organization ID (returns org + default rules)"),
    enabled_only: bool = Query(default=False, description="Filter for only enabled rules"),
) -> List[PolicyRule]:
    return policy_repo.list_policies(org_id=org_id, enabled_only=enabled_only)


@router.get(
    "/{policy_id}",
    response_model=PolicyRule,
    summary="Get Specific Policy Rule [Development-Only]",
    description="Development-only capability: retrieves a specific policy rule by ID.",
)
async def get_policy(policy_id: str) -> PolicyRule:
    policy = policy_repo.get_policy(policy_id)
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy rule '{policy_id}' not found.",
        )
    return policy


@router.post(
    "",
    response_model=PolicyRule,
    status_code=status.HTTP_201_CREATED,
    summary="Create or Update Policy Rule [Development-Only]",
    description="Creates or updates a policy rule scoped to an organization. Validates constraints and records a tamper-evident audit event.",
)
async def save_policy(rule: PolicyRule, check_duplicate: bool = Query(default=False)) -> PolicyRule:
    # 1. Validate policy ID format
    if not re.match(r"^[A-Za-z0-9_\-\.]{3,64}$", rule.id.strip()):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Policy ID must be 3-64 characters consisting of letters, digits, underscores, dashes, or dots.",
        )

    # 2. Validate required string fields
    if not rule.name or not rule.name.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Policy name is required and cannot be empty.",
        )

    if not rule.description or not rule.description.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Policy description is required.",
        )

    if not rule.intent_explanation or not rule.intent_explanation.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Policy intent justification is required for audit defensibility.",
        )

    # 3. Priority range validation
    if rule.priority < 1 or rule.priority > 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Rule priority must be an integer between 1 and 100.",
        )

    existing = policy_repo.get_policy(rule.id)
    is_new = existing is None

    if check_duplicate and not is_new:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Policy rule with ID '{rule.id}' already exists.",
        )

    # 4. Save to persistent SQLite storage
    saved = policy_repo.save_policy(rule)

    # 5. Synchronize in-memory engine
    policy_engine.add_or_update_rule(saved)

    # 6. Record tamper-evident audit event for policy management
    event_type = "POLICY_CREATED" if is_new else "POLICY_UPDATED"
    audit_service.append_event(
        event_type=event_type,
        sanitized_metadata={
            "policy_id": saved.id,
            "org_id": saved.org_id,
            "action": saved.action.value,
            "name": saved.name,
            "priority": saved.priority,
            "enabled": saved.enabled,
        },
        actor_id="admin_policy_builder",
        policy_decision=saved.action.value,
        policy_references=[saved.id],
    )

    return saved


@router.patch(
    "/{policy_id}/toggle",
    response_model=PolicyRule,
    summary="Enable or Disable a Policy Rule",
    description="Updates the enabled state of a policy rule and records an audit event.",
)
async def toggle_policy(
    policy_id: str,
    request: Optional[TogglePolicyRequest] = None,
    enabled: Optional[bool] = Query(default=None),
) -> PolicyRule:
    existing = policy_repo.get_policy(policy_id)
    if not existing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy rule '{policy_id}' not found.",
        )

    if enabled is not None:
        target_enabled = enabled
    elif request is not None and request.enabled is not None:
        target_enabled = request.enabled
    else:
        target_enabled = not existing.enabled

    updated = policy_repo.toggle_policy(policy_id, target_enabled)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update policy status.",
        )

    # Sync engine
    policy_engine.add_or_update_rule(updated)

    audit_service.append_event(
        event_type="POLICY_TOGGLED",
        sanitized_metadata={
            "policy_id": policy_id,
            "org_id": updated.org_id,
            "enabled": updated.enabled,
        },
        actor_id="admin_policy_builder",
        policy_decision=updated.action.value,
        policy_references=[policy_id],
    )

    return updated


@router.delete(
    "/{policy_id}",
    status_code=status.HTTP_200_OK,
    summary="Delete a Custom Policy Rule",
    description="Removes a custom organization policy. Baseline system rules (POL-001 through POL-005) are protected and cannot be deleted.",
)
async def delete_policy(policy_id: str) -> dict:
    if policy_id in PROTECTED_BASELINE_POLICY_IDS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Rule '{policy_id}' is a protected baseline policy invariant and cannot be deleted.",
        )

    existing = policy_repo.get_policy(policy_id)
    if not existing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy rule '{policy_id}' not found.",
        )

    deleted = policy_repo.delete_policy(policy_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete policy '{policy_id}'.",
        )

    # Sync in-memory engine
    policy_engine.remove_rule(policy_id)

    audit_service.append_event(
        event_type="POLICY_DELETED",
        sanitized_metadata={
            "policy_id": policy_id,
            "org_id": existing.org_id,
            "name": existing.name,
        },
        actor_id="admin_policy_builder",
        policy_decision=existing.action.value,
        policy_references=[policy_id],
    )

    return {"deleted": True, "policy_id": policy_id}


@router.post(
    "/evaluate",
    response_model=PolicyEvaluateResponse,
    summary="Evaluate Policies & Risk on Context",
    description="Evaluates policy rules and computes composite risk scoring against either raw text or pre-extracted findings.",
)
async def evaluate_policies(request: PolicyEvaluateRequest) -> PolicyEvaluateResponse:
    ctx = request.context or SharingContext()

    findings: List[Finding] = []
    if request.text:
        scan_res = engine.scan_and_redact(request.text, request.options)
        findings = scan_res.findings
        if request.findings:
            from app.policy.risk_scorer import deduplicate_overlapping_findings
            findings = deduplicate_overlapping_findings(findings + request.findings)
    elif request.findings is not None:
        findings = request.findings

    policy_res = policy_engine.evaluate(findings, ctx)
    risk_res = risk_scorer.calculate_risk(findings, ctx, policy_res)

    return PolicyEvaluateResponse(
        policy_evaluation=policy_res,
        risk_scoring=risk_res,
        findings_evaluated=len(findings),
    )
