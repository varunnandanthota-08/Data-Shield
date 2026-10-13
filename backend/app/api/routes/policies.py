from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field
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


class PolicyEvaluateRequest(BaseModel):
    text: Optional[str] = Field(default=None, description="Optional raw text to scan and evaluate")
    findings: Optional[List[Finding]] = Field(default=None, description="Optional pre-extracted findings")
    context: Optional[SharingContext] = Field(default=None, description="Explicit transfer context")
    options: Optional[ScanOptions] = Field(default=None, description="Optional scan options")


class PolicyEvaluateResponse(BaseModel):
    policy_evaluation: PolicyEvaluationResult
    risk_scoring: RiskScoreResult
    findings_evaluated: int


@router.get(
    "",
    response_model=List[PolicyRule],
    summary="List Security & Privacy Policies [Development-Only]",
    description="Returns all active or configured deterministic policy rules. Development-only capability: access control required before production use.",
)
async def list_policies(
    enabled_only: bool = Query(default=False, description="Filter for only enabled rules")
) -> List[PolicyRule]:
    # Query database repository
    return policy_repo.list_policies(enabled_only=enabled_only)


@router.get(
    "/{policy_id}",
    response_model=PolicyRule,
    summary="Get Specific Policy Rule [Development-Only]",
    description="Development-only capability: requires authentication/authorization before exposure to production networks.",
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
    description="Creates or updates a policy rule. Development-only capability: access control required before production use. Do not expose to untrusted networks.",
)
async def save_policy(rule: PolicyRule) -> PolicyRule:
    saved = policy_repo.save_policy(rule)
    # Synchronize in-memory engine
    policy_engine.add_or_update_rule(saved)
    return saved


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
