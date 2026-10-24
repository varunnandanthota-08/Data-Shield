from typing import Dict, List, Optional
from app.ai.schemas import (
    AIContextAnalysisResult,
    AIUsageTelemetry,
    RemediationActionType,
    RemediationRecommendation,
)
from app.engine.schemas import Finding, FindingCategory
from app.policy.schemas import (
    DataClassification,
    DestinationType,
    PolicyAction,
    PolicyEvaluationResult,
    RecipientType,
    RiskScoreResult,
    SharingContext,
)


def generate_deterministic_explanation(
    findings: List[Finding],
    context: SharingContext,
    policy_result: PolicyEvaluationResult,
    risk_result: RiskScoreResult,
    failure_reason: str = "AI service unavailable",
    latency_ms: Optional[float] = None,
    retries_attempted: int = 0,
    api_calls_count: int = 0,
) -> AIContextAnalysisResult:
    """Generates an explainable security summary and actionable least-privilege remediation
    derived purely from deterministic policy metadata, detector findings, and transfer context.
    Never invents facts or alters deterministic decisions.
    """
    categories = sorted(list(set(f.category.value for f in findings)))
    rec_list: List[RemediationRecommendation] = []
    rec_counter = 1

    # 1. Incident Summary
    if not findings:
        summary = (
            f"Transfer of {context.classification.value} content to destination "
            f"'{context.destination.value}' with recipient trust level '{context.recipient.value}'. "
            f"Deterministic evaluation resulted in {policy_result.final_decision.value} "
            f"with a heuristic risk score of {risk_result.score}/100 ({risk_result.band})."
        )
    else:
        summary = (
            f"Transfer contains {len(findings)} sensitive entity/entities ({', '.join(categories)}) "
            f"destined for '{context.destination.value}' (recipient: '{context.recipient.value}'). "
            f"Enforced decision: {policy_result.final_decision.value} with heuristic risk score "
            f"{risk_result.score}/100 ({risk_result.band})."
        )

    # 2. Risk factors from actual context & findings
    risk_factors: List[str] = []
    for f in findings:
        risk_factors.append(f"{f.severity.value} severity {f.category.value} ({f.rule_id}) detected.")
    if context.destination in (DestinationType.PUBLIC_LLM, DestinationType.EXTERNAL_SAAS):
        risk_factors.append(f"Destination '{context.destination.value}' is outside the internal security perimeter.")
    if context.recipient in (RecipientType.PUBLIC, RecipientType.UNKNOWN):
        risk_factors.append(f"Recipient trust boundary is '{context.recipient.value}'.")
    if context.classification in (DataClassification.CONFIDENTIAL, DataClassification.RESTRICTED):
        risk_factors.append(f"Organizational classification '{context.classification.value}' requires controlled custody.")

    # 3. Policy rationales from triggered policies
    policy_rationales: Dict[str, str] = {}
    for p in policy_result.triggered_policies:
        policy_rationales[p.id] = f"{p.name}: {p.intent_explanation}"

    # 4. Contextual ambiguities
    ambiguities: List[str] = []
    if context.destination == DestinationType.UNSPECIFIED:
        ambiguities.append("Destination is UNSPECIFIED: target processing environment is not declared.")
    if context.recipient == RecipientType.UNKNOWN:
        ambiguities.append("Recipient is UNKNOWN: identity and authorization boundary could not be verified.")

    # 5. Deterministic Remediation Recommendations
    has_secrets = any(f.category in (FindingCategory.SECRET, FindingCategory.CREDENTIAL, FindingCategory.HIGH_ENTROPY_TOKEN) for f in findings)
    has_cards = any(f.category == FindingCategory.PAYMENT_CARD for f in findings)
    has_pii = any(f.category == FindingCategory.PII for f in findings)

    if has_secrets:
        rec_list.append(
            RemediationRecommendation(
                id=f"REM-{rec_counter:02d}",
                action_type=RemediationActionType.ROTATE_CREDENTIAL,
                title="Rotate Compromised Credentials & API Keys",
                explanation="Immediately revoke the exposed secret in the cloud or provider console and generate new scoped credentials.",
                reason="One or more secrets or credentials detected in payload.",
                expected_security_benefit="Prevents unauthorized access in case the payload was intercepted or cached.",
                requires_human_approval=True,
                is_advisory=True,
            )
        )
        rec_counter += 1

        rec_list.append(
            RemediationRecommendation(
                id=f"REM-{rec_counter:02d}",
                action_type=RemediationActionType.RESTRICT_PUBLIC_SHARING,
                title="Block Egress to Public Endpoints",
                explanation="Enforce strict egress controls preventing transmission of API tokens and keys to external SaaS or public AI services.",
                reason="Policy POL-001 or hard-block boundary triggered.",
                expected_security_benefit="Maintains zero-trust boundary for cloud credentials.",
                requires_human_approval=False,
                is_advisory=True,
            )
        )
        rec_counter += 1

    if has_cards:
        rec_list.append(
            RemediationRecommendation(
                id=f"REM-{rec_counter:02d}",
                action_type=RemediationActionType.REDACT_SENSITIVE_VALUES,
                title="Mask Primary Account Number (PAN)",
                explanation="Enforce position-aware tokenization or masking of payment card digits prior to downstream transfer.",
                reason="Luhn-validated payment card detected in payload.",
                expected_security_benefit="Ensures PCI-DSS requirement compliance for storage and transfer of cardholder data.",
                requires_human_approval=False,
                is_advisory=True,
            )
        )
        rec_counter += 1

    if has_pii:
        rec_list.append(
            RemediationRecommendation(
                id=f"REM-{rec_counter:02d}",
                action_type=RemediationActionType.REQUEST_APPROVAL,
                title="Require Data Privacy Sign-off",
                explanation="Submit transfer request to compliance officer or data privacy owner before sharing regulated identifiers.",
                reason="PII detected in payload for non-internal recipient.",
                expected_security_benefit="Maintains GDPR / CCPA legal compliance auditability.",
                requires_human_approval=True,
                is_advisory=True,
            )
        )
        rec_counter += 1

    if bool(ambiguities):
        rec_list.append(
            RemediationRecommendation(
                id=f"REM-{rec_counter:02d}",
                action_type=RemediationActionType.REQUEST_HUMAN_REVIEW,
                title="Resolve Metadata Context Ambiguity",
                explanation="Specify intended destination system and verified recipient identity before releasing transfer.",
                reason="Zero-trust missing context policy triggered.",
                expected_security_benefit="Eliminates risk of unintended data leakage through default permissions.",
                requires_human_approval=True,
                is_advisory=True,
            )
        )
        rec_counter += 1

    human_review = policy_result.final_decision in (PolicyAction.REQUIRE_APPROVAL, PolicyAction.BLOCK) or bool(ambiguities)

    status = "UNAVAILABLE" if "not configured" in failure_reason.lower() else "FALLBACK"
    rate_limited = any(kw in failure_reason.lower() for kw in ["rate limit", "429", "quota", "resource_exhausted"])
    timed_out = "timeout" in failure_reason.lower()
    error_type = (
        "NOT_CONFIGURED" if "not configured" in failure_reason.lower()
        else ("RATE_LIMIT" if rate_limited
        else ("TIMEOUT" if timed_out
        else "PROVIDER_ERROR"))
    )

    usage = AIUsageTelemetry(
        prompt_tokens=None,
        candidates_tokens=None,
        total_tokens=None,
        cached_tokens=None,
        is_estimated=False,
        operation="context_policy_remediation",
        api_calls_count=api_calls_count,
        latency_ms=latency_ms,
        retries_attempted=retries_attempted,
        rate_limit_encountered=rate_limited,
        timeout_encountered=timed_out,
        error_type=error_type,
        fallback_reason=failure_reason,
        provider_status=status,
        provider_response_id=None,
    )

    return AIContextAnalysisResult(
        incident_summary=summary,
        relevant_risk_factors=risk_factors,
        policy_rationales=policy_rationales,
        ambiguities_and_uncertainty=ambiguities,
        remediation_recommendations=rec_list,
        human_review_recommended=human_review,
        ai_status=status,
        model_identifier="deterministic-fallback",
        is_ai_assisted=False,
        usage=usage,
        disclaimer=(
            f"Deterministic fallback active ({failure_reason}). "
            "Policy enforcement decisions and heuristic risk scores remain fully authoritative."
        ),
    )
