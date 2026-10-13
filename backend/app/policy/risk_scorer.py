from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from app.engine.schemas import Finding, SeverityLevel
from app.policy.schemas import (
    DataClassification,
    DestinationType,
    PolicyAction,
    PolicyEvaluationResult,
    RecipientType,
    RiskContributingFactor,
    RiskScoreResult,
    SharingContext,
)


class RiskScoringConfig(BaseModel):
    """Configurable weights and thresholds for deterministic composite risk scoring."""

    severity_base_points: Dict[SeverityLevel, float] = Field(
        default={
            SeverityLevel.CRITICAL: 30.0,
            SeverityLevel.HIGH: 20.0,
            SeverityLevel.MEDIUM: 10.0,
            SeverityLevel.LOW: 4.0,
            SeverityLevel.INFORMATIONAL: 1.0,
        }
    )
    max_findings_score: float = 35.0

    classification_points: Dict[DataClassification, float] = Field(
        default={
            DataClassification.RESTRICTED: 10.0,
            DataClassification.CONFIDENTIAL: 6.0,
            DataClassification.INTERNAL: 2.0,
            DataClassification.PUBLIC: 0.0,
        }
    )

    destination_points: Dict[DestinationType, float] = Field(
        default={
            DestinationType.PUBLIC_LLM: 25.0,
            DestinationType.EXTERNAL_SAAS: 18.0,
            DestinationType.UNSPECIFIED: 15.0,
            DestinationType.INTERNAL_VECTOR_DB: 8.0,
            DestinationType.INTERNAL_SERVICE: 3.0,
        }
    )

    recipient_points: Dict[RecipientType, float] = Field(
        default={
            RecipientType.PUBLIC: 15.0,
            RecipientType.UNKNOWN: 12.0,
            RecipientType.THIRD_PARTY_CONTRACTOR: 9.0,
            RecipientType.INTERNAL_EMPLOYEE: 3.0,
            RecipientType.AUTHORIZED_ANALYST: 0.0,
        }
    )

    action_escalation_points: Dict[PolicyAction, float] = Field(
        default={
            PolicyAction.BLOCK: 15.0,
            PolicyAction.REQUIRE_APPROVAL: 10.0,
            PolicyAction.REDACT: 6.0,
            PolicyAction.WARN: 3.0,
            PolicyAction.ALLOW: 0.0,
        }
    )

    # Risk Band boundaries
    low_upper: int = 29
    medium_upper: int = 59
    high_upper: int = 84


def deduplicate_overlapping_findings(findings: List[Finding]) -> List[Finding]:
    """Deduplicates findings that cover overlapping character spans to avoid
    double-counting multiple detectors that identify the same underlying value.
    Retains the finding with highest severity and confidence.
    """
    if not findings:
        return []

    severity_rank = {
        SeverityLevel.CRITICAL: 5,
        SeverityLevel.HIGH: 4,
        SeverityLevel.MEDIUM: 3,
        SeverityLevel.LOW: 2,
        SeverityLevel.INFORMATIONAL: 1,
    }

    sorted_findings = sorted(
        findings,
        key=lambda f: (
            f.start_offset,
            -severity_rank.get(f.severity, 0),
            -f.confidence,
        ),
    )

    deduped: List[Finding] = []
    current_end = -1

    for f in sorted_findings:
        if f.start_offset >= current_end:
            deduped.append(f)
            current_end = f.end_offset
        else:
            # Overlap detected; compare with last chosen finding
            last = deduped[-1]
            last_rank = severity_rank.get(last.severity, 0)
            f_rank = severity_rank.get(f.severity, 0)
            if (f_rank > last_rank) or (f_rank == last_rank and f.confidence > last.confidence):
                deduped[-1] = f
                current_end = f.end_offset

    return deduped


class CompositeRiskScorer:
    """Deterministic, explainable risk scoring engine.
    Computes a composite index (0-100) combining data sensitivity, detection confidence,
    destination exposure, recipient authorization, and policy violations.
    Note: The score is a heuristic risk index, not a statistically calibrated probability.
    """

    def __init__(self, config: Optional[RiskScoringConfig] = None):
        self.config = config or RiskScoringConfig()

    def calculate_risk(
        self,
        findings: List[Finding],
        context: SharingContext,
        policy_result: PolicyEvaluationResult,
    ) -> RiskScoreResult:
        factors: List[RiskContributingFactor] = []
        reasons: List[str] = []

        # 1. Deduplicate findings to prevent double-counting overlapping detector matches
        deduped_findings = deduplicate_overlapping_findings(findings)

        # 2. Data Sensitivity & Detection Confidence Factor (0 - 45 points max)
        # Confidence reflects detector certainty; Severity reflects data sensitivity impact.
        findings_score = 0.0
        for f in deduped_findings:
            base_pts = self.config.severity_base_points.get(f.severity, 1.0)
            # Confidence scales detection certainty
            weighted = base_pts * f.confidence
            findings_score += weighted

        findings_score = min(findings_score, self.config.max_findings_score)
        class_pts = self.config.classification_points.get(context.classification, 0.0)
        data_sensitivity_total = round(findings_score + class_pts, 2)

        factors.append(
            RiskContributingFactor(
                factor_name="Data Sensitivity & Detection Confidence",
                score_impact=data_sensitivity_total,
                description=(
                    f"Identified {len(deduped_findings)} unique non-overlapping finding(s) "
                    f"(findings impact: {findings_score:.1f} pts) with organizational classification "
                    f"'{context.classification.value}' (+{class_pts:.1f} pts)."
                ),
            )
        )
        if deduped_findings:
            reasons.append(
                f"{len(deduped_findings)} unique sensitive finding(s) detected with max severity "
                f"'{max(f.severity.value for f in deduped_findings)}'."
            )

        # 3. Destination Exposure Factor (0 - 25 points)
        raw_dest_pts = self.config.destination_points.get(context.destination, 15.0)
        # If payload has zero findings and is marked PUBLIC, scale down exposure impact
        is_sensitive = bool(deduped_findings) or (context.classification != DataClassification.PUBLIC)
        dest_impact = round(raw_dest_pts if is_sensitive else (raw_dest_pts * 0.1), 2)

        factors.append(
            RiskContributingFactor(
                factor_name="Destination Exposure",
                score_impact=dest_impact,
                description=f"Destination '{context.destination.value}' exposure rating ({dest_impact:.1f} pts).",
            )
        )
        reasons.append(f"Destination is '{context.destination.value}'.")

        # 4. Recipient Authorization Factor (0 - 15 points)
        raw_recip_pts = self.config.recipient_points.get(context.recipient, 12.0)
        recip_impact = round(raw_recip_pts if is_sensitive else (raw_recip_pts * 0.1), 2)

        factors.append(
            RiskContributingFactor(
                factor_name="Recipient Authorization",
                score_impact=recip_impact,
                description=f"Recipient trust boundary '{context.recipient.value}' ({recip_impact:.1f} pts).",
            )
        )
        reasons.append(f"Recipient trust level is '{context.recipient.value}'.")

        # 5. Policy Violations Escalation Factor (0 - 15 points)
        policy_action = policy_result.final_decision
        policy_impact = round(self.config.action_escalation_points.get(policy_action, 0.0), 2)

        factors.append(
            RiskContributingFactor(
                factor_name="Policy Violations Escalation",
                score_impact=policy_impact,
                description=f"Action '{policy_action.value}' triggered from {len(policy_result.triggered_policies)} matching policy/policies (+{policy_impact:.1f} pts).",
            )
        )

        # Aggregate total score
        total_raw = data_sensitivity_total + dest_impact + recip_impact + policy_impact
        score = max(0, min(100, int(round(total_raw))))

        # Determine risk band
        if score <= self.config.low_upper:
            band = "LOW"
        elif score <= self.config.medium_upper:
            band = "MEDIUM"
        elif score <= self.config.high_upper:
            band = "HIGH"
        else:
            band = "CRITICAL"

        # Check Hard-Block Override
        # A critical hard-block policy must enforce BLOCK independently of aggregate score
        hard_block_override = False
        final_decision = policy_action

        if policy_result.hard_block_enforced or policy_action == PolicyAction.BLOCK:
            final_decision = PolicyAction.BLOCK
            hard_block_override = True
            reasons.append(
                f"HARD-BLOCK OVERRIDE ENFORCED: Critical security policy mandate enforces BLOCK "
                f"independently of composite numerical score ({score}/100)."
            )

        triggered_ids = [p.id for p in policy_result.triggered_policies]

        return RiskScoreResult(
            score=score,
            band=band,
            contributing_factors=factors,
            reasons=reasons,
            triggered_policy_ids=triggered_ids,
            final_decision=final_decision,
            hard_block_override=hard_block_override,
        )


# Global default risk scorer instance
risk_scorer = CompositeRiskScorer()
