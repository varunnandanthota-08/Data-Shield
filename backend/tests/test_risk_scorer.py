import pytest
from app.engine.schemas import (
    ConfidenceBand,
    Finding,
    FindingCategory,
    SeverityLevel,
)
from app.policy.engine import PolicyEngine
from app.policy.risk_scorer import (
    CompositeRiskScorer,
    RiskScoringConfig,
    deduplicate_overlapping_findings,
)
from app.policy.schemas import (
    DataClassification,
    DestinationType,
    PolicyAction,
    PolicyEvaluationResult,
    RecipientType,
    SharingContext,
)


def create_finding(
    category: FindingCategory,
    severity: SeverityLevel,
    confidence: float,
    start_offset: int,
    end_offset: int,
) -> Finding:
    return Finding(
        id=f"f_{start_offset}_{end_offset}",
        category=category,
        detector_name="test_detector",
        rule_id="test_rule",
        severity=severity,
        confidence=confidence,
        confidence_band=ConfidenceBand.HIGH,
        start_offset=start_offset,
        end_offset=end_offset,
        masked_evidence="****masked****",
        suggested_remediation="Test remediation",
    )


class TestRiskScoreBoundariesAndExplainability:
    def test_clean_internal_payload_has_low_risk(self):
        scorer = CompositeRiskScorer()
        engine = PolicyEngine()
        ctx = SharingContext(
            destination=DestinationType.INTERNAL_SERVICE,
            recipient=RecipientType.INTERNAL_EMPLOYEE,
            classification=DataClassification.PUBLIC,
        )

        policy_res = engine.evaluate([], ctx)
        risk_res = scorer.calculate_risk([], ctx, policy_res)

        assert 0 <= risk_res.score <= 29
        assert risk_res.band == "LOW"
        assert risk_res.final_decision == PolicyAction.ALLOW
        assert len(risk_res.contributing_factors) >= 3
        assert len(risk_res.reasons) > 0

    def test_critical_secret_to_public_destination_has_critical_risk(self):
        scorer = CompositeRiskScorer()
        engine = PolicyEngine()
        secret = create_finding(
            FindingCategory.SECRET,
            SeverityLevel.CRITICAL,
            confidence=0.99,
            start_offset=10,
            end_offset=50,
        )
        ctx = SharingContext(
            destination=DestinationType.PUBLIC_LLM,
            recipient=RecipientType.PUBLIC,
            classification=DataClassification.RESTRICTED,
        )

        policy_res = engine.evaluate([secret], ctx)
        risk_res = scorer.calculate_risk([secret], ctx, policy_res)

        assert risk_res.score >= 85
        assert risk_res.band == "CRITICAL"
        assert risk_res.final_decision == PolicyAction.BLOCK
        assert risk_res.hard_block_override is True

    def test_score_never_exceeds_100_or_falls_below_0(self):
        scorer = CompositeRiskScorer()
        engine = PolicyEngine()
        # Create many severe findings
        many_findings = [
            create_finding(FindingCategory.SECRET, SeverityLevel.CRITICAL, 1.0, i * 40, (i + 1) * 40)
            for i in range(15)
        ]
        ctx = SharingContext(
            destination=DestinationType.PUBLIC_LLM,
            recipient=RecipientType.PUBLIC,
            classification=DataClassification.RESTRICTED,
        )

        policy_res = engine.evaluate(many_findings, ctx)
        risk_res = scorer.calculate_risk(many_findings, ctx, policy_res)

        assert risk_res.score <= 100
        assert risk_res.score >= 0


class TestOverlappingFindingsDeduplication:
    def test_overlapping_spans_are_deduplicated_without_double_counting(self):
        """Avoid double-counting multiple detectors that identify the same underlying value."""
        # Span from 10 to 30 matched by both a High-Entropy detector and an AWS Key detector
        f_entropy = create_finding(
            FindingCategory.HIGH_ENTROPY_TOKEN,
            SeverityLevel.MEDIUM,
            confidence=0.75,
            start_offset=10,
            end_offset=30,
        )
        f_aws = create_finding(
            FindingCategory.SECRET,
            SeverityLevel.CRITICAL,
            confidence=0.99,
            start_offset=10,
            end_offset=30,
        )

        raw_findings = [f_entropy, f_aws]
        deduped = deduplicate_overlapping_findings(raw_findings)

        # Overlapping finding resolved to 1 entry: the higher severity CRITICAL AWS key
        assert len(deduped) == 1
        assert deduped[0].category == FindingCategory.SECRET
        assert deduped[0].severity == SeverityLevel.CRITICAL

    def test_non_overlapping_spans_are_both_preserved(self):
        f1 = create_finding(FindingCategory.PII, SeverityLevel.MEDIUM, 0.90, 0, 15)
        f2 = create_finding(FindingCategory.SECRET, SeverityLevel.HIGH, 0.95, 20, 50)

        deduped = deduplicate_overlapping_findings([f1, f2])
        assert len(deduped) == 2


class TestHardBlockOverride:
    def test_hard_block_policy_enforces_block_independently_of_score(self):
        scorer = CompositeRiskScorer()
        # Fabricate an artificial policy result where decision is BLOCK
        dummy_policy_res = PolicyEvaluationResult(
            final_decision=PolicyAction.BLOCK,
            triggered_policies=[],
            decision_reasons=["Enforced block for security containment."],
            hard_block_enforced=True,
            context_evaluated=SharingContext(),
        )

        ctx = SharingContext(
            destination=DestinationType.INTERNAL_SERVICE,
            recipient=RecipientType.INTERNAL_EMPLOYEE,
            classification=DataClassification.INTERNAL,
        )

        # Even with zero findings and low context points, final decision must be BLOCK
        risk_res = scorer.calculate_risk([], ctx, dummy_policy_res)

        assert risk_res.final_decision == PolicyAction.BLOCK
        assert risk_res.hard_block_override is True
        assert any("HARD-BLOCK OVERRIDE ENFORCED" in r for r in risk_res.reasons)
