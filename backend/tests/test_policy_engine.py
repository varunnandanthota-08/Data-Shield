import pytest
from app.engine.schemas import (
    ConfidenceBand,
    Finding,
    FindingCategory,
    SeverityLevel,
)
from app.policy.engine import PolicyEngine
from app.policy.schemas import (
    DataClassification,
    DestinationType,
    PolicyAction,
    PolicyRule,
    RecipientType,
    SharingContext,
)


def create_dummy_finding(
    category: FindingCategory,
    severity: SeverityLevel = SeverityLevel.HIGH,
    confidence: float = 0.95,
    start_offset: int = 10,
    end_offset: int = 30,
    rule_id: str = "test_rule",
) -> Finding:
    return Finding(
        id=f"f_{category.value}_{start_offset}",
        category=category,
        detector_name="test_detector",
        rule_id=rule_id,
        severity=severity,
        confidence=confidence,
        confidence_band=ConfidenceBand.VERY_HIGH,
        start_offset=start_offset,
        end_offset=end_offset,
        masked_evidence="***-MASKED-***",
        suggested_remediation="Rotate test credential immediately",
    )


class TestPolicyEngineMatchingAndPrecedence:
    def test_pol001_blocks_secret_to_public_destination(self):
        engine = PolicyEngine()
        secret_finding = create_dummy_finding(FindingCategory.SECRET, SeverityLevel.CRITICAL)
        ctx = SharingContext(
            destination=DestinationType.PUBLIC_LLM,
            recipient=RecipientType.PUBLIC,
            classification=DataClassification.CONFIDENTIAL,
        )

        result = engine.evaluate([secret_finding], ctx)

        assert result.final_decision == PolicyAction.BLOCK
        assert result.hard_block_enforced is True
        assert any(p.id == "POL-001" for p in result.triggered_policies)

    def test_pol001_does_not_block_secret_to_internal_service(self):
        engine = PolicyEngine()
        secret_finding = create_dummy_finding(FindingCategory.SECRET, SeverityLevel.CRITICAL)
        ctx = SharingContext(
            destination=DestinationType.INTERNAL_SERVICE,
            recipient=RecipientType.INTERNAL_EMPLOYEE,
            classification=DataClassification.INTERNAL,
        )

        result = engine.evaluate([secret_finding], ctx)

        # Internal service destination does not trigger POL-001 (BLOCK)
        assert result.final_decision != PolicyAction.BLOCK
        assert not any(p.id == "POL-001" for p in result.triggered_policies)

    def test_pol002_requires_approval_for_pii_to_external_recipient(self):
        engine = PolicyEngine()
        pii_finding = create_dummy_finding(FindingCategory.PII, SeverityLevel.HIGH)
        ctx = SharingContext(
            destination=DestinationType.INTERNAL_SERVICE,
            recipient=RecipientType.THIRD_PARTY_CONTRACTOR,
            classification=DataClassification.RESTRICTED,
        )

        result = engine.evaluate([pii_finding], ctx)

        assert result.final_decision == PolicyAction.REQUIRE_APPROVAL
        assert any(p.id == "POL-002" for p in result.triggered_policies)

    def test_pol003_warns_on_confidential_data_sent_externally(self):
        engine = PolicyEngine()
        ctx = SharingContext(
            destination=DestinationType.EXTERNAL_SAAS,
            recipient=RecipientType.PUBLIC,
            classification=DataClassification.CONFIDENTIAL,
        )

        # No specific secret findings, but organizational classification is CONFIDENTIAL to external SaaS
        result = engine.evaluate([], ctx)

        assert result.final_decision == PolicyAction.WARN
        assert any(p.id == "POL-003" for p in result.triggered_policies)

    def test_pol005_allows_clean_low_risk_internal_content(self):
        engine = PolicyEngine()
        ctx = SharingContext(
            destination=DestinationType.INTERNAL_SERVICE,
            recipient=RecipientType.INTERNAL_EMPLOYEE,
            classification=DataClassification.INTERNAL,
        )

        result = engine.evaluate([], ctx)

        assert result.final_decision == PolicyAction.ALLOW
        assert result.hard_block_enforced is False

    def test_hard_block_precedence_overrides_allow_and_warn(self):
        """A hard-block policy must never be overridden by an allow rule."""
        engine = PolicyEngine()
        secret_finding = create_dummy_finding(FindingCategory.SECRET, SeverityLevel.CRITICAL)
        ctx = SharingContext(
            destination=DestinationType.PUBLIC_LLM,
            recipient=RecipientType.INTERNAL_EMPLOYEE,
            classification=DataClassification.INTERNAL,
        )

        result = engine.evaluate([secret_finding], ctx)

        # Even if recipient is internal employee, sending secret to PUBLIC_LLM triggers POL-001 BLOCK
        assert result.final_decision == PolicyAction.BLOCK
        assert result.hard_block_enforced is True


class TestAmbiguousAndMissingContext:
    def test_pol004_escalates_unspecified_destination_with_findings(self):
        """Missing destination context must never silently imply authorization."""
        engine = PolicyEngine()
        pii_finding = create_dummy_finding(FindingCategory.PII, SeverityLevel.MEDIUM)
        ctx = SharingContext(
            destination=DestinationType.UNSPECIFIED,
            recipient=RecipientType.INTERNAL_EMPLOYEE,
            classification=DataClassification.INTERNAL,
        )

        result = engine.evaluate([pii_finding], ctx)

        # Must escalate to REQUIRE_APPROVAL instead of assuming destination is safe
        assert result.final_decision == PolicyAction.REQUIRE_APPROVAL
        assert any(p.id in ("POL-004", "POL-FALLBACK-001") for p in result.triggered_policies)

    def test_pol004_escalates_unknown_recipient_with_sensitive_content(self):
        engine = PolicyEngine()
        ctx = SharingContext(
            destination=DestinationType.INTERNAL_SERVICE,
            recipient=RecipientType.UNKNOWN,
            classification=DataClassification.RESTRICTED,
        )

        result = engine.evaluate([], ctx)

        assert result.final_decision == PolicyAction.REQUIRE_APPROVAL
        assert any(p.id == "POL-004" for p in result.triggered_policies)

    def test_disabled_policy_is_ignored(self):
        custom_rule = PolicyRule(
            id="POL-CUSTOM-TEST",
            version="1.0.0",
            name="Disabled Test Rule",
            description="Should not trigger when disabled",
            enabled=False,
            target_destinations=[DestinationType.INTERNAL_SERVICE],
            action=PolicyAction.BLOCK,
            priority=999,
            intent_explanation="Disabled testing rule",
        )
        engine = PolicyEngine([custom_rule])
        ctx = SharingContext(destination=DestinationType.INTERNAL_SERVICE)

        result = engine.evaluate([], ctx)

        assert not any(p.id == "POL-CUSTOM-TEST" for p in result.triggered_policies)
        assert result.final_decision != PolicyAction.BLOCK

    def test_hard_block_invariance_over_all_other_actions(self):
        """Hard block invariance: BLOCK must always win over ALLOW, WARN, REQUIRE_APPROVAL, and REDACT."""
        rules = [
            PolicyRule(
                id="POL-ALLOW",
                name="Allow Rule",
                description="allow",
                enabled=True,
                action=PolicyAction.ALLOW,
                priority=100,
                intent_explanation="allow",
            ),
            PolicyRule(
                id="POL-WARN",
                name="Warn Rule",
                description="warn",
                enabled=True,
                action=PolicyAction.WARN,
                priority=90,
                intent_explanation="warn",
            ),
            PolicyRule(
                id="POL-REQUIRE-APPROVAL",
                name="Approval Rule",
                description="approval",
                enabled=True,
                action=PolicyAction.REQUIRE_APPROVAL,
                priority=80,
                intent_explanation="approval",
            ),
            PolicyRule(
                id="POL-REDACT",
                name="Redact Rule",
                description="redact",
                enabled=True,
                action=PolicyAction.REDACT,
                priority=70,
                intent_explanation="redact",
            ),
            PolicyRule(
                id="POL-BLOCK",
                name="Block Rule",
                description="block",
                enabled=True,
                action=PolicyAction.BLOCK,
                priority=10,  # Lowest priority number
                intent_explanation="block",
            ),
        ]
        engine = PolicyEngine(rules)
        ctx = SharingContext()
        finding = create_dummy_finding(FindingCategory.SECRET)

        result = engine.evaluate([finding], ctx)
        assert result.final_decision == PolicyAction.BLOCK
        assert result.hard_block_enforced is True

    def test_rule_priority_cannot_override_block(self):
        """Verify that high numerical rule priority cannot override hard-block invariance."""
        allow_super_priority = PolicyRule(
            id="POL-SUPER-ALLOW",
            name="Super High Priority Allow",
            description="attempt to bypass block",
            enabled=True,
            action=PolicyAction.ALLOW,
            priority=99999,
            intent_explanation="attempt bypass",
        )
        block_low_priority = PolicyRule(
            id="POL-LOW-BLOCK",
            name="Low Priority Block",
            description="hard block",
            enabled=True,
            action=PolicyAction.BLOCK,
            priority=1,
            intent_explanation="must enforce",
        )
        engine = PolicyEngine([allow_super_priority, block_low_priority])
        ctx = SharingContext()
        finding = create_dummy_finding(FindingCategory.SECRET)

        result = engine.evaluate([finding], ctx)
        assert result.final_decision == PolicyAction.BLOCK
        assert result.hard_block_enforced is True

    def test_zero_trust_missing_context_escalates_confidential_without_findings(self):
        """Zero-trust: missing context on confidential data escalates to REQUIRE_APPROVAL even with zero findings."""
        engine = PolicyEngine()  # default policies
        ctx = SharingContext(
            destination=DestinationType.UNSPECIFIED,
            recipient=RecipientType.UNKNOWN,
            classification=DataClassification.CONFIDENTIAL,
        )

        result = engine.evaluate([], ctx)
        assert result.final_decision == PolicyAction.REQUIRE_APPROVAL
        assert any("POL-004" in p.id or "POL-FALLBACK" in p.id for p in result.triggered_policies)
