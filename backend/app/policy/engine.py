from typing import Dict, List, Optional
from app.engine.schemas import Finding, FindingCategory
from app.policy.defaults import DEFAULT_POLICIES
from app.policy.schemas import (
    DataClassification,
    DestinationType,
    PolicyAction,
    PolicyEvaluationResult,
    PolicyRule,
    RecipientType,
    SharingContext,
)

# Deterministic Precedence Hierarchy
# Higher numerical value indicates higher priority
ACTION_PRECEDENCE: Dict[PolicyAction, int] = {
    PolicyAction.BLOCK: 50,
    PolicyAction.REQUIRE_APPROVAL: 40,
    PolicyAction.REDACT: 30,
    PolicyAction.WARN: 20,
    PolicyAction.ALLOW: 10,
}


class PolicyEngine:
    """Modular, deterministic policy engine evaluating security and privacy rules.
    Operates without non-deterministic LLM dependencies.
    """

    def __init__(self, rules: Optional[List[PolicyRule]] = None):
        self._rules: List[PolicyRule] = list(rules) if rules is not None else list(DEFAULT_POLICIES)

    @property
    def rules(self) -> List[PolicyRule]:
        return list(self._rules)

    def set_rules(self, rules: List[PolicyRule]) -> None:
        self._rules = list(rules)

    def add_or_update_rule(self, rule: PolicyRule) -> None:
        for idx, existing in enumerate(self._rules):
            if existing.id == rule.id:
                self._rules[idx] = rule
                return
        self._rules.append(rule)

    def _matches_rule(self, rule: PolicyRule, findings: List[Finding], context: SharingContext) -> bool:
        """Determines if a rule triggers based on findings and sharing context."""
        if not rule.enabled:
            return False

        # 1. Applicable Finding Categories check
        if rule.applicable_categories:
            finding_categories = {f.category for f in findings}
            if not any(cat in finding_categories for cat in rule.applicable_categories):
                return False

        # 2. Data Sensitivity Classification check
        if rule.applicable_sensitivities:
            if context.classification not in rule.applicable_sensitivities:
                return False

        # 3. Target Destination constraint check
        if rule.target_destinations:
            if context.destination not in rule.target_destinations:
                return False

        # 4. Target Recipient constraint check
        if rule.target_recipients:
            if context.recipient not in rule.target_recipients:
                return False

        return True

    def evaluate(
        self,
        findings: List[Finding],
        context: Optional[SharingContext] = None,
    ) -> PolicyEvaluationResult:
        """Evaluates all configured policies against findings and sharing context.
        Enforces strict precedence: BLOCK > REQUIRE_APPROVAL > REDACT > WARN > ALLOW.
        Zero-trust principle: Missing context must never silently imply authorization.
        """
        ctx = context or SharingContext()
        triggered: List[PolicyRule] = []
        reasons: List[str] = []

        # Sort rules by explicit priority (highest priority first)
        sorted_rules = sorted(self._rules, key=lambda r: -r.priority)

        # Evaluate rules
        for rule in sorted_rules:
            # Check for ambiguous context policy trigger
            if rule.id == "POL-004":
                # POL-004 triggers if EITHER destination is UNSPECIFIED or recipient is UNKNOWN,
                # provided there are sensitive findings or non-public classification
                is_ambiguous = (
                    ctx.destination == DestinationType.UNSPECIFIED
                    or ctx.recipient == RecipientType.UNKNOWN
                )
                has_sensitive_data = bool(findings) or (ctx.classification != DataClassification.PUBLIC)
                if is_ambiguous and has_sensitive_data and rule.enabled:
                    triggered.append(rule)
                    reasons.append(
                        f"Rule {rule.id} ('{rule.name}') triggered: Ambiguous transfer destination ({ctx.destination.value}) "
                        f"or recipient ({ctx.recipient.value}) with sensitive content."
                    )
                continue

            if self._matches_rule(rule, findings, ctx):
                triggered.append(rule)
                reasons.append(
                    f"Rule {rule.id} ('{rule.name}') triggered action {rule.action.value}: {rule.intent_explanation}"
                )

        # Zero-trust safety fallback: If destination or recipient is ambiguous and findings exist,
        # never silently allow even if no custom rule matched
        has_ambiguity = (
            ctx.destination == DestinationType.UNSPECIFIED
            or ctx.recipient == RecipientType.UNKNOWN
        )
        if has_ambiguity and findings and not any(r.action in (PolicyAction.BLOCK, PolicyAction.REQUIRE_APPROVAL) for r in triggered):
            reasons.append(
                "Zero-trust fallback: Transfer context contains unspecified destination or unknown recipient "
                "with active findings. Escalating to REQUIRE_APPROVAL."
            )
            # Create synthetic fallback trigger indicator
            fallback_rule = PolicyRule(
                id="POL-FALLBACK-001",
                version="1.0.0",
                name="Zero-Trust Missing Context Safeguard",
                description="Automatically escalates transfers with unspecified destination or unknown recipient to REQUIRE_APPROVAL.",
                enabled=True,
                action=PolicyAction.REQUIRE_APPROVAL,
                priority=75,
                intent_explanation="Missing context must never silently imply authorization.",
            )
            triggered.append(fallback_rule)

        # Determine final decision based on strict precedence hierarchy
        if not triggered:
            # If no policies matched and no findings exist, allow
            if not findings:
                final_decision = PolicyAction.ALLOW
                reasons.append("No policies triggered and zero sensitive entities detected. Content allowed.")
            else:
                # Findings exist but no restrictive policy matched -> default to WARN for awareness
                final_decision = PolicyAction.WARN
                reasons.append(f"{len(findings)} sensitive entity/entities detected without restrictive policy match. Advisory WARN.")
            hard_block_enforced = False
        else:
            # Select action with the highest precedence rank
            # If equal precedence, select highest priority rule
            highest_action = max(
                (r.action for r in triggered),
                key=lambda a: ACTION_PRECEDENCE.get(a, 0),
            )
            final_decision = highest_action
            hard_block_enforced = (final_decision == PolicyAction.BLOCK)

        if hard_block_enforced:
            reasons.append("HARD-BLOCK ENFORCED: Critical security boundary violation prevents transmission.")

        return PolicyEvaluationResult(
            final_decision=final_decision,
            triggered_policies=triggered,
            decision_reasons=reasons,
            hard_block_enforced=hard_block_enforced,
            context_evaluated=ctx,
        )


# Global default policy engine instance
policy_engine = PolicyEngine()
