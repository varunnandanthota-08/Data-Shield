from typing import List
from app.engine.schemas import FindingCategory
from app.policy.schemas import (
    DataClassification,
    DestinationType,
    PolicyAction,
    PolicyRule,
    RecipientType,
)

DEFAULT_POLICIES: List[PolicyRule] = [
    PolicyRule(
        id="POL-001",
        version="1.0.0",
        name="Block Cloud Secrets and Credentials to Public Destinations",
        description="Strictly blocks exposure of credentials, private keys, API tokens, and secrets to public LLMs or external SaaS endpoints.",
        enabled=True,
        applicable_categories=[
            FindingCategory.SECRET,
            FindingCategory.CREDENTIAL,
            FindingCategory.HIGH_ENTROPY_TOKEN,
        ],
        applicable_sensitivities=[],
        target_destinations=[
            DestinationType.PUBLIC_LLM,
            DestinationType.EXTERNAL_SAAS,
        ],
        target_recipients=[],
        action=PolicyAction.BLOCK,
        priority=100,
        intent_explanation="Zero-tolerance boundary for secrets and private keys. Hard blocks unredacted transmission to external or public artificial intelligence services.",
    ),
    PolicyRule(
        id="POL-002",
        version="1.0.0",
        name="Require Approval for Restricted Personal & Cardholder Data to External Recipients",
        description="Requires formal compliance and data owner sign-off before sending PII or PCI payment card numbers to external third parties or public recipients.",
        enabled=True,
        applicable_categories=[
            FindingCategory.PII,
            FindingCategory.PAYMENT_CARD,
        ],
        applicable_sensitivities=[
            DataClassification.CONFIDENTIAL,
            DataClassification.RESTRICTED,
        ],
        target_destinations=[],
        target_recipients=[
            RecipientType.PUBLIC,
            RecipientType.THIRD_PARTY_CONTRACTOR,
            RecipientType.UNKNOWN,
        ],
        action=PolicyAction.REQUIRE_APPROVAL,
        priority=80,
        intent_explanation="Enforces GDPR, CCPA, and PCI-DSS compliance by requiring manual authorization when regulated customer identifiers leave direct internal custody.",
    ),
    PolicyRule(
        id="POL-003",
        version="1.0.0",
        name="Warn on Confidential Data Shared Outside Organization",
        description="Issues an advisory alert when confidential or restricted organizational data is shared to public destinations or external software systems.",
        enabled=True,
        applicable_categories=[],
        applicable_sensitivities=[
            DataClassification.CONFIDENTIAL,
            DataClassification.RESTRICTED,
        ],
        target_destinations=[
            DestinationType.PUBLIC_LLM,
            DestinationType.EXTERNAL_SAAS,
        ],
        target_recipients=[],
        action=PolicyAction.WARN,
        priority=60,
        intent_explanation="Maintains user security awareness of corporate confidentiality boundaries during external data interactions.",
    ),
    PolicyRule(
        id="POL-004",
        version="1.0.0",
        name="Escalate Ambiguous or Insufficiently Specified Transfer Context",
        description="Zero-trust safety fallback: escalates to review whenever transfer destination or recipient is unspecified/unknown for non-public content or detected findings.",
        enabled=True,
        applicable_categories=[],
        applicable_sensitivities=[
            DataClassification.INTERNAL,
            DataClassification.CONFIDENTIAL,
            DataClassification.RESTRICTED,
        ],
        target_destinations=[
            DestinationType.UNSPECIFIED,
        ],
        target_recipients=[
            RecipientType.UNKNOWN,
        ],
        action=PolicyAction.REQUIRE_APPROVAL,
        priority=70,
        intent_explanation="Prevents silent authorization when metadata context is missing. Ambiguity must escalate to approval rather than assuming safety.",
    ),
    PolicyRule(
        id="POL-005",
        version="1.0.0",
        name="Default Baseline Allow for Low-Risk Internal Content",
        description="Permits processing of low-risk content within internal services or authorized workflows when no restrictive policies trigger.",
        enabled=True,
        applicable_categories=[],
        applicable_sensitivities=[
            DataClassification.PUBLIC,
            DataClassification.INTERNAL,
        ],
        target_destinations=[
            DestinationType.INTERNAL_SERVICE,
            DestinationType.INTERNAL_VECTOR_DB,
        ],
        target_recipients=[
            RecipientType.INTERNAL_EMPLOYEE,
            RecipientType.AUTHORIZED_ANALYST,
        ],
        action=PolicyAction.ALLOW,
        priority=10,
        intent_explanation="Provides baseline operational throughput for safe internal development and business analytics pipelines.",
    ),
]
