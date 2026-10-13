from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from app.engine.schemas import FindingCategory


class PolicyAction(str, Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    REDACT = "REDACT"
    BLOCK = "BLOCK"


class DestinationType(str, Enum):
    PUBLIC_LLM = "PUBLIC_LLM"
    EXTERNAL_SAAS = "EXTERNAL_SAAS"
    INTERNAL_SERVICE = "INTERNAL_SERVICE"
    INTERNAL_VECTOR_DB = "INTERNAL_VECTOR_DB"
    UNSPECIFIED = "UNSPECIFIED"


class RecipientType(str, Enum):
    PUBLIC = "PUBLIC"
    THIRD_PARTY_CONTRACTOR = "THIRD_PARTY_CONTRACTOR"
    INTERNAL_EMPLOYEE = "INTERNAL_EMPLOYEE"
    AUTHORIZED_ANALYST = "AUTHORIZED_ANALYST"
    UNKNOWN = "UNKNOWN"


class DataClassification(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


class SharingContext(BaseModel):
    destination: DestinationType = Field(
        default=DestinationType.UNSPECIFIED,
        description="Target destination or processing system for data",
    )
    recipient: RecipientType = Field(
        default=RecipientType.UNKNOWN,
        description="Recipient authorization level or trust boundary",
    )
    classification: DataClassification = Field(
        default=DataClassification.INTERNAL,
        description="Organizational data classification tier",
    )
    actor_id: str = Field(default="user_analyst", description="User or service account initiating the request")
    purpose: Optional[str] = Field(default=None, description="Optional stated business purpose")
    org_id: str = Field(
        default="default",
        description="Organization / Tenant identifier for scoped policy evaluation",
    )


class PolicyRule(BaseModel):
    id: str = Field(description="Unique stable policy ID, e.g., POL-001")
    org_id: str = Field(
        default="default",
        description="Organization or tenant associated with this rule ('default' applies globally)",
    )
    version: str = Field(default="1.0.0", description="Semantic policy version")
    name: str = Field(description="Human-readable rule name")
    description: str = Field(description="Detailed explanation of what this rule monitors")
    enabled: bool = Field(default=True, description="Whether rule is actively enforced")
    applicable_categories: List[FindingCategory] = Field(
        default_factory=list,
        description="Data categories that trigger this policy (empty = any/not category-restricted)",
    )
    applicable_sensitivities: List[DataClassification] = Field(
        default_factory=list,
        description="Sensitivity tiers triggering this policy (empty = any)",
    )
    target_destinations: List[DestinationType] = Field(
        default_factory=list,
        description="Destinations triggering this policy (empty = any destination)",
    )
    target_recipients: List[RecipientType] = Field(
        default_factory=list,
        description="Recipients triggering this policy (empty = any recipient)",
    )
    action: PolicyAction = Field(description="Enforcement action to take")
    priority: int = Field(default=10, description="Rule evaluation priority order (higher = higher priority)")
    intent_explanation: str = Field(description="Plain-language justification for security and compliance audits")


class PolicyEvaluationResult(BaseModel):
    final_decision: PolicyAction
    triggered_policies: List[PolicyRule]
    decision_reasons: List[str]
    hard_block_enforced: bool
    context_evaluated: SharingContext


class RiskContributingFactor(BaseModel):
    factor_name: str
    score_impact: float
    description: str


class RiskScoreResult(BaseModel):
    score: int = Field(ge=0, le=100, description="Risk index between 0 and 100")
    band: str = Field(description="Risk band: LOW, MEDIUM, HIGH, or CRITICAL")
    contributing_factors: List[RiskContributingFactor] = Field(default_factory=list)
    reasons: List[str] = Field(default_factory=list)
    triggered_policy_ids: List[str] = Field(default_factory=list)
    final_decision: PolicyAction
    hard_block_override: bool = Field(
        default=False,
        description="True if a hard-block policy enforced BLOCK independently of numerical risk score",
    )


class AuditEvent(BaseModel):
    event_id: str
    sequence_number: int
    timestamp: str
    event_type: str
    scan_id: Optional[str] = None
    actor_id: Optional[str] = None
    policy_decision: Optional[str] = None
    policy_references: List[str] = Field(default_factory=list)
    sanitized_metadata: Dict[str, Any] = Field(default_factory=dict)
    prev_event_hash: str
    event_hash: str


class AuditVerificationResult(BaseModel):
    is_valid: bool
    total_events: int
    verified_events: int
    tampered_event_id: Optional[str] = None
    errors: List[str] = Field(default_factory=list)
    chain_head_hash: Optional[str] = None
    details: str
