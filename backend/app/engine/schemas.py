from enum import Enum
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field, field_validator


class FindingCategory(str, Enum):
    PII = "PII"
    PAYMENT_CARD = "PAYMENT_CARD"
    SECRET = "SECRET"
    CREDENTIAL = "CREDENTIAL"
    HIGH_ENTROPY_TOKEN = "HIGH_ENTROPY_TOKEN"


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class ConfidenceBand(str, Enum):
    VERY_HIGH = "VERY_HIGH"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ScanOptions(BaseModel):
    enable_entropy: bool = Field(default=True, description="Enable Shannon high-entropy token detection")
    entropy_threshold: float = Field(default=4.2, ge=2.0, le=6.0, description="Shannon entropy bit threshold (typical 4.0 - 4.5)")
    min_entropy_len: int = Field(default=20, ge=8, le=128, description="Minimum length for entropy token consideration")
    redaction_mode: Literal["placeholder", "synthetic"] = Field(default="placeholder", description="Redaction mode: 'placeholder' or 'synthetic'")


class Finding(BaseModel):
    id: str = Field(description="Unique stable ID for this finding")
    category: FindingCategory
    detector_name: str
    rule_id: str
    severity: SeverityLevel
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score between 0.0 and 1.0")
    confidence_band: ConfidenceBand
    start_offset: int = Field(ge=0, description="Character start offset in original text")
    end_offset: int = Field(ge=0, description="Character end offset in original text")
    masked_evidence: str = Field(description="Sanitized and masked snippet. Never raw secrets.")
    suggested_remediation: str = Field(description="Actionable least-privilege fix advice")
    validation_metadata: Dict[str, Any] = Field(default_factory=dict, description="Metadata such as checksum results")


class FindingCounts(BaseModel):
    by_category: Dict[str, int] = Field(default_factory=dict)
    by_severity: Dict[str, int] = Field(default_factory=dict)
    total: int = 0


class ScanRequest(BaseModel):
    text: str = Field(..., max_length=500_000, description="Raw input text to scan and redact (max 500,000 chars)")
    options: Optional[ScanOptions] = Field(default=None, description="Optional scan and redaction configuration")
    context: Optional[Any] = Field(default=None, description="Optional explicit sharing context (destination, recipient, classification)")

    @field_validator("context", mode="before")
    @classmethod
    def validate_context(cls, v: Any) -> Any:
        if v is None:
            return None
        from app.policy.schemas import SharingContext
        if isinstance(v, SharingContext):
            return v
        if isinstance(v, dict):
            return SharingContext(**v)
        raise ValueError("context must be a valid SharingContext object or dictionary.")


class ScanResponse(BaseModel):
    scan_id: str
    findings: List[Finding]
    redacted_text: str
    counts: FindingCounts
    detector_metadata: Dict[str, Any]
    processing_duration_ms: float
    context: Optional[Dict[str, Any]] = None
    risk_score: Optional[int] = None
    risk_band: Optional[str] = None
    policy_decision: Optional[str] = None
    triggered_policies: Optional[List[Dict[str, Any]]] = None
    decision_reasons: Optional[List[str]] = None
    audit_event_id: Optional[str] = None
    audit_event_hash: Optional[str] = None
    ai_analysis: Optional[Any] = None

