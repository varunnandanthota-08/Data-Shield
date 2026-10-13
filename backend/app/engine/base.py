from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import hashlib
from typing import Any, Dict, List
from app.engine.schemas import ConfidenceBand, Finding, FindingCategory, ScanOptions, SeverityLevel


@dataclass
class RawFindingCandidate:
    """Internal candidate during engine execution.
    Holds raw_match solely for position-aware redaction.
    NEVER serialized or exported into external API responses.
    """
    category: FindingCategory
    detector_name: str
    rule_id: str
    severity: SeverityLevel
    confidence: float
    start_offset: int
    end_offset: int
    raw_match: str
    suggested_remediation: str
    validation_metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def confidence_band(self) -> ConfidenceBand:
        if self.confidence >= 0.90:
            return ConfidenceBand.VERY_HIGH
        if self.confidence >= 0.80:
            return ConfidenceBand.HIGH
        if self.confidence >= 0.60:
            return ConfidenceBand.MEDIUM
        return ConfidenceBand.LOW

    def generate_id(self, scan_id: str) -> str:
        unique_seed = f"{scan_id}:{self.rule_id}:{self.start_offset}:{self.end_offset}"
        hash_digest = hashlib.sha256(unique_seed.encode("utf-8")).hexdigest()[:12]
        return f"find_{hash_digest}"

    def to_sanitized_finding(self, scan_id: str, masked_evidence: str) -> Finding:
        return Finding(
            id=self.generate_id(scan_id),
            category=self.category,
            detector_name=self.detector_name,
            rule_id=self.rule_id,
            severity=self.severity,
            confidence=self.confidence,
            confidence_band=self.confidence_band,
            start_offset=self.start_offset,
            end_offset=self.end_offset,
            masked_evidence=masked_evidence,
            suggested_remediation=self.suggested_remediation,
            validation_metadata=self.validation_metadata,
        )


class BaseDetector(ABC):
    """Abstract Base Class for all DataShield detection plugins."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the detector."""
        pass

    @abstractmethod
    def detect(self, text: str, options: ScanOptions) -> List[RawFindingCandidate]:
        """Scans the provided text and returns candidate findings with character offsets."""
        pass
