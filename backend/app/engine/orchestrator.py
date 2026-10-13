import hashlib
import time
from typing import Dict, List, Optional
from app.engine.base import BaseDetector, RawFindingCandidate
from app.engine.entropy import HighEntropyDetector
from app.engine.payment_cards import PaymentCardDetector
from app.engine.pii import PIIDetector
from app.engine.redactor import PositionAwareRedactor, generate_masked_evidence
from app.engine.schemas import Finding, FindingCounts, ScanOptions, ScanResponse
from app.engine.secrets import SecretDetector


class DetectionOrchestrator:
    """Orchestrates multi-category sensitive data detection and non-destructive redaction."""

    def __init__(self, detectors: Optional[List[BaseDetector]] = None):
        self._detectors: List[BaseDetector] = detectors or [
            PIIDetector(),
            PaymentCardDetector(),
            SecretDetector(),
            HighEntropyDetector(),
        ]

    def register_detector(self, detector: BaseDetector) -> None:
        """Extensibility hook to add new custom detectors."""
        self._detectors.append(detector)

    def scan_and_redact(self, text: str, options: Optional[ScanOptions] = None) -> ScanResponse:
        start_time = time.perf_counter()
        opts = options or ScanOptions()

        # Generate unique scan ID based on timestamp and content digest
        timestamp_ms = int(time.time() * 1000)
        content_hash = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:10]
        scan_id = f"scan_{timestamp_ms}_{content_hash}"

        raw_candidates: List[RawFindingCandidate] = []

        # Run registered detectors
        for detector in self._detectors:
            try:
                candidates = detector.detect(text, opts)
                raw_candidates.extend(candidates)
            except Exception:
                # Detector failures do not crash the engine; continue with other detectors
                continue

        # Position-aware non-destructive redaction and overlap resolution
        redacted_text, resolved_candidates = PositionAwareRedactor.redact(
            text, raw_candidates, redaction_mode=opts.redaction_mode
        )

        # Convert resolved candidates into sanitized public findings (Zero raw secrets exported)
        sanitized_findings: List[Finding] = []
        for cand in resolved_candidates:
            masked = generate_masked_evidence(cand)
            sanitized_findings.append(cand.to_sanitized_finding(scan_id, masked))

        # Compute summary metrics
        counts_by_category: Dict[str, int] = {}
        counts_by_severity: Dict[str, int] = {}

        for finding in sanitized_findings:
            cat_name = finding.category.value
            sev_name = finding.severity.value
            counts_by_category[cat_name] = counts_by_category.get(cat_name, 0) + 1
            counts_by_severity[sev_name] = counts_by_severity.get(sev_name, 0) + 1

        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

        return ScanResponse(
            scan_id=scan_id,
            findings=sanitized_findings,
            redacted_text=redacted_text,
            counts=FindingCounts(
                by_category=counts_by_category,
                by_severity=counts_by_severity,
                total=len(sanitized_findings),
            ),
            detector_metadata={
                "detectors_evaluated": [d.name for d in self._detectors],
                "redaction_mode": opts.redaction_mode,
                "input_char_count": len(text),
            },
            processing_duration_ms=duration_ms,
        )


# Global default engine instance
engine = DetectionOrchestrator()
