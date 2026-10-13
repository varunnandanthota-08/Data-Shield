import re
from typing import List
from app.engine.base import BaseDetector, RawFindingCandidate
from app.engine.schemas import FindingCategory, ScanOptions, SeverityLevel


class PIIDetector(BaseDetector):
    """Detector for personally identifiable information (Email, Phone, US SSN, UK NIN)."""

    # Email pattern (RFC 5322 pragmatic candidate)
    EMAIL_PATTERN = re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    )

    # Phone numbers: North American Numbering Plan and international formats
    # matches (123) 456-7890, 123-456-7890, +1 123 456 7890, +44 20 7946 0919
    PHONE_PATTERN = re.compile(
        r"\b(?:(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})\b"
    )

    # US Social Security Number (validates structure & rejects invalid area/group/serial codes)
    SSN_PATTERN = re.compile(
        r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"
    )

    # UK National Insurance Number
    UK_NIN_PATTERN = re.compile(
        r"\b[A-CEGHJ-PR-TW-Z]{2}\s?[0-9]{6}\s?[A-D]\b",
        re.IGNORECASE
    )

    @property
    def name(self) -> str:
        return "pii_detector"

    def detect(self, text: str, options: ScanOptions) -> List[RawFindingCandidate]:
        findings: List[RawFindingCandidate] = []

        # 1. Emails
        for match in self.EMAIL_PATTERN.finditer(text):
            raw = match.group(0)
            findings.append(
                RawFindingCandidate(
                    category=FindingCategory.PII,
                    detector_name=self.name,
                    rule_id="pii_email_address",
                    severity=SeverityLevel.MEDIUM,
                    confidence=0.95,
                    start_offset=match.start(),
                    end_offset=match.end(),
                    raw_match=raw,
                    suggested_remediation="Tokenize or mask email before forwarding to external LLM prompts.",
                    validation_metadata={"type": "email"},
                )
            )

        # 2. US SSN
        for match in self.SSN_PATTERN.finditer(text):
            raw = match.group(0)
            findings.append(
                RawFindingCandidate(
                    category=FindingCategory.PII,
                    detector_name=self.name,
                    rule_id="pii_us_ssn",
                    severity=SeverityLevel.CRITICAL,
                    confidence=0.98,
                    start_offset=match.start(),
                    end_offset=match.end(),
                    raw_match=raw,
                    suggested_remediation="Remove or replace government identifiers with synthetic test IDs.",
                    validation_metadata={"type": "ssn_us"},
                )
            )

        # 3. UK National Insurance Number
        for match in self.UK_NIN_PATTERN.finditer(text):
            raw = match.group(0)
            findings.append(
                RawFindingCandidate(
                    category=FindingCategory.PII,
                    detector_name=self.name,
                    rule_id="pii_uk_nin",
                    severity=SeverityLevel.HIGH,
                    confidence=0.92,
                    start_offset=match.start(),
                    end_offset=match.end(),
                    raw_match=raw,
                    suggested_remediation="Mask national insurance identifiers in compliance with GDPR.",
                    validation_metadata={"type": "uk_nin"},
                )
            )

        # 4. Phone Numbers (filtered to avoid matching simple dates or year ranges)
        for match in self.PHONE_PATTERN.finditer(text):
            raw = match.group(0)
            # Basic validation: must contain at least 10 digits
            digits_only = re.sub(r"\D", "", raw)
            if 10 <= len(digits_only) <= 15:
                # Avoid overlapping with already found SSN matches
                if not any(f.rule_id == "pii_us_ssn" and f.start_offset <= match.start() and match.end() <= f.end_offset for f in findings):
                    findings.append(
                        RawFindingCandidate(
                            category=FindingCategory.PII,
                            detector_name=self.name,
                            rule_id="pii_phone_number",
                            severity=SeverityLevel.LOW,
                            confidence=0.85,
                            start_offset=match.start(),
                            end_offset=match.end(),
                            raw_match=raw,
                            suggested_remediation="Mask phone number with [REDACTED_PHONE] to protect consumer privacy.",
                            validation_metadata={"digits_count": len(digits_only)},
                        )
                    )

        return findings
