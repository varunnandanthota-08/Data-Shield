import re
from typing import List, Optional, Tuple
from app.engine.base import BaseDetector, RawFindingCandidate
from app.engine.schemas import FindingCategory, ScanOptions, SeverityLevel


def luhn_checksum_valid(number_str: str) -> bool:
    """Validates candidate string against the Luhn modulo 10 checksum algorithm."""
    digits = [int(c) for c in number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False

    checksum = 0
    reverse_digits = digits[::-1]
    for idx, d in enumerate(reverse_digits):
        if idx % 2 == 1:
            doubled = d * 2
            checksum += doubled if doubled < 10 else (doubled - 9)
        else:
            checksum += d
    return checksum % 10 == 0


def identify_card_brand(digits: str) -> str:
    """Identifies plausible card brand based on ISO/IEC 7812 Issuer Identification Numbers."""
    if digits.startswith("4"):
        return "Visa"
    if digits.startswith(("34", "37")):
        return "American Express"
    if 51 <= int(digits[:2]) <= 55 or (len(digits) >= 4 and 2221 <= int(digits[:4]) <= 2720):
        return "Mastercard"
    if digits.startswith("6011") or digits.startswith("65") or (len(digits) >= 3 and 644 <= int(digits[:3]) <= 649):
        return "Discover"
    if digits.startswith(("300", "301", "302", "303", "304", "305", "36", "38")):
        return "Diners Club"
    if digits.startswith(("2131", "1800", "35")):
        return "JCB"
    return "Unknown Brand"


class PaymentCardDetector(BaseDetector):
    """Detector for payment cards with Luhn checksum validation and IIN brand detection."""

    # Matches formatted or contiguous 13 to 19 digit candidates
    # Examples: 4111-2222-3333-4444, 4111 2222 3333 4444, 4111222233334444
    CARD_CANDIDATE_PATTERN = re.compile(
        r"\b(?:\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{1,4}|\d{4}[-\s]?\d{6}[-\s]?\d{5}|\d{13,19})\b"
    )

    @property
    def name(self) -> str:
        return "payment_card_detector"

    def detect(self, text: str, options: ScanOptions) -> List[RawFindingCandidate]:
        findings: List[RawFindingCandidate] = []

        for match in self.CARD_CANDIDATE_PATTERN.finditer(text):
            raw = match.group(0)
            digits = re.sub(r"\D", "", raw)

            if len(digits) < 13 or len(digits) > 19:
                continue

            # Check if all digits are the same (e.g. 0000000000000000 or 1111111111111111) to avoid obvious bogus repetitions
            if len(set(digits)) == 1:
                continue

            # Run Luhn algorithm validation
            is_luhn_valid = luhn_checksum_valid(digits)

            if is_luhn_valid:
                brand = identify_card_brand(digits)
                findings.append(
                    RawFindingCandidate(
                        category=FindingCategory.PAYMENT_CARD,
                        detector_name=self.name,
                        rule_id="payment_card_luhn_valid",
                        severity=SeverityLevel.CRITICAL,
                        confidence=0.96,
                        start_offset=match.start(),
                        end_offset=match.end(),
                        raw_match=raw,
                        suggested_remediation="PCI-DSS compliance: Mask primary account number (PAN) with [REDACTED_CARD].",
                        validation_metadata={
                            "luhn_valid": True,
                            "card_brand": brand,
                            "digit_length": len(digits),
                        },
                    )
                )

        return findings
