import math
import re
from typing import List
from collections import Counter
from app.engine.base import BaseDetector, RawFindingCandidate
from app.engine.schemas import FindingCategory, ScanOptions, SeverityLevel


def calculate_shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy (in bits per character) of a string."""
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)
    entropy = 0.0

    for count in counts.values():
        p_x = count / length
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)

    return entropy


class HighEntropyDetector(BaseDetector):
    """Detector for generic high-entropy strings, API tokens, and cryptographic secrets."""

    # Candidate token regex: continuous sequence of letters, digits, and safe base64/hex symbols
    TOKEN_PATTERN = re.compile(r"\b[A-Za-z0-9+/=_-]{16,128}\b")

    @property
    def name(self) -> str:
        return "high_entropy_detector"

    def detect(self, text: str, options: ScanOptions) -> List[RawFindingCandidate]:
        if not options.enable_entropy:
            return []

        findings: List[RawFindingCandidate] = []
        min_len = options.min_entropy_len
        threshold = options.entropy_threshold

        for match in self.TOKEN_PATTERN.finditer(text):
            token = match.group(0)

            if len(token) < min_len:
                continue

            # Skip common URLs or MIME types
            if token.startswith(("http", "https", "application", "multipart")):
                continue

            entropy = calculate_shannon_entropy(token)

            # High entropy threshold check
            if entropy >= threshold:
                # Discard strings that are just sequential or repeated characters
                unique_char_ratio = len(set(token)) / len(token)
                if unique_char_ratio < 0.35:
                    continue

                findings.append(
                    RawFindingCandidate(
                        category=FindingCategory.HIGH_ENTROPY_TOKEN,
                        detector_name=self.name,
                        rule_id="entropy_high_token",
                        severity=SeverityLevel.MEDIUM,
                        confidence=0.78,
                        start_offset=match.start(),
                        end_offset=match.end(),
                        raw_match=token,
                        suggested_remediation="High-entropy token detected; verify if this is an API key, seed, or encrypted blob.",
                        validation_metadata={
                            "entropy": round(entropy, 3),
                            "length": len(token),
                            "unique_chars": len(set(token)),
                        },
                    )
                )

        return findings
