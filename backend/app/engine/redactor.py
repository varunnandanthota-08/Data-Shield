from typing import Dict, List, Tuple
from app.engine.base import RawFindingCandidate
from app.engine.schemas import FindingCategory, SeverityLevel

SEVERITY_WEIGHTS: Dict[SeverityLevel, int] = {
    SeverityLevel.CRITICAL: 5,
    SeverityLevel.HIGH: 4,
    SeverityLevel.MEDIUM: 3,
    SeverityLevel.LOW: 2,
    SeverityLevel.INFORMATIONAL: 1,
}

CATEGORY_PLACEHOLDERS: Dict[FindingCategory, str] = {
    FindingCategory.PII: "[REDACTED_PII]",
    FindingCategory.PAYMENT_CARD: "[REDACTED_CARD]",
    FindingCategory.SECRET: "[REDACTED_API_KEY]",
    FindingCategory.CREDENTIAL: "[REDACTED_CREDENTIAL]",
    FindingCategory.HIGH_ENTROPY_TOKEN: "[REDACTED_HIGH_ENTROPY_TOKEN]",
}

RULE_SPECIFIC_PLACEHOLDERS: Dict[str, str] = {
    "pii_email_address": "[REDACTED_EMAIL]",
    "pii_phone_number": "[REDACTED_PHONE]",
    "pii_us_ssn": "[REDACTED_SSN]",
    "pii_uk_nin": "[REDACTED_NIN]",
    "payment_card_luhn_valid": "[REDACTED_CARD]",
    "secret_aws_access_key": "[REDACTED_AWS_KEY]",
    "secret_aws_secret_key": "[REDACTED_AWS_SECRET]",
    "secret_github_token": "[REDACTED_GITHUB_TOKEN]",
    "secret_openai_api_key": "[REDACTED_OPENAI_KEY]",
    "secret_google_api_key": "[REDACTED_GOOGLE_KEY]",
    "secret_slack_token": "[REDACTED_SLACK_TOKEN]",
    "secret_jwt_token": "[REDACTED_JWT]",
    "secret_private_key_block": "[REDACTED_PRIVATE_KEY]",
    "credential_hardcoded_assignment": "[REDACTED_CREDENTIAL]",
    "entropy_high_token": "[REDACTED_TOKEN]",
}


def generate_masked_evidence(candidate: RawFindingCandidate) -> str:
    """Creates a non-reversible, safe masked snippet for reporting.
    Never exposes raw secrets or sensitive personal info.
    """
    raw = candidate.raw_match
    rule_id = candidate.rule_id

    if rule_id == "pii_email_address" and "@" in raw:
        local, domain = raw.split("@", 1)
        if len(local) <= 2:
            return f"{local[0]}***@{domain}"
        return f"{local[0]}***{local[-1]}@{domain}"

    if rule_id == "pii_us_ssn":
        parts = raw.split("-")
        last4 = parts[-1] if len(parts) == 3 else raw[-4:]
        return f"***-**-{last4}"

    if rule_id == "pii_phone_number":
        digits = [c for c in raw if c.isdigit()]
        last4 = "".join(digits[-4:]) if len(digits) >= 4 else "****"
        return f"***-***-{last4}"

    if rule_id == "payment_card_luhn_valid":
        digits = [c for c in raw if c.isdigit()]
        first4 = "".join(digits[:4])
        last4 = "".join(digits[-4:])
        return f"{first4}-****-****-{last4}"

    if rule_id == "secret_private_key_block":
        return "-----BEGIN PRIVATE KEY-----\n[PROTECTED_KEY_BODY]\n-----END PRIVATE KEY-----"

    if candidate.category in (FindingCategory.SECRET, FindingCategory.CREDENTIAL, FindingCategory.HIGH_ENTROPY_TOKEN):
        if len(raw) <= 8:
            return "********"
        prefix = raw[:3]
        suffix = raw[-2:]
        return f"{prefix}****...****{suffix}"

    # Default fallback mask
    if len(raw) <= 4:
        return "****"
    return f"{raw[0]}***{raw[-1]}"


def resolve_overlapping_candidates(candidates: List[RawFindingCandidate]) -> List[RawFindingCandidate]:
    """Resolves overlapping candidate spans deterministically.
    Conflict Resolution Strategy:
      1. Higher severity wins.
      2. If equal severity, higher confidence wins.
      3. If equal confidence, longer span wins.
    """
    if not candidates:
        return []

    # Sort primarily by start offset, then secondary tiebreakers
    sorted_candidates = sorted(
        candidates,
        key=lambda c: (
            c.start_offset,
            -SEVERITY_WEIGHTS.get(c.severity, 1),
            -c.confidence,
            -(c.end_offset - c.start_offset),
        ),
    )

    resolved: List[RawFindingCandidate] = []
    current_end = -1

    for cand in sorted_candidates:
        if cand.start_offset >= current_end:
            # Non-overlapping candidate, accept it
            resolved.append(cand)
            current_end = cand.end_offset
        else:
            # Overlap detected! Compare with the last accepted candidate
            last = resolved[-1]
            last_weight = SEVERITY_WEIGHTS.get(last.severity, 1)
            cand_weight = SEVERITY_WEIGHTS.get(cand.severity, 1)

            # Check if current candidate should replace previous candidate
            if (cand_weight > last_weight) or (
                cand_weight == last_weight and cand.confidence > last.confidence
            ) or (
                cand_weight == last_weight
                and cand.confidence == last.confidence
                and (cand.end_offset - cand.start_offset) > (last.end_offset - last.start_offset)
            ):
                resolved[-1] = cand
                current_end = cand.end_offset

    # Ensure strictly sorted by start offset
    return sorted(resolved, key=lambda c: c.start_offset)


class PositionAwareRedactor:
    """Non-destructive, position-aware redactor that reconstructs text using original offsets."""

    @staticmethod
    def redact(
        original_text: str,
        candidates: List[RawFindingCandidate],
        redaction_mode: str = "placeholder",
    ) -> Tuple[str, List[RawFindingCandidate]]:
        """Applies position-aware redaction without cascading offset corruption."""
        if not candidates or not original_text:
            return original_text, candidates

        resolved = resolve_overlapping_candidates(candidates)

        chunks: List[str] = []
        last_index = 0
        synthetic_counters: Dict[str, int] = {}

        for cand in resolved:
            # Append intact text preceding this finding
            chunks.append(original_text[last_index : cand.start_offset])

            # Determine replacement token
            if redaction_mode == "synthetic":
                cat_key = cand.category.value
                synthetic_counters[cat_key] = synthetic_counters.get(cat_key, 0) + 1
                token_placeholder = f"[{cat_key}_TOKEN_{synthetic_counters[cat_key]:02d}]"
            else:
                token_placeholder = RULE_SPECIFIC_PLACEHOLDERS.get(
                    cand.rule_id,
                    CATEGORY_PLACEHOLDERS.get(cand.category, "[REDACTED]"),
                )

            chunks.append(token_placeholder)
            last_index = cand.end_offset

        # Append remaining trailing text
        chunks.append(original_text[last_index:])

        redacted_text = "".join(chunks)
        return redacted_text, resolved
