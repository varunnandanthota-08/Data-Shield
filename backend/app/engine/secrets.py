import re
from typing import List
from app.engine.base import BaseDetector, RawFindingCandidate
from app.engine.schemas import FindingCategory, ScanOptions, SeverityLevel


class SecretDetector(BaseDetector):
    """Detector for cloud credentials, API tokens, JWTs, private keys, and hardcoded secrets."""

    # 1. AWS Access Key ID
    AWS_KEY_PATTERN = re.compile(r"\bAKIA[0-9A-Z]{16}\b")

    # 2. AWS Secret Access Key assignment
    AWS_SECRET_PATTERN = re.compile(
        r"(?i)(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?"
    )

    # 3. GitHub Tokens (Personal Access, OAuth, Fine-grained)
    GITHUB_TOKEN_PATTERN = re.compile(
        r"\b(?:ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{60,100})\b"
    )

    # 4. OpenAI API Keys (legacy sk-... and project-scoped sk-proj-...)
    OPENAI_KEY_PATTERN = re.compile(
        r"\bsk-(?:proj-|admin-)?[a-zA-Z0-9_-]{32,100}\b"
    )

    # 5. Google / Gemini API Keys
    GOOGLE_KEY_PATTERN = re.compile(
        r"\bAIza[0-9A-Za-z-_]{35}\b"
    )

    # 6. Slack API Tokens
    SLACK_TOKEN_PATTERN = re.compile(
        r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}\b"
    )

    # 7. JWT Tokens (Three base64url segments separated by dots, starting with eyJ)
    JWT_PATTERN = re.compile(
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
    )

    # 8. Asymmetric Private Key Headers
    PRIVATE_KEY_PATTERN = re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    )

    # 9. Generic hardcoded passwords/secrets in config/code assignments
    HARDCODED_SECRET_PATTERN = re.compile(
        r"(?i)\b(?:password|passwd|pwd|client_secret|db_password)\s*[:=]\s*[\"']([^\"'\r\n\s]{8,64})[\"']"
    )

    @property
    def name(self) -> str:
        return "secret_detector"

    def detect(self, text: str, options: ScanOptions) -> List[RawFindingCandidate]:
        findings: List[RawFindingCandidate] = []

        # 1. AWS Access Key ID
        for match in self.AWS_KEY_PATTERN.finditer(text):
            raw = match.group(0)
            findings.append(
                RawFindingCandidate(
                    category=FindingCategory.SECRET,
                    detector_name=self.name,
                    rule_id="secret_aws_access_key",
                    severity=SeverityLevel.CRITICAL,
                    confidence=0.99,
                    start_offset=match.start(),
                    end_offset=match.end(),
                    raw_match=raw,
                    suggested_remediation="Revoke the exposed AWS Access Key ID in IAM console immediately.",
                    validation_metadata={"vendor": "AWS", "type": "access_key_id"},
                )
            )

        # 2. AWS Secret Access Key
        for match in self.AWS_SECRET_PATTERN.finditer(text):
            # Capture group 1 is the actual secret key
            secret_val = match.group(1)
            # Find offset of the secret value inside the match
            val_start = match.start(1)
            val_end = match.end(1)
            findings.append(
                RawFindingCandidate(
                    category=FindingCategory.SECRET,
                    detector_name=self.name,
                    rule_id="secret_aws_secret_key",
                    severity=SeverityLevel.CRITICAL,
                    confidence=0.95,
                    start_offset=val_start,
                    end_offset=val_end,
                    raw_match=secret_val,
                    suggested_remediation="Rotate AWS Secret Access Key; use IAM Instance Profiles or STS temporary credentials.",
                    validation_metadata={"vendor": "AWS", "type": "secret_access_key"},
                )
            )

        # 3. GitHub Tokens
        for match in self.GITHUB_TOKEN_PATTERN.finditer(text):
            raw = match.group(0)
            findings.append(
                RawFindingCandidate(
                    category=FindingCategory.SECRET,
                    detector_name=self.name,
                    rule_id="secret_github_token",
                    severity=SeverityLevel.CRITICAL,
                    confidence=0.99,
                    start_offset=match.start(),
                    end_offset=match.end(),
                    raw_match=raw,
                    suggested_remediation="Revoke exposed GitHub token in developer settings; use fine-grained GitHub Apps.",
                    validation_metadata={"vendor": "GitHub"},
                )
            )

        # 4. OpenAI API Keys
        for match in self.OPENAI_KEY_PATTERN.finditer(text):
            raw = match.group(0)
            findings.append(
                RawFindingCandidate(
                    category=FindingCategory.SECRET,
                    detector_name=self.name,
                    rule_id="secret_openai_api_key",
                    severity=SeverityLevel.CRITICAL,
                    confidence=0.97,
                    start_offset=match.start(),
                    end_offset=match.end(),
                    raw_match=raw,
                    suggested_remediation="Rotate compromised OpenAI key; configure enterprise spending limits and scoped project keys.",
                    validation_metadata={"vendor": "OpenAI"},
                )
            )

        # 5. Google / Gemini API Keys
        for match in self.GOOGLE_KEY_PATTERN.finditer(text):
            raw = match.group(0)
            findings.append(
                RawFindingCandidate(
                    category=FindingCategory.SECRET,
                    detector_name=self.name,
                    rule_id="secret_google_api_key",
                    severity=SeverityLevel.CRITICAL,
                    confidence=0.95,
                    start_offset=match.start(),
                    end_offset=match.end(),
                    raw_match=raw,
                    suggested_remediation="Rotate Google Cloud API key; enforce HTTP referrer or IP restrictions in Google Cloud Console.",
                    validation_metadata={"vendor": "Google"},
                )
            )

        # 6. Slack Tokens
        for match in self.SLACK_TOKEN_PATTERN.finditer(text):
            raw = match.group(0)
            findings.append(
                RawFindingCandidate(
                    category=FindingCategory.SECRET,
                    detector_name=self.name,
                    rule_id="secret_slack_token",
                    severity=SeverityLevel.CRITICAL,
                    confidence=0.98,
                    start_offset=match.start(),
                    end_offset=match.end(),
                    raw_match=raw,
                    suggested_remediation="Revoke Slack bot/user token in the Slack App Directory.",
                    validation_metadata={"vendor": "Slack"},
                )
            )

        # 7. JWT Tokens
        for match in self.JWT_PATTERN.finditer(text):
            raw = match.group(0)
            findings.append(
                RawFindingCandidate(
                    category=FindingCategory.SECRET,
                    detector_name=self.name,
                    rule_id="secret_jwt_token",
                    severity=SeverityLevel.HIGH,
                    confidence=0.90,
                    start_offset=match.start(),
                    end_offset=match.end(),
                    raw_match=raw,
                    suggested_remediation="Do not pass live session or bearer JWTs into LLM prompt context.",
                    validation_metadata={"type": "jwt"},
                )
            )

        # 8. Private Keys
        for match in self.PRIVATE_KEY_PATTERN.finditer(text):
            raw = match.group(0)
            findings.append(
                RawFindingCandidate(
                    category=FindingCategory.SECRET,
                    detector_name=self.name,
                    rule_id="secret_private_key_block",
                    severity=SeverityLevel.CRITICAL,
                    confidence=0.99,
                    start_offset=match.start(),
                    end_offset=match.end(),
                    raw_match=raw,
                    suggested_remediation="CRITICAL: Private cryptographic key leaked! Revoke keypair and inspect certificates immediately.",
                    validation_metadata={"type": "asymmetric_private_key"},
                )
            )

        # 9. Hardcoded Passwords / Assigned Credentials
        for match in self.HARDCODED_SECRET_PATTERN.finditer(text):
            secret_val = match.group(1)
            # Skip placeholders like "********" or "your_password_here" or "none"
            lower_val = secret_val.lower()
            if any(placeholder in lower_val for placeholder in ["dummy", "fake", "example", "replace", "your_", "todo"]):
                continue

            val_start = match.start(1)
            val_end = match.end(1)
            findings.append(
                RawFindingCandidate(
                    category=FindingCategory.CREDENTIAL,
                    detector_name=self.name,
                    rule_id="credential_hardcoded_assignment",
                    severity=SeverityLevel.HIGH,
                    confidence=0.86,
                    start_offset=val_start,
                    end_offset=val_end,
                    raw_match=secret_val,
                    suggested_remediation="Externalize hardcoded credentials to a secret manager (HashiCorp Vault, AWS Secrets Manager).",
                    validation_metadata={"type": "hardcoded_credential"},
                )
            )

        return findings
