import json
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.engine.orchestrator import engine
from app.engine.schemas import FindingCategory, ScanOptions, SeverityLevel
from app.engine.payment_cards import luhn_checksum_valid
from app.engine.entropy import calculate_shannon_entropy

client = TestClient(app)

# --- Synthetic Fixtures (Standard Test Numbers & Non-Secret Dummies) ---
SYNTHETIC_EMAIL = "alex.murphy.sec@example.corp"
SYNTHETIC_PHONE = "+1 (555) 839-2001"
SYNTHETIC_SSN = "123-45-6789"
SYNTHETIC_INVALID_SSN = "000-12-3456"  # Area 000 is invalid in US SSN
SYNTHETIC_VISA = "4111-1111-1111-1111"  # Standard Luhn valid synthetic test card
SYNTHETIC_INVALID_CARD = "4111-1111-1111-1112"  # Fails Luhn checksum modulo 10
SYNTHETIC_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # Standard AWS documentation fixture
SYNTHETIC_GITHUB_TOKEN = "ghp_111122223333444455556666777788889999"
SYNTHETIC_OPENAI_KEY = "sk-proj-abc1234567890abcdef1234567890abcdef12345678"
SYNTHETIC_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
SYNTHETIC_PRIVATE_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEA0Y1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL\n"
    "-----END RSA PRIVATE KEY-----"
)


class TestLuhnAlgorithm:
    def test_valid_luhn_card(self):
        assert luhn_checksum_valid(SYNTHETIC_VISA) is True

    def test_invalid_luhn_card(self):
        assert luhn_checksum_valid(SYNTHETIC_INVALID_CARD) is False

    def test_length_boundaries(self):
        assert luhn_checksum_valid("12345") is False
        assert luhn_checksum_valid("123456789012345678901") is False


class TestShannonEntropy:
    def test_high_entropy_random_string(self):
        # Base64-like random bytes have entropy ~ 5.0+
        random_str = "k8J2x9PqL0vZ4mN7wY1rT3bS6fH5cV8g"
        entropy = calculate_shannon_entropy(random_str)
        assert entropy > 4.2

    def test_low_entropy_repeating_string(self):
        repeating_str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        entropy = calculate_shannon_entropy(repeating_str)
        assert entropy == 0.0

    def test_low_entropy_english_sentence(self):
        sentence = "This is a typical enterprise log message for system health check."
        entropy = calculate_shannon_entropy(sentence)
        assert entropy < 4.2


class TestCoreDetectors:
    def test_detect_pii_email_and_phone(self):
        text = f"Contact developer at {SYNTHETIC_EMAIL} or phone {SYNTHETIC_PHONE}."
        res = engine.scan_and_redact(text)

        rule_ids = [f.rule_id for f in res.findings]
        assert "pii_email_address" in rule_ids
        assert "pii_phone_number" in rule_ids
        assert "[REDACTED_EMAIL]" in res.redacted_text
        assert "[REDACTED_PHONE]" in res.redacted_text
        assert SYNTHETIC_EMAIL not in res.redacted_text

    def test_detect_ssn_and_reject_malformed(self):
        valid_text = f"User SSN is {SYNTHETIC_SSN}."
        invalid_text = f"Bogus number is {SYNTHETIC_INVALID_SSN}."

        res_valid = engine.scan_and_redact(valid_text)
        assert any(f.rule_id == "pii_us_ssn" for f in res_valid.findings)
        assert "[REDACTED_SSN]" in res_valid.redacted_text

        res_invalid = engine.scan_and_redact(invalid_text)
        assert not any(f.rule_id == "pii_us_ssn" for f in res_invalid.findings)

    def test_detect_payment_card_luhn_enforcement(self):
        valid_payload = f"Card charged: {SYNTHETIC_VISA}"
        invalid_payload = f"Invalid card: {SYNTHETIC_INVALID_CARD}"

        res_valid = engine.scan_and_redact(valid_payload)
        assert any(f.rule_id == "payment_card_luhn_valid" for f in res_valid.findings)
        assert "[REDACTED_CARD]" in res_valid.redacted_text
        assert SYNTHETIC_VISA not in res_valid.redacted_text

        res_invalid = engine.scan_and_redact(invalid_payload)
        assert not any(f.rule_id == "payment_card_luhn_valid" for f in res_invalid.findings)

    def test_detect_secrets_and_credentials(self):
        text = (
            f"export AWS_ACCESS_KEY_ID={SYNTHETIC_AWS_KEY}\n"
            f"export GITHUB_TOKEN={SYNTHETIC_GITHUB_TOKEN}\n"
            f"export OPENAI_KEY={SYNTHETIC_OPENAI_KEY}\n"
            f"auth_token: \"{SYNTHETIC_JWT}\"\n"
            f"db_password = 'MySecretProductionPassword987!'\n"
        )
        res = engine.scan_and_redact(text)

        rule_ids = {f.rule_id for f in res.findings}
        assert "secret_aws_access_key" in rule_ids
        assert "secret_github_token" in rule_ids
        assert "secret_openai_api_key" in rule_ids
        assert "secret_jwt_token" in rule_ids
        assert "credential_hardcoded_assignment" in rule_ids

        # Ensure raw secret values are replaced in redacted output
        assert SYNTHETIC_AWS_KEY not in res.redacted_text
        assert SYNTHETIC_GITHUB_TOKEN not in res.redacted_text
        assert SYNTHETIC_OPENAI_KEY not in res.redacted_text
        assert "MySecretProductionPassword987!" not in res.redacted_text

    def test_detect_private_key_header(self):
        text = f"Server certificate private key:\n{SYNTHETIC_PRIVATE_KEY}\nEnd."
        res = engine.scan_and_redact(text)
        assert any(f.rule_id == "secret_private_key_block" for f in res.findings)
        assert "[REDACTED_PRIVATE_KEY]" in res.redacted_text
        assert "MIIEowIBAAKCAQEA" not in res.redacted_text


class TestRedactionAndPositionAwareness:
    def test_overlapping_conflict_resolution(self):
        # A high-entropy token detector might match inside an AWS key or JWT
        text = f"Config key is {SYNTHETIC_AWS_KEY}."
        res = engine.scan_and_redact(text)

        # AWS key detector has higher severity (CRITICAL) and confidence than entropy detector
        # Overlap must resolve to 1 single non-duplicated redacted span
        assert res.redacted_text == "Config key is [REDACTED_AWS_KEY]."
        assert len(res.findings) == 1
        assert res.findings[0].rule_id == "secret_aws_access_key"

    def test_unicode_and_special_character_offsets(self):
        # Test emojis and multi-byte characters preceding sensitive data
        text = f"🔒 Security alert: 🚀 deployment key is {SYNTHETIC_AWS_KEY} in São Paulo 🇧🇷!"
        res = engine.scan_and_redact(text)

        assert "[REDACTED_AWS_KEY]" in res.redacted_text
        assert "🔒 Security alert: 🚀 deployment key is [REDACTED_AWS_KEY] in São Paulo 🇧🇷!" == res.redacted_text

    def test_repeated_identical_values(self):
        text = f"Primary email: {SYNTHETIC_EMAIL}, fallback: {SYNTHETIC_EMAIL}."
        res = engine.scan_and_redact(text)

        assert len(res.findings) == 2
        assert res.redacted_text == "Primary email: [REDACTED_EMAIL], fallback: [REDACTED_EMAIL]."

    def test_synthetic_token_redaction_mode(self):
        text = f"Email: {SYNTHETIC_EMAIL}, Card: {SYNTHETIC_VISA}"
        options = ScanOptions(redaction_mode="synthetic")
        res = engine.scan_and_redact(text, options)

        assert "[PII_TOKEN_01]" in res.redacted_text
        assert "[PAYMENT_CARD_TOKEN_01]" in res.redacted_text


class TestZeroRawSecretExposure:
    def test_raw_secret_never_exposed_in_findings(self):
        text = (
            f"Here is confidential data: {SYNTHETIC_EMAIL}, {SYNTHETIC_VISA}, "
            f"{SYNTHETIC_AWS_KEY}, {SYNTHETIC_OPENAI_KEY}"
        )
        res = engine.scan_and_redact(text)
        serialized_json = res.model_dump_json()

        # Crucial security guarantee: raw secrets must NEVER appear anywhere in finding payloads
        assert SYNTHETIC_AWS_KEY not in serialized_json
        assert SYNTHETIC_OPENAI_KEY not in serialized_json
        assert SYNTHETIC_VISA not in serialized_json
        # Email evidence is masked
        assert SYNTHETIC_EMAIL not in serialized_json

        for finding in res.findings:
            # Masked evidence should be redacted/obfuscated
            assert "*" in finding.masked_evidence


class TestScanAPIEndpoint:
    def test_scan_api_success(self):
        payload = {
            "text": f"Incident report: developer sent {SYNTHETIC_AWS_KEY} to {SYNTHETIC_EMAIL}.",
            "options": {"enable_entropy": True, "redaction_mode": "placeholder"},
        }
        response = client.post("/api/v1/scan/text", json=payload)
        assert response.status_code == 200
        data = response.json()

        assert "scan_id" in data
        assert data["counts"]["total"] == 2
        assert "[REDACTED_AWS_KEY]" in data["redacted_text"]
        assert "[REDACTED_EMAIL]" in data["redacted_text"]
        assert data["processing_duration_ms"] > 0

    def test_empty_text_returns_clean_response(self):
        response = client.post("/api/v1/scan/text", json={"text": "   "})
        assert response.status_code == 200
        data = response.json()
        assert data["counts"]["total"] == 0
        assert data["findings"] == []
        assert data["redacted_text"] == ""

    def test_payload_too_large_rejection(self):
        # Exceeds 500,000 characters
        oversized = "A" * 500_001
        response = client.post("/api/v1/scan/text", json={"text": oversized})
        # Pydantic or endpoint rejects with 422 or 413
        assert response.status_code in (413, 422)


class TestSyntheticCorpusMetrics:
    def test_precision_recall_benchmark(self):
        """Measures precision and recall across a curated synthetic ground-truth corpus."""
        corpus = [
            # (text, expected_categories)
            (f"Normal text without any secrets or sensitive data here.", []),
            (f"Please reach out to support@test.corp immediately.", [FindingCategory.PII]),
            (f"Customer card on file: {SYNTHETIC_VISA}", [FindingCategory.PAYMENT_CARD]),
            (f"AWS key deployed: {SYNTHETIC_AWS_KEY}", [FindingCategory.SECRET]),
            (f"GitHub key: {SYNTHETIC_GITHUB_TOKEN}", [FindingCategory.SECRET]),
            (f"Bogus digit string that fails Luhn: 9876543210123456", []),
            (f"Regular 6-digit order ID: 123456", []),
        ]

        true_positives = 0
        false_positives = 0
        false_negatives = 0

        for text, expected_cats in corpus:
            res = engine.scan_and_redact(text)
            detected_cats = [f.category for f in res.findings]

            if not expected_cats and not detected_cats:
                continue

            for expected in expected_cats:
                if expected in detected_cats:
                    true_positives += 1
                else:
                    false_negatives += 1

            for detected in detected_cats:
                if detected not in expected_cats:
                    false_positives += 1

        precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 1.0
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 1.0

        # Assert benchmark quality on synthetic corpus
        assert precision >= 0.90
        assert recall >= 0.90
