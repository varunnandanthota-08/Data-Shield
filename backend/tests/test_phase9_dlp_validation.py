import json
import os
import sqlite3
import time
from unittest.mock import MagicMock, patch, PropertyMock
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.audit.service import AuditService, compute_event_hash, GENESIS_HASH
from app.core.config import Settings
from app.db.connection import get_connection, get_db_path, resolve_db_path
from app.db.schema import init_db
from app.engine.orchestrator import engine, DetectionOrchestrator
from app.engine.schemas import FindingCategory, ScanOptions, SeverityLevel
from app.policy.engine import PolicyEngine, ACTION_PRECEDENCE
from app.policy.risk_scorer import CompositeRiskScorer
from app.policy.schemas import (
    DataClassification,
    DestinationType,
    PolicyAction,
    PolicyRule,
    RecipientType,
    SharingContext,
)
from app.ai.service import GeminiContextAnalysisService


# ---------------------------------------------------------------------------
# SYNTHETIC TEST CORPUS
# ---------------------------------------------------------------------------
SYNTHETIC_CORPUS = {
    # 1. PII
    "email_standard": "Contact lead engineer at alice.smith@example.com for credentials.",
    "email_subdomain": "Alert dispatch: notification sent to bob.jones@secops.corp.example.org immediately.",
    "email_numeric": "Automated ticket created by dev456@test-domain.io regarding issue.",
    "phone_us_dashed": "Call emergency SOC contact at 555-876-5432 if unresponsive.",
    "phone_us_paren": "Primary security hotline is (555) 234-5678 available 24/7.",
    "phone_intl_us": "International office line is +1 555 432 1098 during business hours.",
    "phone_intl_uk": "London security center desk: +44 123 456 7890 for incident triage.",
    "ssn_valid": "Applicant government SSN is 123-45-6789 submitted on verification form.",
    "uk_nin_spaced": "National insurance record: AB 123456 C registered with HMRC.",
    "uk_nin_nospace": "UK citizen identifier AB123456C submitted for compliance audit.",

    # 2. Cloud Credentials & API Keys
    "aws_access_key": "Deploying worker using AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE' into production.",
    "aws_secret_key": "aws_secret_access_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'",
    "github_pat": "CI token configured: ghp_1234567890abcdefghijklmnopqrstuvwxyz for repo sync.",
    "github_oauth": "User authorization token: gho_0123456789abcdefghijklmnopqrstuvwxyz received.",
    "github_fine_grained": "github_pat_11AAAAAAA01234567890abcdefghijklmnopqrstuvwxyz_0123456789012345678901234567890123456789",
    "openai_key": "Model query authorization header: Bearer sk-1234567890abcdefghijklmnopqrstuvwxyz123456",
    "openai_proj_key": "Project key: sk-proj-1234567890abcdefghijklmnopqrstuvwxyz1234567890123456",
    "google_api_key": "AIzaSyD-1234567890abcdefghijklmnop_uvwx key for Gemini cloud gateway.",
    "slack_token": "Chatbot notification hook token: xoxb-FAKE-TEST-TOKEN-NOT-VALID",
    "private_key_block": (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0syntheticKeyBodyNotRealForTestingPurposesOnly1234567890\n"
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890==\n"
        "-----END RSA PRIVATE KEY-----"
    ),

    # 3. Passwords and Tokens
    "hardcoded_password_1": "Database configuration: password = 'SuperSecretPassword123!' in local config.",
    "hardcoded_password_2": "Connecting to cluster with db_password: 'ProdDbSecret2026@' on port 5432.",
    "jwt_token": (
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    ),
    "high_entropy_token": "Session seed: wJalrXUtnFEMIK7MDENGbPxRfiCYEXMPL345 generated randomly.",

    # 4. Confidential Business Data (Payment Cards with Luhn Check)
    "card_visa_16": "Customer billing card: 4111-1111-1111-1111 on file for renewal.",
    "card_visa_dashed": "Card ending in 1881: 4012-8888-8888-1881 authorized.",
    "card_mastercard_16": "Merchant account 5555 5555 5555 4444 charged $120.00 USD.",
    "card_amex_15": "Corporate Amex card 378282246310005 exp 12/28.",
    "card_discover_16": "Payment option: 6011-1111-1111-1117 selected.",

    # 5. Clean Text & Realistic False Positives
    "clean_corporate_text": (
        "The quarterly operations review will take place on Thursday at 10:00 AM UTC. "
        "All engineering team leads should submit their slide deck before Wednesday evening. "
        "Please review the updated project roadmap in the shared internal portal."
    ),
    "clean_code_snippet": (
        "def calculate_total(items, tax_rate=0.08):\n"
        "    subtotal = sum(item.price * item.quantity for item in items)\n"
        "    return round(subtotal * (1 + tax_rate), 2)"
    ),
    "luhn_invalid_card": "Transaction reference number 4111-1111-1111-1112 rejected by processor.",
    "all_identical_digits": "Placeholder card string 0000-0000-0000-0000 is invalid.",
    "ssn_invalid_area_000": "Government reference 000-12-3456 is an invalid area code.",
    "ssn_invalid_area_666": "Application ID 666-12-3456 contains prohibited prefix.",
    "ssn_invalid_area_950": "Fictitious test entry 950-12-3456 rejected.",
    "ssn_invalid_group_00": "Malformed format 123-00-4567 rejected.",
    "innocuous_uuid": "Request trace ID: 550e8400-e29b-41d4-a716-446655440000 submitted.",
    "innocuous_commit_sha": "Merged commit 7f8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b to main branch.",

    # 6. Multiple Sensitive Values in One Payload
    "multi_finding_document": (
        "Incident Report:\n"
        "Staff member alice.smith@example.com (cell: (555) 234-5678) accidentally checked in "
        "AWS credentials AKIAIOSFODNN7EXAMPLE and customer SSN 123-45-6789 while debugging "
        "payment failure on Visa card 4111-1111-1111-1111. "
        "Database password was password = 'SuperSecretPassword123!'."
    ),

    # 7. Malformed, Encoded, and Boundary Cases
    "boundary_start": "AKIAIOSFODNN7EXAMPLE is at offset zero in this string.",
    "boundary_end": "The key is at the very end of string: AKIAIOSFODNN7EXAMPLE",
    "unicode_accented": "Employé résumé: contact élève à alice.smith@example.com avec numéro 555-876-5432.",
    "emoji_surrounded": "🔒 URGENT: Key AKIAIOSFODNN7EXAMPLE leaked in chat! 🚨 Check immediately! ⚠️",
    "whitespace_only": "   \n\t   \r\n   ",
    "empty_string": "",
}


@pytest.fixture
def isolated_phase9_db(tmp_path, monkeypatch):
    """Provides a fresh isolated SQLite database for Phase 9 testing."""
    test_db = str(tmp_path / "datashield_phase9_test.db")
    monkeypatch.setenv("SQLITE_DB_PATH", test_db)
    monkeypatch.setenv("ENVIRONMENT", "staging")
    monkeypatch.setenv("DEBUG", "false")
    init_db(db_path=test_db)
    return test_db


# ---------------------------------------------------------------------------
# SECTION 1: SYNTHETIC DETECTION TEST CORPUS
# ---------------------------------------------------------------------------
class TestPhase9DetectionCorpus:
    """Verifies that the multi-category detection engine accurately identifies all supported
    synthetic patterns and appropriately rejects false positives.
    """

    def test_pii_emails(self):
        opts = ScanOptions(enable_entropy=True)
        for key in ["email_standard", "email_subdomain", "email_numeric"]:
            res = engine.scan_and_redact(SYNTHETIC_CORPUS[key], opts)
            assert len(res.findings) >= 1, f"Failed to detect email in: {key}"
            email_findings = [f for f in res.findings if f.rule_id == "pii_email_address"]
            assert len(email_findings) == 1
            assert email_findings[0].category == FindingCategory.PII
            assert email_findings[0].severity == SeverityLevel.MEDIUM
            assert "[REDACTED_EMAIL]" in res.redacted_text

    def test_pii_phone_numbers(self):
        opts = ScanOptions(enable_entropy=True)
        for key in ["phone_us_dashed", "phone_us_paren", "phone_intl_us", "phone_intl_uk"]:
            res = engine.scan_and_redact(SYNTHETIC_CORPUS[key], opts)
            assert len(res.findings) >= 1, f"Failed to detect phone in: {key}"
            phone_findings = [f for f in res.findings if f.rule_id == "pii_phone_number"]
            assert len(phone_findings) == 1
            assert phone_findings[0].category == FindingCategory.PII
            assert "[REDACTED_PHONE]" in res.redacted_text

    def test_national_identifiers(self):
        opts = ScanOptions(enable_entropy=True)
        # US SSN
        ssn_res = engine.scan_and_redact(SYNTHETIC_CORPUS["ssn_valid"], opts)
        ssn_findings = [f for f in ssn_res.findings if f.rule_id == "pii_us_ssn"]
        assert len(ssn_findings) == 1
        assert ssn_findings[0].severity == SeverityLevel.CRITICAL
        assert "[REDACTED_SSN]" in ssn_res.redacted_text

        # UK NIN
        for key in ["uk_nin_spaced", "uk_nin_nospace"]:
            nin_res = engine.scan_and_redact(SYNTHETIC_CORPUS[key], opts)
            nin_findings = [f for f in nin_res.findings if f.rule_id == "pii_uk_nin"]
            assert len(nin_findings) == 1, f"Failed to detect UK NIN in {key}"
            assert nin_findings[0].severity == SeverityLevel.HIGH
            assert "[REDACTED_NIN]" in nin_res.redacted_text

    def test_cloud_credentials_and_api_keys(self):
        opts = ScanOptions(enable_entropy=True)

        # AWS Access Key
        res = engine.scan_and_redact(SYNTHETIC_CORPUS["aws_access_key"], opts)
        aws_findings = [f for f in res.findings if f.rule_id == "secret_aws_access_key"]
        assert len(aws_findings) == 1
        assert aws_findings[0].severity == SeverityLevel.CRITICAL
        assert "AKIAIOSFODNN7EXAMPLE" not in res.redacted_text
        assert "[REDACTED_AWS_KEY]" in res.redacted_text

        # AWS Secret Key
        res_secret = engine.scan_and_redact(SYNTHETIC_CORPUS["aws_secret_key"], opts)
        secret_findings = [f for f in res_secret.findings if f.rule_id == "secret_aws_secret_key"]
        assert len(secret_findings) == 1
        assert "[REDACTED_AWS_SECRET]" in res_secret.redacted_text

        # GitHub Tokens
        for gh_key in ["github_pat", "github_oauth", "github_fine_grained"]:
            gh_res = engine.scan_and_redact(SYNTHETIC_CORPUS[gh_key], opts)
            gh_findings = [f for f in gh_res.findings if f.rule_id == "secret_github_token"]
            assert len(gh_findings) == 1, f"Failed on {gh_key}"
            assert "[REDACTED_GITHUB_TOKEN]" in gh_res.redacted_text

        # OpenAI Keys
        for oai_key in ["openai_key", "openai_proj_key"]:
            oai_res = engine.scan_and_redact(SYNTHETIC_CORPUS[oai_key], opts)
            oai_findings = [f for f in oai_res.findings if f.rule_id == "secret_openai_api_key"]
            assert len(oai_findings) == 1, f"Failed on {oai_key}"
            assert "[REDACTED_OPENAI_KEY]" in oai_res.redacted_text

        # Google / Gemini Key
        g_res = engine.scan_and_redact(SYNTHETIC_CORPUS["google_api_key"], opts)
        g_findings = [f for f in g_res.findings if f.rule_id == "secret_google_api_key"]
        assert len(g_findings) == 1
        assert "[REDACTED_GOOGLE_KEY]" in g_res.redacted_text

        # Slack Token
        s_res = engine.scan_and_redact(SYNTHETIC_CORPUS["slack_token"], opts)
        s_findings = [f for f in s_res.findings if f.rule_id == "secret_slack_token"]
        assert len(s_findings) == 1
        assert "[REDACTED_SLACK_TOKEN]" in s_res.redacted_text

        # Private Key Block
        pk_res = engine.scan_and_redact(SYNTHETIC_CORPUS["private_key_block"], opts)
        pk_findings = [f for f in pk_res.findings if f.rule_id == "secret_private_key_block"]
        assert len(pk_findings) == 1
        assert "[REDACTED_PRIVATE_KEY]" in pk_res.redacted_text

    def test_passwords_and_tokens(self):
        opts = ScanOptions(enable_entropy=True)

        # Hardcoded Passwords
        res1 = engine.scan_and_redact(SYNTHETIC_CORPUS["hardcoded_password_1"], opts)
        pwd_findings = [f for f in res1.findings if f.rule_id == "credential_hardcoded_assignment"]
        assert len(pwd_findings) == 1
        assert "SuperSecretPassword123!" not in res1.redacted_text
        assert "[REDACTED_CREDENTIAL]" in res1.redacted_text

        res2 = engine.scan_and_redact(SYNTHETIC_CORPUS["hardcoded_password_2"], opts)
        assert any(f.rule_id == "credential_hardcoded_assignment" for f in res2.findings)

        # JWT Token
        jwt_res = engine.scan_and_redact(SYNTHETIC_CORPUS["jwt_token"], opts)
        jwt_findings = [f for f in jwt_res.findings if f.rule_id == "secret_jwt_token"]
        assert len(jwt_findings) == 1
        assert "[REDACTED_JWT]" in jwt_res.redacted_text

    def test_confidential_business_payment_cards_luhn(self):
        opts = ScanOptions(enable_entropy=True)
        for card_key in ["card_visa_16", "card_visa_dashed", "card_mastercard_16", "card_amex_15", "card_discover_16"]:
            res = engine.scan_and_redact(SYNTHETIC_CORPUS[card_key], opts)
            card_findings = [f for f in res.findings if f.rule_id == "payment_card_luhn_valid"]
            assert len(card_findings) == 1, f"Failed on card: {card_key}"
            assert card_findings[0].category == FindingCategory.PAYMENT_CARD
            assert card_findings[0].severity == SeverityLevel.CRITICAL
            assert "[REDACTED_CARD]" in res.redacted_text

    def test_clean_text_and_false_positive_rejection(self):
        opts = ScanOptions(enable_entropy=True)

        # Clean business communications must produce 0 findings
        res_clean = engine.scan_and_redact(SYNTHETIC_CORPUS["clean_corporate_text"], opts)
        assert len(res_clean.findings) == 0
        assert res_clean.redacted_text == SYNTHETIC_CORPUS["clean_corporate_text"]

        res_code = engine.scan_and_redact(SYNTHETIC_CORPUS["clean_code_snippet"], opts)
        assert len(res_code.findings) == 0

        # Luhn invalid card numbers must NOT be identified as payment cards
        res_bad_luhn = engine.scan_and_redact(SYNTHETIC_CORPUS["luhn_invalid_card"], opts)
        assert not any(f.rule_id == "payment_card_luhn_valid" for f in res_bad_luhn.findings)

        # All identical digits must NOT be identified as payment cards
        res_ident = engine.scan_and_redact(SYNTHETIC_CORPUS["all_identical_digits"], opts)
        assert not any(f.rule_id == "payment_card_luhn_valid" for f in res_ident.findings)

        # Invalid SSN structural codes must NOT be identified as SSN
        for bad_ssn_key in ["ssn_invalid_area_000", "ssn_invalid_area_666", "ssn_invalid_area_950", "ssn_invalid_group_00"]:
            res_bad_ssn = engine.scan_and_redact(SYNTHETIC_CORPUS[bad_ssn_key], opts)
            assert not any(f.rule_id == "pii_us_ssn" for f in res_bad_ssn.findings), f"False positive on {bad_ssn_key}"

        # Innocuous UUIDs and Git commit hashes
        res_uuid = engine.scan_and_redact(SYNTHETIC_CORPUS["innocuous_uuid"], opts)
        assert not any(f.rule_id in ("secret_aws_access_key", "payment_card_luhn_valid", "pii_us_ssn") for f in res_uuid.findings)

    def test_multiple_sensitive_values_in_one_payload(self):
        opts = ScanOptions(enable_entropy=True)
        res = engine.scan_and_redact(SYNTHETIC_CORPUS["multi_finding_document"], opts)

        # Must detect email, phone, AWS key, SSN, credit card, and password
        detected_rules = {f.rule_id for f in res.findings}
        assert "pii_email_address" in detected_rules
        assert "pii_phone_number" in detected_rules
        assert "secret_aws_access_key" in detected_rules
        assert "pii_us_ssn" in detected_rules
        assert "payment_card_luhn_valid" in detected_rules
        assert "credential_hardcoded_assignment" in detected_rules

        # Every sensitive item must be redacted
        assert "alice.smith@example.com" not in res.redacted_text
        assert "555" not in res.redacted_text or "[REDACTED_PHONE]" in res.redacted_text
        assert "AKIAIOSFODNN7EXAMPLE" not in res.redacted_text
        assert "123-45-6789" not in res.redacted_text
        assert "4111-1111-1111-1111" not in res.redacted_text
        assert "SuperSecretPassword123!" not in res.redacted_text

    def test_malformed_and_boundary_cases(self):
        opts = ScanOptions(enable_entropy=True)

        # Finding at index 0
        res_start = engine.scan_and_redact(SYNTHETIC_CORPUS["boundary_start"], opts)
        assert res_start.redacted_text.startswith("[REDACTED_AWS_KEY]")

        # Finding at the exact end of text
        res_end = engine.scan_and_redact(SYNTHETIC_CORPUS["boundary_end"], opts)
        assert res_end.redacted_text.endswith("[REDACTED_AWS_KEY]")

        # Unicode accented text around findings
        res_uni = engine.scan_and_redact(SYNTHETIC_CORPUS["unicode_accented"], opts)
        assert "alice.smith@example.com" not in res_uni.redacted_text
        assert "[REDACTED_EMAIL]" in res_uni.redacted_text
        assert "[REDACTED_PHONE]" in res_uni.redacted_text
        assert "Employé résumé" in res_uni.redacted_text

        # Emojis surrounding finding
        res_emoji = engine.scan_and_redact(SYNTHETIC_CORPUS["emoji_surrounded"], opts)
        assert "AKIAIOSFODNN7EXAMPLE" not in res_emoji.redacted_text
        assert "[REDACTED_AWS_KEY]" in res_emoji.redacted_text
        assert "🔒" in res_emoji.redacted_text and "🚨" in res_emoji.redacted_text

        # Whitespace and empty strings
        res_ws = engine.scan_and_redact(SYNTHETIC_CORPUS["whitespace_only"], opts)
        assert len(res_ws.findings) == 0

        res_empty = engine.scan_and_redact(SYNTHETIC_CORPUS["empty_string"], opts)
        assert len(res_empty.findings) == 0
        assert res_empty.redacted_text == ""


# ---------------------------------------------------------------------------
# SECTION 2: POLICY ENFORCEMENT & PRECEDENCE MATRIX
# ---------------------------------------------------------------------------
class TestPhase9PolicyEnforcement:
    """Verifies deterministic policy evaluations: ALLOW, WARN, REDACT, REQUIRE_APPROVAL, BLOCK,
    strict precedence hierarchy, and tenant isolation.
    """

    def test_allow_action(self):
        """Clean content to internal service evaluates to ALLOW."""
        pe = PolicyEngine()
        ctx = SharingContext(
            destination=DestinationType.INTERNAL_SERVICE,
            recipient=RecipientType.INTERNAL_EMPLOYEE,
            classification=DataClassification.INTERNAL,
        )
        res = pe.evaluate([], ctx)
        assert res.final_decision == PolicyAction.ALLOW
        assert res.hard_block_enforced is False

    def test_warn_action(self):
        """Confidential content without credentials to public destination triggers WARN."""
        pe = PolicyEngine()
        ctx = SharingContext(
            destination=DestinationType.PUBLIC_LLM,
            recipient=RecipientType.PUBLIC,
            classification=DataClassification.CONFIDENTIAL,
        )
        res = pe.evaluate([], ctx)
        assert res.final_decision == PolicyAction.WARN
        assert any(p.id == "POL-003" for p in res.triggered_policies)

    def test_redact_action(self):
        """Custom policy with REDACT action correctly assigns REDACT decision."""
        redact_policy = PolicyRule(
            id="POL-REDACT-TEST",
            version="1.0.0",
            name="Redact PII for Contractors",
            description="Forces redaction of PII before sharing with contractors",
            enabled=True,
            applicable_categories=[FindingCategory.PII],
            applicable_sensitivities=[],
            target_destinations=[],
            target_recipients=[RecipientType.THIRD_PARTY_CONTRACTOR],
            action=PolicyAction.REDACT,
            priority=50,
            intent_explanation="Ensure PII is sanitized prior to contractor egress.",
        )
        pe = PolicyEngine([redact_policy])
        ctx = SharingContext(
            destination=DestinationType.INTERNAL_SERVICE,
            recipient=RecipientType.THIRD_PARTY_CONTRACTOR,
            classification=DataClassification.INTERNAL,
        )
        # Scan synthetic email
        scan_res = engine.scan_and_redact(SYNTHETIC_CORPUS["email_standard"])
        eval_res = pe.evaluate(scan_res.findings, ctx)
        assert eval_res.final_decision == PolicyAction.REDACT
        assert any(p.id == "POL-REDACT-TEST" for p in eval_res.triggered_policies)

    def test_require_approval_action(self):
        """Restricted PII/Card data to external recipient triggers REQUIRE_APPROVAL (POL-002)."""
        pe = PolicyEngine()
        ctx = SharingContext(
            destination=DestinationType.EXTERNAL_SAAS,
            recipient=RecipientType.THIRD_PARTY_CONTRACTOR,
            classification=DataClassification.CONFIDENTIAL,
        )
        scan_res = engine.scan_and_redact(SYNTHETIC_CORPUS["card_visa_16"])
        eval_res = pe.evaluate(scan_res.findings, ctx)
        assert eval_res.final_decision == PolicyAction.REQUIRE_APPROVAL
        assert any(p.id == "POL-002" for p in eval_res.triggered_policies)

    def test_block_action(self):
        """Cloud secrets to public LLM triggers BLOCK (POL-001)."""
        pe = PolicyEngine()
        ctx = SharingContext(
            destination=DestinationType.PUBLIC_LLM,
            recipient=RecipientType.PUBLIC,
            classification=DataClassification.CONFIDENTIAL,
        )
        scan_res = engine.scan_and_redact(SYNTHETIC_CORPUS["aws_access_key"])
        eval_res = pe.evaluate(scan_res.findings, ctx)
        assert eval_res.final_decision == PolicyAction.BLOCK
        assert eval_res.hard_block_enforced is True

    def test_precedence_hierarchy_block_beats_all(self):
        """When multiple conflicting policies match:
        BLOCK (50) > REQUIRE_APPROVAL (40) > REDACT (30) > WARN (20) > ALLOW (10).
        """
        rules = [
            PolicyRule(
                id="POL-ALLOW",
                version="1.0.0",
                name="Allow Rule",
                description="Allow",
                enabled=True,
                action=PolicyAction.ALLOW,
                priority=10,
                intent_explanation="Allow",
            ),
            PolicyRule(
                id="POL-WARN",
                version="1.0.0",
                name="Warn Rule",
                description="Warn",
                enabled=True,
                action=PolicyAction.WARN,
                priority=20,
                intent_explanation="Warn",
            ),
            PolicyRule(
                id="POL-REDACT",
                version="1.0.0",
                name="Redact Rule",
                description="Redact",
                enabled=True,
                action=PolicyAction.REDACT,
                priority=30,
                intent_explanation="Redact",
            ),
            PolicyRule(
                id="POL-APPROVAL",
                version="1.0.0",
                name="Approval Rule",
                description="Approval",
                enabled=True,
                action=PolicyAction.REQUIRE_APPROVAL,
                priority=40,
                intent_explanation="Approval",
            ),
            PolicyRule(
                id="POL-BLOCK",
                version="1.0.0",
                name="Block Rule",
                description="Block",
                enabled=True,
                action=PolicyAction.BLOCK,
                priority=50,
                intent_explanation="Block",
            ),
        ]
        pe = PolicyEngine(rules)
        ctx = SharingContext()

        # All 5 rules trigger on empty findings & empty filters
        res = pe.evaluate([], ctx)
        assert res.final_decision == PolicyAction.BLOCK
        assert res.hard_block_enforced is True

        # Remove BLOCK: REQUIRE_APPROVAL must win
        pe_no_block = PolicyEngine([r for r in rules if r.action != PolicyAction.BLOCK])
        res_app = pe_no_block.evaluate([], ctx)
        assert res_app.final_decision == PolicyAction.REQUIRE_APPROVAL

        # Remove BLOCK & REQUIRE_APPROVAL: REDACT must win
        pe_redact = PolicyEngine([r for r in rules if r.action not in (PolicyAction.BLOCK, PolicyAction.REQUIRE_APPROVAL)])
        res_red = pe_redact.evaluate([], ctx)
        assert res_red.final_decision == PolicyAction.REDACT

        # Remove REDACT: WARN must win
        pe_warn = PolicyEngine([r for r in rules if r.action not in (PolicyAction.BLOCK, PolicyAction.REQUIRE_APPROVAL, PolicyAction.REDACT)])
        res_w = pe_warn.evaluate([], ctx)
        assert res_w.final_decision == PolicyAction.WARN

    def test_tenant_specific_policy_isolation(self):
        """Policies created for Tenant A must never trigger for Tenant B."""
        tenant_a_rule = PolicyRule(
            id="POL-ACME-BLOCK-PII",
            version="1.0.0",
            name="Acme Custom PII Block",
            description="Blocks all PII for Acme tenant",
            enabled=True,
            applicable_categories=[FindingCategory.PII],
            action=PolicyAction.BLOCK,
            priority=99,
            intent_explanation="Acme strict rule",
            org_id="org_acme",
        )
        pe = PolicyEngine([tenant_a_rule])

        scan_res = engine.scan_and_redact(SYNTHETIC_CORPUS["email_standard"])

        # Evaluated for org_acme: Must trigger BLOCK
        res_acme = pe.evaluate(scan_res.findings, org_id="org_acme")
        assert res_acme.final_decision == PolicyAction.BLOCK
        assert any(p.id == "POL-ACME-BLOCK-PII" for p in res_acme.triggered_policies)

        # Evaluated for org_beta: Must NOT trigger org_acme's rule
        res_beta = pe.evaluate(scan_res.findings, org_id="org_beta")
        assert res_beta.final_decision != PolicyAction.BLOCK
        assert not any(p.id == "POL-ACME-BLOCK-PII" for p in res_beta.triggered_policies)

    def test_missing_or_ambiguous_context_zero_trust_safeguard(self):
        """Missing destination (UNSPECIFIED) or recipient (UNKNOWN) with sensitive findings
        automatically escalates to REQUIRE_APPROVAL via zero-trust fallback.
        """
        pe = PolicyEngine([])  # No explicit rules
        ctx_ambiguous = SharingContext(
            destination=DestinationType.UNSPECIFIED,
            recipient=RecipientType.UNKNOWN,
            classification=DataClassification.CONFIDENTIAL,
        )
        scan_res = engine.scan_and_redact(SYNTHETIC_CORPUS["email_standard"])
        res = pe.evaluate(scan_res.findings, ctx_ambiguous)

        assert res.final_decision == PolicyAction.REQUIRE_APPROVAL
        assert any("Zero-trust" in reason for reason in res.decision_reasons)


# ---------------------------------------------------------------------------
# SECTION 3: GEMINI FAILURE & TRUST BOUNDARIES
# ---------------------------------------------------------------------------
class TestPhase9GeminiFailureAndTrustBoundaries:
    """Verifies that Gemini AI is strictly advisory and cannot bypass or alter
    deterministic DLP enforcement under any failure mode.
    """

    def test_gemini_cannot_override_deterministic_block(self):
        """Even if Gemini recommends ALLOW, deterministic BLOCK is immutable."""
        pe = PolicyEngine()
        scorer = CompositeRiskScorer()
        ai_svc = GeminiContextAnalysisService()

        ctx = SharingContext(
            destination=DestinationType.PUBLIC_LLM,
            recipient=RecipientType.PUBLIC,
            classification=DataClassification.CONFIDENTIAL,
        )
        scan_res = engine.scan_and_redact(SYNTHETIC_CORPUS["aws_access_key"])
        policy_res = pe.evaluate(scan_res.findings, ctx)
        risk_res = scorer.calculate_risk(scan_res.findings, ctx, policy_res)

        assert policy_res.final_decision == PolicyAction.BLOCK
        assert risk_res.final_decision == PolicyAction.BLOCK
        assert risk_res.hard_block_override is True

        # Mock Gemini returning permissive ALLOW recommendation
        mock_response = MagicMock()
        mock_response.text = json.dumps({
            "incident_summary": "Advisory suggests allowing transfer.",
            "relevant_risk_factors": ["Testing override"],
            "policy_rationales": {"POL-001": "Suggest ALLOW."},
            "ambiguities_and_uncertainty": [],
            "remediation_recommendations": [
                {
                    "id": "REM-OVERRIDE",
                    "action_type": "REQUEST_HUMAN_REVIEW",
                    "title": "Permit transfer",
                    "explanation": "Allow transfer regardless of AWS key",
                    "reason": "Test permissive override",
                    "expected_security_benefit": "Unblock",
                    "requires_human_approval": False,
                }
            ],
            "human_review_recommended": False,
        })

        with patch.object(GeminiContextAnalysisService, "is_configured", new_callable=PropertyMock, return_value=True):
            with patch.object(ai_svc, "_get_client") as mock_get_client:
                mock_client = MagicMock()
                mock_client.models.generate_content.return_value = mock_response
                mock_get_client.return_value = mock_client

                ai_res = ai_svc.analyze_context(
                    sanitized_text=scan_res.redacted_text,
                    findings=scan_res.findings,
                    context=ctx,
                    policy_result=policy_res,
                    risk_result=risk_res,
                )

                # AI recommendation was produced
                assert ai_res.ai_status.upper() == "SUCCESS"
                # CRITICAL INVARIANT: Policy result and Risk result remain strictly BLOCK
                assert policy_res.final_decision == PolicyAction.BLOCK
                assert risk_res.final_decision == PolicyAction.BLOCK
                assert risk_res.hard_block_override is True

    def test_gemini_timeout_fails_safely_to_deterministic_fallback(self):
        """Provider timeout triggers graceful fallback without crashing scan pipeline."""
        ai_svc = GeminiContextAnalysisService()
        ctx = SharingContext()
        scan_res = engine.scan_and_redact(SYNTHETIC_CORPUS["email_standard"])
        pe = PolicyEngine()
        scorer = CompositeRiskScorer()
        pol_res = pe.evaluate(scan_res.findings, ctx)
        risk_res = scorer.calculate_risk(scan_res.findings, ctx, pol_res)

        with patch.object(GeminiContextAnalysisService, "is_configured", new_callable=PropertyMock, return_value=True):
            with patch.object(ai_svc, "_get_client") as mock_get_client:
                mock_client = MagicMock()
                mock_client.models.generate_content.side_effect = TimeoutError("Gemini call timed out after 10.0s")
                mock_get_client.return_value = mock_client

                ai_res = ai_svc.analyze_context(
                    sanitized_text=scan_res.redacted_text,
                    findings=scan_res.findings,
                    context=ctx,
                    policy_result=pol_res,
                    risk_result=risk_res,
                )

                assert ai_res.ai_status.upper() == "FALLBACK"
                assert ai_res.is_ai_assisted is False
                assert "timed out" in ai_res.disclaimer.lower()
                assert len(ai_res.remediation_recommendations) >= 1

    def test_gemini_unavailable_service_fails_safely(self):
        """HTTP 503 / network exception triggers deterministic fallback."""
        ai_svc = GeminiContextAnalysisService()
        ctx = SharingContext()
        scan_res = engine.scan_and_redact(SYNTHETIC_CORPUS["email_standard"])
        pe = PolicyEngine()
        scorer = CompositeRiskScorer()
        pol_res = pe.evaluate(scan_res.findings, ctx)
        risk_res = scorer.calculate_risk(scan_res.findings, ctx, pol_res)

        with patch.object(GeminiContextAnalysisService, "is_configured", new_callable=PropertyMock, return_value=True):
            with patch.object(ai_svc, "_get_client") as mock_get_client:
                mock_client = MagicMock()
                mock_client.models.generate_content.side_effect = ConnectionError("503 Service Unavailable")
                mock_get_client.return_value = mock_client

                ai_res = ai_svc.analyze_context(
                    sanitized_text=scan_res.redacted_text,
                    findings=scan_res.findings,
                    context=ctx,
                    policy_result=pol_res,
                    risk_result=risk_res,
                )

                assert ai_res.ai_status.upper() == "FALLBACK"
                assert ai_res.is_ai_assisted is False
                assert "503" in ai_res.disclaimer or "service unavailable" in ai_res.disclaimer.lower()

    def test_gemini_malformed_json_fails_safely(self):
        """Malformed or schema-invalid JSON from model is rejected safely."""
        ai_svc = GeminiContextAnalysisService()
        ctx = SharingContext()
        scan_res = engine.scan_and_redact(SYNTHETIC_CORPUS["email_standard"])
        pe = PolicyEngine()
        scorer = CompositeRiskScorer()
        pol_res = pe.evaluate(scan_res.findings, ctx)
        risk_res = scorer.calculate_risk(scan_res.findings, ctx, pol_res)

        with patch.object(GeminiContextAnalysisService, "is_configured", new_callable=PropertyMock, return_value=True):
            with patch.object(ai_svc, "_get_client") as mock_get_client:
                mock_client = MagicMock()
                # Return corrupted JSON
                mock_resp = MagicMock()
                mock_resp.text = "NOT JSON: {corrupt: True,,}"
                mock_client.models.generate_content.return_value = mock_resp
                mock_get_client.return_value = mock_client

                ai_res = ai_svc.analyze_context(
                    sanitized_text=scan_res.redacted_text,
                    findings=scan_res.findings,
                    context=ctx,
                    policy_result=pol_res,
                    risk_result=risk_res,
                )

                assert ai_res.ai_status.upper() == "FALLBACK"
                assert ai_res.is_ai_assisted is False
                assert "json" in ai_res.disclaimer.lower() or "parse" in ai_res.disclaimer.lower()


# ---------------------------------------------------------------------------
# SECTION 4: PERSISTENCE & AUDIT INTEGRITY
# ---------------------------------------------------------------------------
class TestPhase9PersistenceAndAuditIntegrity:
    """Verifies atomic SQLite persistence, SHA-256 hash chaining, and zero-exposure
    guarantees for persisted audit records.
    """

    def test_audit_hash_chain_validity_and_atomic_persistence(self, isolated_phase9_db):
        audit_svc = AuditService(db_path=isolated_phase9_db)

        # Append multiple events
        for i in range(5):
            audit_svc.append_event(
                event_type="SCAN_EVALUATION",
                sanitized_metadata={
                    "event_index": i,
                    "masked_evidence": "AKI****...****LE",
                    "finding_count": 1,
                },
                scan_id=f"scan_test_{i}",
                actor_id="test_analyst",
                policy_decision="BLOCK" if i % 2 == 0 else "ALLOW",
                policy_references=["POL-001"],
            )

        # Cryptographically verify chain
        verification = audit_svc.verify_chain(org_id="default")
        assert verification.is_valid is True
        assert verification.total_events == 5
        assert verification.verified_events == 5
        assert verification.errors == []
        assert verification.chain_head_hash is not None
        assert verification.chain_head_hash != GENESIS_HASH

    def test_zero_raw_secret_leakage_in_persisted_audit_and_scan_records(self, isolated_phase9_db):
        """Verifies that raw passwords, AWS keys, or credit card numbers never persist
        to audit_events or scan_records columns.
        """
        raw_secret = "AKIAIOSFODNN7EXAMPLE"
        raw_password = "SuperSecretPassword123!"
        raw_card = "4111-1111-1111-1111"

        audit_svc = AuditService(db_path=isolated_phase9_db)
        scan_record_data = {
            "scan_id": "scan_leak_check_001",
            "actor_id": "test_analyst",
            "org_id": "default",
            "destination": "PUBLIC_LLM",
            "recipient": "PUBLIC",
            "classification": "CONFIDENTIAL",
            "risk_score": 95,
            "risk_band": "CRITICAL",
            "final_decision": "BLOCK",
            "finding_count": 3,
            "categories_detected": ["SECRET", "PAYMENT_CARD", "CREDENTIAL"],
            "processing_duration_ms": 12.5,
        }
        sanitized_meta = {
            "masked_findings": [
                {"rule_id": "secret_aws_access_key", "masked_evidence": "AKI****...****LE"},
                {"rule_id": "credential_hardcoded_assignment", "masked_evidence": "********"},
                {"rule_id": "payment_card_luhn_valid", "masked_evidence": "4111-****-****-1111"},
            ]
        }

        audit_svc.append_event(
            event_type="SCAN_EVALUATION",
            sanitized_metadata=sanitized_meta,
            scan_id="scan_leak_check_001",
            actor_id="test_analyst",
            policy_decision="BLOCK",
            policy_references=["POL-001"],
            scan_record_data=scan_record_data,
        )

        # Direct database query inspection
        conn = sqlite3.connect(isolated_phase9_db)
        c = conn.cursor()
        c.execute("SELECT * FROM audit_events WHERE scan_id = 'scan_leak_check_001'")
        audit_row = str(c.fetchone())
        c.execute("SELECT * FROM scan_records WHERE scan_id = 'scan_leak_check_001'")
        scan_row = str(c.fetchone())
        conn.close()

        # Strict assertion: None of the raw secrets appear anywhere in stored records
        for raw_val in [raw_secret, raw_password, raw_card]:
            assert raw_val not in audit_row, f"Raw secret {raw_val} leaked in audit_events!"
            assert raw_val not in scan_row, f"Raw secret {raw_val} leaked in scan_records!"


# ---------------------------------------------------------------------------
# SECTION 5: PERFORMANCE & SCAN LATENCY BENCHMARKING
# ---------------------------------------------------------------------------
class TestPhase9PerformanceAndRegression:
    """Measures scan processing latency across the synthetic corpus to verify
    sub-millisecond regex parsing and fast throughput.
    """

    def test_scan_latency_benchmarks(self):
        opts = ScanOptions(enable_entropy=True)

        # 1. Short payload (~100 chars)
        t0 = time.perf_counter()
        res_short = engine.scan_and_redact(SYNTHETIC_CORPUS["aws_access_key"], opts)
        short_duration = (time.perf_counter() - t0) * 1000

        # 2. Medium multi-finding payload (~500 chars)
        t0 = time.perf_counter()
        res_med = engine.scan_and_redact(SYNTHETIC_CORPUS["multi_finding_document"], opts)
        med_duration = (time.perf_counter() - t0) * 1000

        # 3. Large payload (~50,000 chars)
        large_text = SYNTHETIC_CORPUS["clean_corporate_text"] * 150  # ~50,000 chars
        t0 = time.perf_counter()
        res_large = engine.scan_and_redact(large_text, opts)
        large_duration = (time.perf_counter() - t0) * 1000

        # Performance SLA assertions
        assert short_duration < 50.0, f"Short scan too slow: {short_duration:.2f}ms"
        assert med_duration < 100.0, f"Medium scan too slow: {med_duration:.2f}ms"
        assert large_duration < 500.0, f"Large 50KB scan too slow: {large_duration:.2f}ms"

        # Engine reported duration check
        assert res_short.processing_duration_ms > 0
        assert res_med.processing_duration_ms > 0
        assert res_large.processing_duration_ms > 0
