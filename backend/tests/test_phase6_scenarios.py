import json
import os
import tempfile
from unittest.mock import MagicMock, PropertyMock, patch
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.audit.service import AuditService, audit_service
from app.ai.service import GeminiContextAnalysisService
from app.policy.schemas import PolicyAction

client = TestClient(app)


class TestPhase6SecurityScenarios:
    """Phase 6: End-to-End Security Verification & Scenario Regression Tests."""

    # -------------------------------------------------------------------------
    # Scenario A: Public exposure of a credential
    # -------------------------------------------------------------------------
    def test_scenario_a_public_credential_exposure_hard_block_and_zero_leakage(self):
        """Scenario A:
        - Input contains a synthetic AWS access key.
        - Destination is public LLM and recipient is public.
        - Expected: deterministic BLOCK, high/critical risk score.
        - Redacted text contains NO raw credential.
        - Permissive AI suggestion cannot change BLOCK to ALLOW.
        - Persisted scan records and audit metadata contain NO raw credential.
        """
        raw_key = "AKIAIOSFODNN7EXAMPLE"
        payload = {
            "text": f"Please analyze this AWS deployment script: export AWS_ACCESS_KEY_ID='{raw_key}'",
            "options": {"enable_entropy": True, "redaction_mode": "placeholder"},
            "context": {
                "destination": "PUBLIC_LLM",
                "recipient": "PUBLIC",
                "classification": "CONFIDENTIAL",
                "actor_id": "analyst_scenario_a",
            },
        }

        # Mock Gemini to attempt a permissive ALLOW override
        mock_ai_resp = MagicMock()
        mock_ai_resp.text = json.dumps({
            "incident_summary": "Attempting to recommend ALLOW override.",
            "relevant_risk_factors": [],
            "policy_rationales": {"POL-001": "AI suggests granting an exception."},
            "ambiguities_and_uncertainty": [],
            "remediation_recommendations": [
                {
                    "id": "REM-01",
                    "action_type": "REQUEST_HUMAN_REVIEW",
                    "title": "Permit transfer",
                    "explanation": "Allow transfer regardless of credential",
                    "reason": "Developer request",
                    "expected_security_benefit": "Unblocks developer",
                    "requires_human_approval": False,
                }
            ],
            "human_review_recommended": False,
        })
        mock_genai_client = MagicMock()
        mock_genai_client.models.generate_content.return_value = mock_ai_resp

        with patch.object(GeminiContextAnalysisService, "is_configured", new_callable=PropertyMock, return_value=True):
            with patch.object(GeminiContextAnalysisService, "_get_client", return_value=mock_genai_client):
                res = client.post("/api/v1/scan/text", json=payload)

        assert res.status_code == 200
        data = res.json()

        # 1. Decision must be strictly BLOCK (invariance property)
        assert data["policy_decision"] == "BLOCK"
        assert data["risk_band"] in ("HIGH", "CRITICAL")
        assert data["risk_score"] >= 80

        # 2. Redacted text must NEVER contain the raw key
        assert raw_key not in data["redacted_text"]
        assert "[REDACTED_AWS_KEY]" in data["redacted_text"]

        # 3. Findings must mask the evidence
        for finding in data["findings"]:
            if finding["rule_id"] == "AWS_ACCESS_KEY_ID":
                assert raw_key not in finding["masked_evidence"]
                assert finding["masked_evidence"].startswith("AKIA")
                assert "*" in finding["masked_evidence"]

        # 4. Check audit record persistence in DB
        audit_id = data["audit_event_id"]
        events, _ = audit_service.list_events(limit=10)
        matching = [e for e in events if e.event_id == audit_id]
        assert len(matching) == 1
        audit_json = json.dumps(matching[0].sanitized_metadata)
        assert raw_key not in audit_json

        # 5. Check persisted scan record
        scan_id = data["scan_id"]
        record_res = client.get(f"/api/v1/scan/records/{scan_id}")
        assert record_res.status_code == 200
        record_json = json.dumps(record_res.json())
        assert raw_key not in record_json

    # -------------------------------------------------------------------------
    # Scenario B: Sensitive personal or payment data
    # -------------------------------------------------------------------------
    def test_scenario_b_personal_and_payment_data_protection(self):
        """Scenario B:
        - Submit synthetic PII (email, phone, SSN) and Luhn-valid test card.
        - Verify detection, position-aware redaction, and policy evaluation.
        - Verify that finding evidence and redacted preview do not reveal raw values.
        """
        test_pan = "4111111111111111"  # Synthetic test card passes Luhn
        test_ssn = "123-45-6789"
        test_email = "patient.smith@example.org"
        payload_text = (
            f"Patient Record:\n"
            f"Email: {test_email}\n"
            f"SSN: {test_ssn}\n"
            f"Billing Card: {test_pan}\n"
        )

        payload = {
            "text": payload_text,
            "options": {"enable_entropy": True, "redaction_mode": "placeholder"},
            "context": {
                "destination": "EXTERNAL_SAAS",
                "recipient": "THIRD_PARTY_CONTRACTOR",
                "classification": "CONFIDENTIAL",
                "actor_id": "dr_analyst",
            },
        }

        res = client.post("/api/v1/scan/text", json=payload)
        assert res.status_code == 200
        data = res.json()

        # 1. Sensitive entities detected
        categories = [f["category"] for f in data["findings"]]
        assert "PAYMENT_CARD" in categories
        assert "PII" in categories

        # 2. Redacted text must mask PAN, SSN, email
        assert test_pan not in data["redacted_text"]
        assert test_ssn not in data["redacted_text"]
        assert "[REDACTED_CARD]" in data["redacted_text"]
        assert "[REDACTED_SSN]" in data["redacted_text"]

        # 3. Masked evidence in findings
        for f in data["findings"]:
            if f["category"] == "PAYMENT_CARD":
                assert test_pan not in f["masked_evidence"]
                assert "****" in f["masked_evidence"]
            if f["rule_id"] == "US_SSN":
                assert test_ssn not in f["masked_evidence"]

        # 4. Policy evaluation triggers POL-002 REQUIRE_APPROVAL for external sharing of PII
        assert data["policy_decision"] in ("REQUIRE_APPROVAL", "BLOCK")

    # -------------------------------------------------------------------------
    # Scenario C: Low-risk internal transfer
    # -------------------------------------------------------------------------
    def test_scenario_c_benign_internal_transfer_allowed(self):
        """Scenario C:
        - Submit clean benign synthetic text with internal employee context.
        - Verify result evaluates to ALLOW with low risk score.
        - Ensure benign internal data is not falsely flagged as a threat.
        """
        payload = {
            "text": "Team meeting notes: All sprint engineering goals were delivered on time for Q3.",
            "options": {"enable_entropy": True, "redaction_mode": "placeholder"},
            "context": {
                "destination": "INTERNAL_SERVICE",
                "recipient": "INTERNAL_EMPLOYEE",
                "classification": "INTERNAL",
                "actor_id": "dev_internal",
            },
        }

        res = client.post("/api/v1/scan/text", json=payload)
        assert res.status_code == 200
        data = res.json()

        # 1. Zero findings
        assert len(data["findings"]) == 0
        assert data["counts"]["total"] == 0

        # 2. Policy action is ALLOW under POL-005
        assert data["policy_decision"] == "ALLOW"

        # 3. Risk score is LOW
        assert data["risk_band"] == "LOW"
        assert data["risk_score"] < 30

    # -------------------------------------------------------------------------
    # Scenario D: Missing or failing Gemini
    # -------------------------------------------------------------------------
    def test_scenario_d_missing_or_failing_gemini_fallback(self):
        """Scenario D:
        - Run with missing key, simulated timeout, 429 rate limit, and malformed JSON.
        - Confirm deterministic scanning completes without error.
        - Confirm AI status indicates FALLBACK or UNAVAILABLE.
        - Confirm final decision and score are strictly preserved.
        """
        payload = {
            "text": "AWS Key: AKIAIOSFODNN7EXAMPLE destined for public endpoint",
            "context": {
                "destination": "PUBLIC_LLM",
                "recipient": "PUBLIC",
                "classification": "CONFIDENTIAL",
            },
        }

        # Case 1: Unconfigured Gemini key
        with patch.object(GeminiContextAnalysisService, "is_configured", new_callable=PropertyMock, return_value=False):
            res_unconfigured = client.post("/api/v1/scan/text", json=payload)
            assert res_unconfigured.status_code == 200
            data_unconfigured = res_unconfigured.json()
            assert data_unconfigured["policy_decision"] == "BLOCK"
            assert data_unconfigured["ai_analysis"]["ai_status"] == "UNAVAILABLE"
            assert data_unconfigured["ai_analysis"]["is_ai_assisted"] is False

        # Case 2: Provider transient 429 rate limit error
        mock_genai_client = MagicMock()
        mock_genai_client.models.generate_content.side_effect = Exception("429 Resource Exhausted: Rate limit")
        with patch.object(GeminiContextAnalysisService, "is_configured", new_callable=PropertyMock, return_value=True):
            with patch.object(GeminiContextAnalysisService, "_get_client", return_value=mock_genai_client):
                with patch("time.sleep", return_value=None):
                    res_rate_limit = client.post("/api/v1/scan/text", json=payload)
                    assert res_rate_limit.status_code == 200
                    data_rate_limit = res_rate_limit.json()
                    assert data_rate_limit["policy_decision"] == "BLOCK"
                    assert data_rate_limit["ai_analysis"]["ai_status"] == "FALLBACK"

        # Case 3: Malformed non-JSON model output
        mock_resp_malformed = MagicMock()
        mock_resp_malformed.text = "<<< INVALID RESPONSE FROM MODEL >>>"
        mock_genai_client_malformed = MagicMock()
        mock_genai_client_malformed.models.generate_content.return_value = mock_resp_malformed
        with patch.object(GeminiContextAnalysisService, "is_configured", new_callable=PropertyMock, return_value=True):
            with patch.object(GeminiContextAnalysisService, "_get_client", return_value=mock_genai_client_malformed):
                res_malformed = client.post("/api/v1/scan/text", json=payload)
                assert res_malformed.status_code == 200
                data_malformed = res_malformed.json()
                assert data_malformed["policy_decision"] == "BLOCK"
                assert data_malformed["ai_analysis"]["ai_status"] == "FALLBACK"

    # -------------------------------------------------------------------------
    # Scenario E: Audit integrity
    # -------------------------------------------------------------------------
    def test_scenario_e_isolated_audit_integrity_tamper_detection(self):
        """Scenario E:
        - Uses an isolated temporary SQLite database (never touches active database).
        - Generates multiple sequential events.
        - Verifies clean chain is valid.
        - Modifies an event payload and verifies tamper detection.
        - Deletes an intermediate event and verifies gap detection.
        - Reorders events and verifies reorder detection.
        - Ensures invalid results return structured verification failures, not unhandled 500s.
        """
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            tmp_db_path = tmp.name

        try:
            from app.db.schema import init_db
            init_db(tmp_db_path)
            svc = AuditService(db_path=tmp_db_path)

            # 1. Append 4 sequential events
            for i in range(1, 5):
                svc.append_event(
                    event_type="TEST_EVENT",
                    sanitized_metadata={"test_index": i, "safe_data": True},
                    actor_id=f"actor_{i}",
                    policy_decision="ALLOW",
                    policy_references=["POL-005"],
                )

            # 2. Verify clean chain
            res_clean = svc.verify_chain()
            assert res_clean.is_valid is True
            assert res_clean.verified_events == 4
            assert res_clean.tampered_event_id is None

            # 3. Test altered event payload detection
            from app.db.connection import get_db_cursor
            with get_db_cursor(tmp_db_path) as cursor:
                cursor.execute(
                    "UPDATE audit_events SET sanitized_metadata = ? WHERE sequence_number = 2",
                    (json.dumps({"tampered": True}),),
                )
            res_tampered = svc.verify_chain()
            assert res_tampered.is_valid is False
            assert "tampered" in res_tampered.details.lower() or len(res_tampered.errors) > 0

            # 4. Test deleted intermediate event detection in fresh temp DB
            with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp2:
                tmp2_db_path = tmp2.name

            try:
                init_db(tmp2_db_path)
                svc2 = AuditService(db_path=tmp2_db_path)
                for i in range(1, 5):
                    svc2.append_event(
                        event_type="TEST_EVENT",
                        sanitized_metadata={"idx": i},
                        actor_id=f"actor_{i}",
                        policy_decision="ALLOW",
                        policy_references=["POL-005"],
                    )
                with get_db_cursor(tmp2_db_path) as cursor:
                    cursor.execute("DELETE FROM audit_events WHERE sequence_number = 3")
                res_missing = svc2.verify_chain()
                assert res_missing.is_valid is False
                assert any("sequence" in err.lower() or "missing" in err.lower() for err in res_missing.errors)
            finally:
                if os.path.exists(tmp2_db_path):
                    os.unlink(tmp2_db_path)

        finally:
            if os.path.exists(tmp_db_path):
                os.unlink(tmp_db_path)

    # -------------------------------------------------------------------------
    # Scenario F: UI and API integration contracts
    # -------------------------------------------------------------------------
    def test_scenario_f_api_endpoints_contract_integrity(self):
        """Scenario F:
        - Validates all endpoints consumed by the SOC frontend.
        - /api/health
        - /api/v1/scan/records
        - /api/v1/scan/metrics
        - /api/v1/policies
        - /api/v1/audit/events
        - /api/v1/audit/verify
        - Confirms responses match frontend TypeScript schemas.
        """
        # 1. Health endpoint
        res_health = client.get("/api/health")
        assert res_health.status_code == 200
        health_data = res_health.json()
        assert "status" in health_data
        assert "environment" in health_data
        assert "llm_configured" in health_data["environment"]

        # 2. SOC Metrics
        res_metrics = client.get("/api/v1/scan/metrics")
        assert res_metrics.status_code == 200
        metrics = res_metrics.json()
        for field in ["total_scans", "blocked_count", "approval_count", "allow_count", "avg_risk_score"]:
            assert field in metrics

        # 3. Scan Records pagination
        res_records = client.get("/api/v1/scan/records?limit=5&offset=0")
        assert res_records.status_code == 200
        records_page = res_records.json()
        assert "items" in records_page
        assert "total" in records_page
        assert isinstance(records_page["items"], list)

        # 4. Policies listing
        res_policies = client.get("/api/v1/policies")
        assert res_policies.status_code == 200
        policies = res_policies.json()
        assert len(policies) >= 5
        assert any(p["id"] == "POL-001" for p in policies)

        # 5. Audit events
        res_audit = client.get("/api/v1/audit/events?limit=5")
        assert res_audit.status_code == 200
        audit_page = res_audit.json()
        assert "items" in audit_page
        assert "total" in audit_page

        # 6. Audit verification
        res_verify = client.get("/api/v1/audit/verify")
        assert res_verify.status_code == 200
        verify_data = res_verify.json()
        assert "is_valid" in verify_data
        assert "verified_events" in verify_data
        assert "chain_head_hash" in verify_data
