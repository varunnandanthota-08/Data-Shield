import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

SYNTHETIC_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


class TestAPIPhase3Endpoints:
    def test_scan_text_with_context_and_audit(self):
        payload = {
            "text": f"Production deployment leaked key: {SYNTHETIC_AWS_KEY}",
            "context": {
                "destination": "PUBLIC_LLM",
                "recipient": "PUBLIC",
                "classification": "CONFIDENTIAL",
                "actor_id": "test_engineer",
            },
        }
        response = client.post("/api/v1/scan/text", json=payload)
        assert response.status_code == 200
        data = response.json()

        # Check detection and redaction
        assert data["counts"]["total"] >= 1
        assert SYNTHETIC_AWS_KEY not in data["redacted_text"]

        # Check policy and risk scoring integration
        assert data["policy_decision"] == "BLOCK"
        assert data["risk_band"] == "CRITICAL"
        assert data["risk_score"] >= 85
        assert len(data["triggered_policies"]) >= 1
        assert any(p["id"] == "POL-001" for p in data["triggered_policies"])

        # Check tamper-evident audit linkage
        assert "audit_event_id" in data
        assert data["audit_event_id"] is not None
        assert "audit_event_hash" in data
        assert len(data["audit_event_hash"]) == 64

    def test_list_and_get_policies(self):
        response = client.get("/api/v1/policies")
        assert response.status_code == 200
        policies = response.json()
        assert len(policies) >= 5
        policy_ids = [p["id"] for p in policies]
        assert "POL-001" in policy_ids
        assert "POL-002" in policy_ids
        assert "POL-003" in policy_ids
        assert "POL-004" in policy_ids
        assert "POL-005" in policy_ids

        # Fetch POL-001 individually
        get_res = client.get("/api/v1/policies/POL-001")
        assert get_res.status_code == 200
        assert get_res.json()["name"] == "Block Cloud Secrets and Credentials to Public Destinations"

    def test_create_and_update_policy(self):
        new_policy = {
            "id": "POL-TEST-999",
            "version": "1.0.0",
            "name": "Integration Test Policy",
            "description": "Rule created during API integration test",
            "enabled": True,
            "applicable_categories": ["PAYMENT_CARD"],
            "applicable_sensitivities": ["RESTRICTED"],
            "target_destinations": ["EXTERNAL_SAAS"],
            "target_recipients": ["PUBLIC"],
            "action": "BLOCK",
            "priority": 95,
            "intent_explanation": "Test rule intent",
        }
        create_res = client.post("/api/v1/policies", json=new_policy)
        assert create_res.status_code == 201
        assert create_res.json()["id"] == "POL-TEST-999"

        # Verify it can be fetched
        get_res = client.get("/api/v1/policies/POL-TEST-999")
        assert get_res.status_code == 200
        assert get_res.json()["action"] == "BLOCK"

    def test_evaluate_policy_endpoint(self):
        payload = {
            "text": "Card number 4111-1111-1111-1111 submitted.",
            "context": {
                "destination": "EXTERNAL_SAAS",
                "recipient": "THIRD_PARTY_CONTRACTOR",
                "classification": "RESTRICTED",
            },
        }
        res = client.post("/api/v1/policies/evaluate", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert "policy_evaluation" in data
        assert "risk_scoring" in data
        assert data["policy_evaluation"]["final_decision"] in ("REQUIRE_APPROVAL", "BLOCK")

    def test_audit_events_pagination_and_verification(self):
        # 1. Fetch paginated events
        events_res = client.get("/api/v1/audit/events?limit=10&offset=0")
        assert events_res.status_code == 200
        events_data = events_res.json()
        assert "items" in events_data
        assert "total" in events_data
        assert events_data["total"] >= 1

        # 2. Run chain integrity verification
        verify_res = client.get("/api/v1/audit/verify")
        assert verify_res.status_code == 200
        verify_data = verify_res.json()
        assert verify_data["is_valid"] is True
        assert verify_data["verified_events"] >= 1
        assert verify_data["tampered_event_id"] is None

    def test_invalid_context_returns_422(self):
        """Verify invalid context format returns 422 Validation Error instead of 500 Internal Server Error."""
        payload = {
            "text": "Valid test text",
            "context": {
                "destination": "INVALID_DESTINATION_FOR_SECURITY_TEST",
            },
        }
        res = client.post("/api/v1/scan/text", json=payload)
        assert res.status_code == 422

    def test_options_cannot_suppress_entropy_detection(self):
        """Verify callers cannot disable entropy detection via request options to suppress findings."""
        # Synthetic high entropy token
        high_entropy_token = "K9zX8bQ2wV5pL1mJ7yT4rN6sD3fG0hA9"
        payload = {
            "text": f"Here is high entropy token: {high_entropy_token}",
            "options": {"enable_entropy": False},
        }
        res = client.post("/api/v1/scan/text", json=payload)
        assert res.status_code == 200
        data = res.json()
        # High entropy token must be detected despite caller's attempt to disable it
        assert any(f["category"] == "HIGH_ENTROPY_TOKEN" for f in data["findings"])

    def test_audit_highest_severity_hierarchy(self):
        """Verify audit record highest_severity uses severity hierarchy (CRITICAL > LOW) rather than alphabetical sort."""
        payload = {
            "text": "AWS Key: AKIAIOSFODNN7EXAMPLE and Phone: +1 415 555 2671",
            "context": {
                "destination": "PUBLIC_LLM",
                "recipient": "PUBLIC",
                "classification": "CONFIDENTIAL",
            },
        }
        res = client.post("/api/v1/scan/text", json=payload)
        assert res.status_code == 200
        audit_id = res.json()["audit_event_id"]

        events_res = client.get("/api/v1/audit/events?limit=10")
        assert events_res.status_code == 200
        matching = [e for e in events_res.json()["items"] if e["event_id"] == audit_id]
        assert len(matching) == 1
        meta = matching[0]["sanitized_metadata"]
        assert meta["highest_severity"] == "CRITICAL"
        assert meta["highest_severity"] != "LOW"

    def test_redact_produces_redacted_text_in_scan_endpoint(self):
        """Confirm scan endpoint produces appropriately redacted outgoing content."""
        payload = {
            "text": "Secret deployed: AKIAIOSFODNN7EXAMPLE and email dev@example.com",
        }
        res = client.post("/api/v1/scan/text", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert "[REDACTED_AWS_KEY]" in data["redacted_text"]
        assert "[REDACTED_EMAIL]" in data["redacted_text"]
        assert "AKIAIOSFODNN7EXAMPLE" not in data["redacted_text"]
        assert "dev@example.com" not in data["redacted_text"]

    def test_list_scan_records_and_detail(self):
        """Phase 5: Test scan records list, filtering, and detail endpoint."""
        # 1. Perform a scan to ensure at least one record exists
        payload = {
            "text": "AWS Key: AKIAIOSFODNN7EXAMPLE",
            "context": {
                "destination": "PUBLIC_LLM",
                "recipient": "PUBLIC",
                "classification": "CONFIDENTIAL",
            },
        }
        scan_res = client.post("/api/v1/scan/text", json=payload)
        assert scan_res.status_code == 200
        scan_id = scan_res.json()["scan_id"]

        # 2. Query scan records page
        records_res = client.get("/api/v1/scan/records?limit=10")
        assert records_res.status_code == 200
        records_data = records_res.json()
        assert "items" in records_data
        assert "total" in records_data
        assert records_data["total"] >= 1
        assert any(r["scan_id"] == scan_id for r in records_data["items"])

        # 3. Query specific detail
        detail_res = client.get(f"/api/v1/scan/records/{scan_id}")
        assert detail_res.status_code == 200
        detail_data = detail_res.json()
        assert detail_data["scan_id"] == scan_id
        assert detail_data["final_decision"] == "BLOCK"
        assert "audit_event_id" in detail_data
        assert "audit_metadata" in detail_data

    def test_get_soc_metrics(self):
        """Phase 5: Test SOC metrics aggregation endpoint."""
        res = client.get("/api/v1/scan/metrics")
        assert res.status_code == 200
        data = res.json()
        assert "total_scans" in data
        assert "blocked_count" in data
        assert "avg_risk_score" in data
        assert "total_findings" in data
        assert data["total_scans"] >= 1

