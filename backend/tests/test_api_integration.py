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
