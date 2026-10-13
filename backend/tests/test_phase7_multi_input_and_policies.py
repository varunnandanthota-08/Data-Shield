import io
import json
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.engine.file_extractor import (
    extract_file_content,
    FileExtractionError,
    MAX_FILE_SIZE_BYTES,
)
from app.db.repository import ScanRecordRepository

client = TestClient(app)

SYNTHETIC_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
SYNTHETIC_SSN = "123-45-6789"
SYNTHETIC_CARD = "4111111111111111"


class TestFileExtractionEngine:
    def test_extract_valid_plain_text(self):
        content = b"Hello world, this is a clean log payload."
        res = extract_file_content("debug.log", content)
        assert res.filename == "debug.log"
        assert res.file_type == "plain_text"
        assert "Hello world" in res.text_content
        assert len(res.text_content) == len(content)

    def test_extract_valid_code_file(self):
        content = b"def handler(event):\n    return {'status': 200}"
        res = extract_file_content("main.py", content)
        assert res.file_type == "source_code"
        assert "def handler" in res.text_content

    def test_extract_unsupported_extension(self):
        with pytest.raises(FileExtractionError) as exc_info:
            extract_file_content("payload.exe", b"MZ\x90\x00\x03...")
        assert exc_info.value.status_code == 400
        assert "rejected for security reasons" in exc_info.value.message

    def test_extract_oversized_file(self):
        huge_bytes = b"A" * (MAX_FILE_SIZE_BYTES + 1024)
        with pytest.raises(FileExtractionError) as exc_info:
            extract_file_content("large.txt", huge_bytes)
        assert exc_info.value.status_code == 413
        assert "exceeds" in exc_info.value.message

    def test_extract_empty_file(self):
        with pytest.raises(FileExtractionError) as exc_info:
            extract_file_content("empty.json", b"")
        assert exc_info.value.status_code == 400
        assert "empty" in exc_info.value.message

    def test_extract_null_bytes_rejected_as_binary(self):
        with pytest.raises(FileExtractionError) as exc_info:
            extract_file_content("data.txt", b"header\x00\x00\x00\x01payload")
        assert exc_info.value.status_code == 400
        assert "binary null bytes" in exc_info.value.message


class TestFileScanAPI:
    def test_scan_valid_code_file_clean(self):
        code_bytes = b"const x = 42;\nconsole.log('clean script');"
        files = {"file": ("script.js", io.BytesIO(code_bytes), "application/javascript")}
        data = {
            "context_json": json.dumps({
                "destination": "INTERNAL_SERVICE",
                "recipient": "INTERNAL_EMPLOYEE",
                "classification": "INTERNAL",
                "actor_id": "dev_test",
                "org_id": "default",
            })
        }
        response = client.post("/api/v1/scan/file", files=files, data=data)
        assert response.status_code == 200
        res = response.json()
        assert res["source_type"] == "file"
        assert res["filename"] == "script.js"
        assert res["file_size_bytes"] == len(code_bytes)
        assert res["counts"]["total"] == 0
        assert res["policy_decision"] == "ALLOW"
        assert "audit_event_id" in res

    def test_scan_file_with_synthetic_secret_hard_block(self):
        leak_text = f"AWS_SECRET_KEY={SYNTHETIC_AWS_KEY}\nDEPLOYMENT=prod".encode("utf-8")
        files = {"file": ("credentials.env", io.BytesIO(leak_text), "text/plain")}
        data = {
            "context_json": json.dumps({
                "destination": "PUBLIC_LLM",
                "recipient": "PUBLIC",
                "classification": "CONFIDENTIAL",
                "actor_id": "test_analyst",
                "org_id": "default",
            })
        }
        response = client.post("/api/v1/scan/file", files=files, data=data)
        assert response.status_code == 200
        res = response.json()
        assert res["policy_decision"] == "BLOCK"
        assert res["risk_band"] == "CRITICAL"
        assert res["counts"]["total"] >= 1
        # Hard invariant: raw secret never present in redacted text
        assert SYNTHETIC_AWS_KEY not in res["redacted_text"]

    def test_scan_file_pii_and_pci_detection(self):
        customer_csv = f"name,ssn,card\nJane,{SYNTHETIC_SSN},{SYNTHETIC_CARD}".encode("utf-8")
        files = {"file": ("customers.csv", io.BytesIO(customer_csv), "text/csv")}
        data = {
            "context_json": json.dumps({
                "destination": "EXTERNAL_SAAS",
                "recipient": "THIRD_PARTY_CONTRACTOR",
                "classification": "CONFIDENTIAL",
                "actor_id": "ops_analyst",
                "org_id": "default",
            })
        }
        response = client.post("/api/v1/scan/file", files=files, data=data)
        assert response.status_code == 200
        res = response.json()
        assert res["counts"]["total"] >= 2
        assert SYNTHETIC_SSN not in res["redacted_text"]
        assert SYNTHETIC_CARD not in res["redacted_text"]

    def test_scan_file_unsupported_extension_rejected(self):
        files = {"file": ("malware.exe", io.BytesIO(b"MZ12345"), "application/octet-stream")}
        response = client.post("/api/v1/scan/file", files=files)
        assert response.status_code == 400
        assert "rejected for security reasons" in response.json()["detail"]

    def test_scan_file_oversized_rejected(self):
        huge_bytes = b"X" * (MAX_FILE_SIZE_BYTES + 100)
        files = {"file": ("huge.txt", io.BytesIO(huge_bytes), "text/plain")}
        response = client.post("/api/v1/scan/file", files=files)
        assert response.status_code == 413
        assert "exceeds" in response.json()["detail"]

    def test_scan_file_empty_rejected(self):
        files = {"file": ("empty.txt", io.BytesIO(b""), "text/plain")}
        response = client.post("/api/v1/scan/file", files=files)
        assert response.status_code == 400
        assert "empty" in response.json()["detail"]

    def test_no_raw_secret_stored_in_scan_record_or_audit(self):
        secret_payload = f"test_key={SYNTHETIC_AWS_KEY}".encode("utf-8")
        files = {"file": ("secrets.txt", io.BytesIO(secret_payload), "text/plain")}
        data = {
            "context_json": json.dumps({
                "destination": "PUBLIC_LLM",
                "recipient": "PUBLIC",
                "classification": "CONFIDENTIAL",
                "actor_id": "auditor",
                "org_id": "default",
            })
        }
        res = client.post("/api/v1/scan/file", files=files, data=data).json()
        scan_id = res["scan_id"]

        # Check repository scan record
        repo = ScanRecordRepository()
        scan_rec = repo.get_scan_record(scan_id)
        assert scan_rec is not None
        # Verify scan record does not contain raw secret in its fields
        assert SYNTHETIC_AWS_KEY not in json.dumps(scan_rec)

        # Check audit event
        audit_event_id = res["audit_event_id"]
        audit_res = client.get("/api/v1/audit/events?limit=10&offset=0")
        assert audit_res.status_code == 200
        audit_events = audit_res.json()
        matched_event = next((e for e in audit_events["items"] if e["event_id"] == audit_event_id), None)
        assert matched_event is not None
        assert SYNTHETIC_AWS_KEY not in json.dumps(matched_event)


class TestCompanySpecificPolicyBuilder:
    def test_create_and_list_organization_policy(self):
        policy_id = "POL-TEST-ACME-001"
        payload = {
            "id": policy_id,
            "version": "1.0.0",
            "name": "Acme Internal Sharing Rule",
            "description": "Requires approval when sharing confidential data internally.",
            "enabled": True,
            "org_id": "org_acme",
            "applicable_categories": ["PII"],
            "applicable_sensitivities": ["CONFIDENTIAL"],
            "target_destinations": ["INTERNAL_SERVICE"],
            "target_recipients": ["INTERNAL_EMPLOYEE"],
            "action": "REQUIRE_APPROVAL",
            "priority": 75,
            "intent_explanation": "Acme corporate compliance policy.",
        }
        # Create
        create_res = client.post("/api/v1/policies", json=payload)
        assert create_res.status_code in (200, 201)
        created = create_res.json()
        assert created["id"] == policy_id
        assert created["org_id"] == "org_acme"

        # List filtered by org_id=org_acme
        list_res = client.get("/api/v1/policies?org_id=org_acme")
        assert list_res.status_code == 200
        policies = list_res.json()
        assert any(p["id"] == policy_id for p in policies)

        # Ensure it does NOT show under org_cybershield
        other_list_res = client.get("/api/v1/policies?org_id=org_cybershield")
        assert other_list_res.status_code == 200
        other_policies = other_list_res.json()
        assert not any(p["id"] == policy_id for p in other_policies)

    def test_create_policy_validation_failure(self):
        # Invalid ID with disallowed characters
        payload = {
            "id": "INVALID POLICY ID @@",
            "version": "1.0.0",
            "name": "Bad ID Policy",
            "description": "Test",
            "action": "BLOCK",
            "priority": 50,
            "intent_explanation": "Test",
        }
        res = client.post("/api/v1/policies", json=payload)
        assert res.status_code in (400, 422)

        # Invalid priority out of bounds (1-100)
        payload2 = {
            "id": "POL-BAD-PRIORITY",
            "version": "1.0.0",
            "name": "Bad Priority",
            "description": "Test",
            "action": "BLOCK",
            "priority": 999,
            "intent_explanation": "Test",
        }
        res2 = client.post("/api/v1/policies", json=payload2)
        assert res2.status_code in (400, 422)

    def test_create_duplicate_policy_id_rejected(self):
        dup_id = "POL-DUP-TEST"
        payload = {
            "id": dup_id,
            "version": "1.0.0",
            "name": "First Instance",
            "description": "Test",
            "action": "WARN",
            "priority": 25,
            "org_id": "org_test",
            "intent_explanation": "Test intent",
        }
        res1 = client.post("/api/v1/policies", json=payload)
        assert res1.status_code in (200, 201)

        # Second creation with check_duplicate=true must fail with 409
        res2 = client.post("/api/v1/policies?check_duplicate=true", json=payload)
        assert res2.status_code == 409
        assert "already exists" in res2.json()["detail"]

    def test_custom_allow_cannot_override_mandatory_hard_block(self):
        # Attempt to create an aggressive ALLOW rule for secrets in an org
        org_id = "org_override_test"
        allow_rule_id = "POL-UNSAFE-ALLOW"
        payload = {
            "id": allow_rule_id,
            "version": "1.0.0",
            "name": "Permissive Secret Allow",
            "description": "Attempt to allow secret sharing.",
            "enabled": True,
            "org_id": org_id,
            "applicable_categories": ["SECRET"],
            "applicable_sensitivities": ["CONFIDENTIAL", "RESTRICTED"],
            "target_destinations": ["PUBLIC_LLM"],
            "target_recipients": ["PUBLIC"],
            "action": "ALLOW",
            "priority": 100,  # Max priority
            "intent_explanation": "Adversarial test rule",
        }
        client.post("/api/v1/policies", json=payload)

        # Now scan text containing AWS key in this tenant context
        scan_payload = {
            "text": f"AWS Key leak: {SYNTHETIC_AWS_KEY}",
            "context": {
                "destination": "PUBLIC_LLM",
                "recipient": "PUBLIC",
                "classification": "CONFIDENTIAL",
                "actor_id": "tester",
                "org_id": org_id,
            },
        }
        res = client.post("/api/v1/scan/text", json=scan_payload).json()

        # Hard-block invariance: POL-001 BLOCK must still win unconditionally!
        assert res["policy_decision"] == "BLOCK"
        assert res["risk_band"] == "CRITICAL"

    def test_custom_block_enforced_for_org(self):
        org_id = "org_strict_pii"
        strict_rule_id = "POL-STRICT-PII-BLOCK"
        payload = {
            "id": strict_rule_id,
            "version": "1.0.0",
            "name": "Strict Block on PII",
            "description": "Blocks any PII to internal service for this org.",
            "enabled": True,
            "org_id": org_id,
            "applicable_categories": ["PII"],
            "applicable_sensitivities": ["INTERNAL"],
            "target_destinations": ["INTERNAL_SERVICE"],
            "target_recipients": ["INTERNAL_EMPLOYEE"],
            "action": "BLOCK",
            "priority": 80,
            "intent_explanation": "Strict compliance",
        }
        client.post("/api/v1/policies", json=payload)

        # Scan PII in this org context
        scan_payload = {
            "text": f"Employee SSN record: {SYNTHETIC_SSN}",
            "context": {
                "destination": "INTERNAL_SERVICE",
                "recipient": "INTERNAL_EMPLOYEE",
                "classification": "INTERNAL",
                "actor_id": "hr_lead",
                "org_id": org_id,
            },
        }
        res = client.post("/api/v1/scan/text", json=scan_payload).json()
        assert res["policy_decision"] == "BLOCK"
        assert any(p["id"] == strict_rule_id for p in res["triggered_policies"])

    def test_disabled_policy_is_not_evaluated(self):
        org_id = "org_disabled_test"
        rule_id = "POL-DISABLED-RULE"
        payload = {
            "id": rule_id,
            "version": "1.0.0",
            "name": "Disabled Rule",
            "description": "Rule that will be toggled off.",
            "enabled": True,
            "org_id": org_id,
            "applicable_categories": ["PII"],
            "applicable_sensitivities": ["INTERNAL"],
            "target_destinations": ["INTERNAL_SERVICE"],
            "target_recipients": ["INTERNAL_EMPLOYEE"],
            "action": "BLOCK",
            "priority": 80,
            "intent_explanation": "Test disable",
        }
        client.post("/api/v1/policies", json=payload)

        # Toggle it off
        toggle_res = client.patch(f"/api/v1/policies/{rule_id}/toggle?enabled=false")
        assert toggle_res.status_code == 200
        assert toggle_res.json()["enabled"] is False

        # Scan PII in this org context
        scan_payload = {
            "text": f"Employee SSN record: {SYNTHETIC_SSN}",
            "context": {
                "destination": "INTERNAL_SERVICE",
                "recipient": "INTERNAL_EMPLOYEE",
                "classification": "INTERNAL",
                "actor_id": "hr_lead",
                "org_id": org_id,
            },
        }
        res = client.post("/api/v1/scan/text", json=scan_payload).json()
        # Since rule is disabled, it should not trigger or block
        assert not any(p["id"] == rule_id for p in res["triggered_policies"])

    def test_protected_baseline_cannot_be_deleted(self):
        res = client.delete("/api/v1/policies/POL-001")
        assert res.status_code == 400
        assert "protected baseline policy" in res.json()["detail"]

    def test_custom_policy_can_be_deleted(self):
        del_rule_id = "POL-TO-BE-DELETED"
        payload = {
            "id": del_rule_id,
            "version": "1.0.0",
            "name": "Temporary Rule",
            "description": "Will be deleted.",
            "action": "WARN",
            "priority": 10,
            "org_id": "org_temp",
            "intent_explanation": "Will be deleted",
        }
        create_res = client.post("/api/v1/policies", json=payload)
        assert create_res.status_code in (200, 201)

        del_res = client.delete(f"/api/v1/policies/{del_rule_id}")
        assert del_res.status_code == 200
        assert del_res.json()["policy_id"] == del_rule_id

        # Verify not in list
        list_res = client.get("/api/v1/policies?org_id=org_temp")
        assert not any(p["id"] == del_rule_id for p in list_res.json())
