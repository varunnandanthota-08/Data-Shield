import io
import json
import os
import sqlite3
import tempfile
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.auth.models import UserRole
from app.auth.repository import user_repo
from app.auth.security import create_access_token, hash_password
from app.auth.rate_limiter import auth_rate_limiter
from app.db.schema import init_db
from app.db.repository import policy_repo, scan_record_repo
from app.audit.service import audit_service, AuditService
from app.policy.engine import policy_engine

client = TestClient(app)

SYNTHETIC_API_KEY = "AIzaSyB_1234567890abcdefghijklmnopqrstuv"
SYNTHETIC_SSN = "123-45-6789"


@pytest.fixture(autouse=True)
def setup_tenants_and_database(monkeypatch):
    """Initializes isolated database, seeds Org Alpha and Org Beta users,
    and returns auth headers for both organizations.
    """
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(path)

    # Patch repo paths
    old_user_db = user_repo.db_path
    old_pol_db = policy_repo.db_path
    old_scan_db = scan_record_repo.db_path
    old_audit_db = audit_service.db_path

    user_repo.db_path = path
    policy_repo.db_path = path
    scan_record_repo.db_path = path
    audit_service.db_path = path

    # Reset in-memory policy engine to DB baseline policies
    policy_engine.set_rules(policy_repo.list_policies())

    auth_rate_limiter.reset_all()

    # Seed Org Alpha users
    pwd_hash = hash_password("PasswordAlpha123!")
    user_repo.create_user(
        user_id="usr_admin_alpha",
        username="admin_alpha",
        email="admin@alpha.org",
        password_hash=pwd_hash,
        role=UserRole.ADMIN.value,
        org_id="org_alpha",
    )
    user_repo.create_user(
        user_id="usr_analyst_alpha",
        username="analyst_alpha",
        email="analyst@alpha.org",
        password_hash=pwd_hash,
        role=UserRole.ANALYST.value,
        org_id="org_alpha",
    )

    # Seed Org Beta users
    pwd_hash_beta = hash_password("PasswordBeta123!")
    user_repo.create_user(
        user_id="usr_admin_beta",
        username="admin_beta",
        email="admin@beta.org",
        password_hash=pwd_hash_beta,
        role=UserRole.ADMIN.value,
        org_id="org_beta",
    )
    user_repo.create_user(
        user_id="usr_analyst_beta",
        username="analyst_beta",
        email="analyst@beta.org",
        password_hash=pwd_hash_beta,
        role=UserRole.ANALYST.value,
        org_id="org_beta",
    )

    yield {
        "db_path": path,
        "token_admin_alpha": create_access_token(user_id="usr_admin_alpha", username="admin_alpha", role="admin", org_id="org_alpha"),
        "token_analyst_alpha": create_access_token(user_id="usr_analyst_alpha", username="analyst_alpha", role="analyst", org_id="org_alpha"),
        "token_admin_beta": create_access_token(user_id="usr_admin_beta", username="admin_beta", role="admin", org_id="org_beta"),
        "token_analyst_beta": create_access_token(user_id="usr_analyst_beta", username="analyst_beta", role="analyst", org_id="org_beta"),
    }

    # Teardown
    user_repo.db_path = old_user_db
    policy_repo.db_path = old_pol_db
    scan_record_repo.db_path = old_scan_db
    audit_service.db_path = old_audit_db

    if os.path.exists(path):
        os.remove(path)


class TestMultiTenantIsolation:
    """Rigorous tests ensuring comprehensive tenant isolation across users,
    scans, audit events, policies, and authorization boundaries.
    """

    # 1. Organization A cannot list Organization B's users
    def test_01_org_a_cannot_list_org_b_users(self, setup_tenants_and_database):
        headers_alpha = {"Authorization": f"Bearer {setup_tenants_and_database['token_admin_alpha']}"}
        res = client.get("/api/v1/users", headers=headers_alpha)
        assert res.status_code == 200
        users = res.json()

        # Must only see Org Alpha users
        assert len(users) >= 2
        for u in users:
            assert u["org_id"] == "org_alpha"
            assert "beta" not in u["username"]

        # Even if Alpha Admin explicitly passes query param ?org_id=org_beta, isolation holds
        spoof_res = client.get("/api/v1/users?org_id=org_beta", headers=headers_alpha)
        assert spoof_res.status_code == 200
        spoofed_users = spoof_res.json()
        for u in spoofed_users:
            assert u["org_id"] == "org_alpha"
            assert "beta" not in u["username"]

    # 2. Organization A cannot retrieve Organization B's scan records
    def test_02_org_a_cannot_retrieve_org_b_scan_records(self, setup_tenants_and_database):
        headers_alpha = {"Authorization": f"Bearer {setup_tenants_and_database['token_analyst_alpha']}"}
        headers_beta = {"Authorization": f"Bearer {setup_tenants_and_database['token_analyst_beta']}"}

        # Beta performs a scan
        scan_payload = {
            "text": "Internal beta document with some notes.",
            "context": {"destination": "INTERNAL_SERVICE", "recipient": "INTERNAL_EMPLOYEE", "classification": "INTERNAL"},
        }
        res_beta = client.post("/api/v1/scan/text", json=scan_payload, headers=headers_beta)
        assert res_beta.status_code == 200
        beta_scan_id = res_beta.json()["scan_id"]

        # Alpha lists records -> beta_scan_id must not be present
        res_alpha_list = client.get("/api/v1/scan/records", headers=headers_alpha)
        assert res_alpha_list.status_code == 200
        alpha_items = res_alpha_list.json()["items"]
        assert not any(r["scan_id"] == beta_scan_id for r in alpha_items)

        # Alpha attempts direct access by ID -> must receive 404 Not Found
        res_alpha_get = client.get(f"/api/v1/scan/records/{beta_scan_id}", headers=headers_alpha)
        assert res_alpha_get.status_code == 404

        # Beta can successfully retrieve its own record
        res_beta_get = client.get(f"/api/v1/scan/records/{beta_scan_id}", headers=headers_beta)
        assert res_beta_get.status_code == 200
        assert res_beta_get.json()["scan_id"] == beta_scan_id

    # 3. Organization A cannot read Organization B's audit events
    def test_03_org_a_cannot_read_org_b_audit_events(self, setup_tenants_and_database):
        headers_alpha = {"Authorization": f"Bearer {setup_tenants_and_database['token_analyst_alpha']}"}
        headers_beta = {"Authorization": f"Bearer {setup_tenants_and_database['token_analyst_beta']}"}

        # Beta performs an audited action
        scan_payload = {
            "text": "Secret operational note for Beta Corp.",
            "context": {"destination": "INTERNAL_SERVICE", "recipient": "INTERNAL_EMPLOYEE", "classification": "INTERNAL"},
        }
        scan_res = client.post("/api/v1/scan/text", json=scan_payload, headers=headers_beta).json()
        beta_audit_id = scan_res["audit_event_id"]

        # Alpha queries audit events
        res_alpha_audit = client.get("/api/v1/audit/events", headers=headers_alpha)
        assert res_alpha_audit.status_code == 200
        alpha_events = res_alpha_audit.json()["items"]
        assert not any(ev["event_id"] == beta_audit_id for ev in alpha_events)
        for ev in alpha_events:
            assert ev["org_id"] == "org_alpha"

        # Beta queries audit events -> beta_audit_id is present
        res_beta_audit = client.get("/api/v1/audit/events", headers=headers_beta)
        assert res_beta_audit.status_code == 200
        beta_events = res_beta_audit.json()["items"]
        assert any(ev["event_id"] == beta_audit_id for ev in beta_events)

    # 4. Organization A cannot retrieve or modify Organization B's policies
    def test_04_org_a_cannot_retrieve_or_modify_org_b_policies(self, setup_tenants_and_database):
        headers_alpha_admin = {"Authorization": f"Bearer {setup_tenants_and_database['token_admin_alpha']}"}
        headers_beta_admin = {"Authorization": f"Bearer {setup_tenants_and_database['token_admin_beta']}"}

        # Beta creates a custom policy
        beta_rule = {
            "id": "POL-BETA-CONFIDENTIAL",
            "version": "1.0.0",
            "name": "Beta Confidential Policy",
            "description": "Restricts Beta internal docs",
            "enabled": True,
            "action": "BLOCK",
            "priority": 75,
            "applicable_categories": ["PII"],
            "applicable_sensitivities": ["INTERNAL"],
            "target_destinations": ["INTERNAL_SERVICE"],
            "target_recipients": ["INTERNAL_EMPLOYEE"],
            "intent_explanation": "Beta strict internal policy",
        }
        create_res = client.post("/api/v1/policies", json=beta_rule, headers=headers_beta_admin)
        assert create_res.status_code == 201

        # Alpha lists policies -> must NOT contain Beta policy
        list_alpha = client.get("/api/v1/policies", headers=headers_alpha_admin).json()
        assert not any(p["id"] == "POL-BETA-CONFIDENTIAL" for p in list_alpha)

        # Alpha attempts to GET Beta policy by ID -> 404 Not Found
        get_alpha = client.get("/api/v1/policies/POL-BETA-CONFIDENTIAL", headers=headers_alpha_admin)
        assert get_alpha.status_code == 404

        # Alpha attempts to toggle Beta policy -> 404 Not Found
        toggle_alpha = client.patch("/api/v1/policies/POL-BETA-CONFIDENTIAL/toggle?enabled=false", headers=headers_alpha_admin)
        assert toggle_alpha.status_code == 404

        # Alpha attempts to delete Beta policy -> 404 Not Found
        delete_alpha = client.delete("/api/v1/policies/POL-BETA-CONFIDENTIAL", headers=headers_alpha_admin)
        assert delete_alpha.status_code == 404

        # Alpha attempts to overwrite Beta policy via POST -> 404 Not Found (refuses cross-tenant overwrite)
        overwrite_payload = dict(beta_rule)
        overwrite_payload["name"] = "Malicious Alpha Overwrite"
        overwrite_res = client.post("/api/v1/policies", json=overwrite_payload, headers=headers_alpha_admin)
        assert overwrite_res.status_code in (404, 403)

    # 5. Changing an organization ID in a request cannot bypass authorization
    def test_05_client_supplied_org_id_cannot_bypass_authorization(self, setup_tenants_and_database):
        headers_alpha_admin = {"Authorization": f"Bearer {setup_tenants_and_database['token_admin_alpha']}"}

        # Alpha Admin attempts to create a policy with org_id='org_beta'
        spoofed_rule = {
            "id": "POL-ALPHA-SPOOF",
            "org_id": "org_beta",  # Attacker attempt
            "version": "1.0.0",
            "name": "Spoofed Rule",
            "description": "Attempt to create policy in Beta org",
            "enabled": True,
            "action": "BLOCK",
            "priority": 50,
            "intent_explanation": "Testing spoof prevention",
        }
        res = client.post("/api/v1/policies", json=spoofed_rule, headers=headers_alpha_admin)
        assert res.status_code == 201
        # The backend must have forced the server-verified org_id 'org_alpha'
        saved_policy = res.json()
        assert saved_policy["org_id"] == "org_alpha"
        assert saved_policy["org_id"] != "org_beta"

    # 6. Tenant policy evaluation uses only the correct tenant's rules
    def test_06_tenant_policy_evaluation_uses_only_correct_tenant_rules(self, setup_tenants_and_database):
        headers_alpha_admin = {"Authorization": f"Bearer {setup_tenants_and_database['token_admin_alpha']}"}
        headers_alpha_analyst = {"Authorization": f"Bearer {setup_tenants_and_database['token_analyst_alpha']}"}
        headers_beta_analyst = {"Authorization": f"Bearer {setup_tenants_and_database['token_analyst_beta']}"}

        # Alpha creates a custom rule: BLOCK any PII sent to INTERNAL_SERVICE
        alpha_block_rule = {
            "id": "POL-ALPHA-INTERNAL-PII",
            "version": "1.0.0",
            "name": "Alpha Block Internal PII",
            "description": "Alpha bans internal PII transfers",
            "enabled": True,
            "action": "BLOCK",
            "priority": 90,
            "applicable_categories": ["PII"],
            "applicable_sensitivities": ["INTERNAL"],
            "target_destinations": ["INTERNAL_SERVICE"],
            "target_recipients": ["INTERNAL_EMPLOYEE"],
            "intent_explanation": "Strict Alpha isolation",
        }
        client.post("/api/v1/policies", json=alpha_block_rule, headers=headers_alpha_admin)

        scan_payload = {
            "text": f"Here is employee SSN: {SYNTHETIC_SSN}",
            "context": {
                "destination": "INTERNAL_SERVICE",
                "recipient": "INTERNAL_EMPLOYEE",
                "classification": "INTERNAL",
            },
        }

        # Alpha scans -> Alpha custom policy must trigger BLOCK
        res_alpha = client.post("/api/v1/scan/text", json=scan_payload, headers=headers_alpha_analyst).json()
        assert res_alpha["policy_decision"] == "BLOCK"
        assert any(p["id"] == "POL-ALPHA-INTERNAL-PII" for p in res_alpha["triggered_policies"])

        # Beta scans the EXACT same payload -> Alpha's custom policy must NOT affect Beta
        res_beta = client.post("/api/v1/scan/text", json=scan_payload, headers=headers_beta_analyst).json()
        # Default policy allows internal PII to internal employee (POL-005 ALLOW)
        assert res_beta["policy_decision"] == "ALLOW"
        assert not any(p["id"] == "POL-ALPHA-INTERNAL-PII" for p in res_beta["triggered_policies"])

    # 7. Global baseline policy protection works as designed
    def test_07_global_baseline_policy_protection(self, setup_tenants_and_database):
        headers_alpha_admin = {"Authorization": f"Bearer {setup_tenants_and_database['token_admin_alpha']}"}

        # Alpha Admin attempts to delete baseline rule POL-001 -> 400 Bad Request
        del_res = client.delete("/api/v1/policies/POL-001", headers=headers_alpha_admin)
        assert del_res.status_code == 400

        # Alpha Admin attempts to toggle baseline rule POL-001 -> 403 Forbidden
        toggle_res = client.patch("/api/v1/policies/POL-001/toggle?enabled=false", headers=headers_alpha_admin)
        assert toggle_res.status_code == 403

        # Alpha Admin attempts to overwrite baseline rule POL-001 -> 403 Forbidden
        overwrite_payload = {
            "id": "POL-001",
            "name": "Tampered Baseline Rule",
            "description": "Downgrading to ALLOW",
            "action": "ALLOW",
            "priority": 100,
            "intent_explanation": "Malicious downgrade attempt",
        }
        post_res = client.post("/api/v1/policies", json=overwrite_payload, headers=headers_alpha_admin)
        assert post_res.status_code == 403

    # 8. Admin permissions remain limited to the appropriate organization
    def test_08_admin_permissions_limited_to_own_org(self, setup_tenants_and_database):
        headers_alpha_admin = {"Authorization": f"Bearer {setup_tenants_and_database['token_admin_alpha']}"}

        # Alpha Admin attempts to delete Beta Admin account -> 404 Not Found
        del_user = client.delete("/api/v1/users/usr_admin_beta", headers=headers_alpha_admin)
        assert del_user.status_code == 404

        # Alpha Admin attempts to update Beta Admin account -> 404 Not Found
        update_user = client.put(
            "/api/v1/users/usr_admin_beta",
            json={"role": "viewer", "is_active": False},
            headers=headers_alpha_admin,
        )
        assert update_user.status_code == 404

        # Alpha Admin attempts to create a user in Beta org
        create_user_res = client.post(
            "/api/v1/users",
            json={
                "username": "new_trojan_user",
                "email": "trojan@beta.org",
                "password": "Password123!",
                "role": "analyst",
                "org_id": "org_beta",
            },
            headers=headers_alpha_admin,
        )
        assert create_user_res.status_code == 201
        created_user = create_user_res.json()
        # Created user must be forced into org_alpha
        assert created_user["org_id"] == "org_alpha"
        assert created_user["org_id"] != "org_beta"

    # 9. Existing file scanning and Gemini fallback still work
    def test_09_file_scanning_and_gemini_fallback(self, setup_tenants_and_database):
        headers_alpha = {"Authorization": f"Bearer {setup_tenants_and_database['token_analyst_alpha']}"}

        # Upload python file with secret
        file_content = f"# config.py\nAPI_KEY = '{SYNTHETIC_API_KEY}'\n"
        files = {"file": ("config.py", io.BytesIO(file_content.encode("utf-8")), "text/plain")}
        data = {
            "destination": "PUBLIC_LLM",
            "recipient": "PUBLIC",
            "classification": "RESTRICTED",
        }

        res = client.post("/api/v1/scan/file", files=files, data=data, headers=headers_alpha)
        assert res.status_code == 200
        scan_data = res.json()

        assert scan_data["policy_decision"] == "BLOCK"
        assert scan_data["risk_band"] in ("HIGH", "CRITICAL")
        assert scan_data["context"]["org_id"] == "org_alpha"
        assert scan_data["ai_analysis"] is not None
        assert scan_data["ai_analysis"]["ai_status"] in ("SUCCESS", "FALLBACK", "UNAVAILABLE")
        assert "model_identifier" in scan_data["ai_analysis"]

    # 10. Mandatory BLOCK decisions cannot be downgraded
    def test_10_mandatory_block_decisions_cannot_be_downgraded(self, setup_tenants_and_database):
        headers_beta_admin = {"Authorization": f"Bearer {setup_tenants_and_database['token_admin_beta']}"}
        headers_beta_analyst = {"Authorization": f"Bearer {setup_tenants_and_database['token_analyst_beta']}"}

        # Beta admin creates an ALLOW policy with priority 100 for API keys to PUBLIC_LLM
        allow_rule = {
            "id": "POL-BETA-ALLOW-EVERYTHING",
            "version": "1.0.0",
            "name": "Beta Allow All Keys",
            "description": "Attempting to bypass security",
            "enabled": True,
            "action": "ALLOW",
            "priority": 100,
            "applicable_categories": ["SECRET"],
            "target_destinations": ["PUBLIC_LLM"],
            "intent_explanation": "Testing bypass resistance",
        }
        client.post("/api/v1/policies", json=allow_rule, headers=headers_beta_admin)

        # Scan text with API key to PUBLIC_LLM
        scan_payload = {
            "text": f"Exposing key {SYNTHETIC_API_KEY} to public LLM.",
            "context": {
                "destination": "PUBLIC_LLM",
                "recipient": "PUBLIC",
                "classification": "RESTRICTED",
            },
        }
        res = client.post("/api/v1/scan/text", json=scan_payload, headers=headers_beta_analyst).json()
        # Even with an ALLOW policy priority 100, POL-001 mandatory hard BLOCK must prevail!
        assert res["policy_decision"] == "BLOCK"
        assert res["risk_band"] in ("HIGH", "CRITICAL")

    # 11. Existing audit-chain integrity remains valid
    def test_11_audit_chain_integrity_remains_valid(self, setup_tenants_and_database):
        headers_alpha = {"Authorization": f"Bearer {setup_tenants_and_database['token_analyst_alpha']}"}
        headers_beta = {"Authorization": f"Bearer {setup_tenants_and_database['token_analyst_beta']}"}

        # Interleave scans from Alpha and Beta
        client.post("/api/v1/scan/text", json={"text": "Alpha record 1"}, headers=headers_alpha)
        client.post("/api/v1/scan/text", json={"text": "Beta record 1"}, headers=headers_beta)
        client.post("/api/v1/scan/text", json={"text": "Alpha record 2"}, headers=headers_alpha)

        # Alpha verifies its audit chain
        verif_alpha = client.get("/api/v1/audit/verify", headers=headers_alpha).json()
        assert verif_alpha["is_valid"] is True
        assert verif_alpha["total_events"] >= 2
        assert verif_alpha["verified_events"] >= 2
        assert verif_alpha["tampered_event_id"] is None

        # Beta verifies its audit chain
        verif_beta = client.get("/api/v1/audit/verify", headers=headers_beta).json()
        assert verif_beta["is_valid"] is True
        assert verif_beta["total_events"] >= 1
        assert verif_beta["verified_events"] >= 1
        assert verif_beta["tampered_event_id"] is None

    # 12. Database migration preserves existing records
    def test_12_database_migration_preserves_existing_records(self):
        """Simulates an existing pre-Phase 3 database without org_id columns
        and verifies init_db() migrates the schema while preserving all existing data.
        """
        fd, legacy_db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)

        # Create legacy tables without org_id columns
        conn = sqlite3.connect(legacy_db_path)
        conn.execute("""
            CREATE TABLE policies (
                id TEXT PRIMARY KEY,
                version TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                action TEXT NOT NULL,
                priority INTEGER NOT NULL DEFAULT 10,
                applicable_categories TEXT NOT NULL DEFAULT '[]',
                applicable_sensitivities TEXT NOT NULL DEFAULT '[]',
                target_destinations TEXT NOT NULL DEFAULT '[]',
                target_recipients TEXT NOT NULL DEFAULT '[]',
                intent_explanation TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
        """)
        conn.execute("""
            CREATE TABLE scan_records (
                scan_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                destination TEXT NOT NULL,
                recipient TEXT NOT NULL,
                classification TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_band TEXT NOT NULL,
                final_decision TEXT NOT NULL,
                finding_count INTEGER NOT NULL,
                categories_detected TEXT NOT NULL,
                processing_duration_ms REAL NOT NULL
            );
        """)
        conn.execute("""
            CREATE TABLE audit_events (
                event_id TEXT PRIMARY KEY,
                sequence_number INTEGER NOT NULL UNIQUE,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                scan_id TEXT,
                actor_id TEXT,
                policy_decision TEXT,
                policy_references TEXT NOT NULL DEFAULT '[]',
                sanitized_metadata TEXT NOT NULL DEFAULT '{}',
                prev_event_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL
            );
        """)

        # Insert legacy pre-existing record
        conn.execute("""
            INSERT INTO scan_records VALUES (
                'legacy-scan-001', '2026-01-01T00:00:00Z', 'legacy_user', 'INTERNAL_SERVICE',
                'INTERNAL_EMPLOYEE', 'INTERNAL', 10, 'LOW', 'ALLOW', 0, '[]', 15.0
            );
        """)
        conn.commit()
        conn.close()

        # Run init_db migration on the legacy database
        init_db(legacy_db_path)

        # Verify columns exist and data preserved with default 'default' org_id
        migrated_conn = sqlite3.connect(legacy_db_path)
        migrated_conn.row_factory = sqlite3.Row
        cur = migrated_conn.cursor()

        # Check policies column
        cur.execute("PRAGMA table_info(policies)")
        assert any(c["name"] == "org_id" for c in cur.fetchall())

        # Check scan_records column and pre-existing record preservation
        cur.execute("PRAGMA table_info(scan_records)")
        assert any(c["name"] == "org_id" for c in cur.fetchall())

        cur.execute("SELECT * FROM scan_records WHERE scan_id = 'legacy-scan-001'")
        legacy_row = cur.fetchone()
        assert legacy_row is not None
        assert legacy_row["scan_id"] == "legacy-scan-001"
        assert legacy_row["org_id"] == "default"  # Successfully defaulted without data loss

        # Check audit_events column
        cur.execute("PRAGMA table_info(audit_events)")
        assert any(c["name"] == "org_id" for c in cur.fetchall())

        migrated_conn.close()
        if os.path.exists(legacy_db_path):
            os.remove(legacy_db_path)
