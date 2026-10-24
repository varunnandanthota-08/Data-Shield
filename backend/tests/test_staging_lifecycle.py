import os
import sqlite3
import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.db.connection import get_db_path, get_connection
from app.db.schema import init_db
from app.audit.service import AuditService
from app.auth.security import create_access_token, decode_access_token


@pytest.fixture
def staging_env(tmp_path, monkeypatch):
    """Sets up a fully isolated staging environment with a temporary staging SQLite database."""
    staging_db = str(tmp_path / "datashield_staging_test.db")
    from app.core.config import settings
    monkeypatch.setattr(settings, "ENVIRONMENT", "staging")
    monkeypatch.setattr(settings, "DEBUG", False)
    monkeypatch.setattr(settings, "SQLITE_DB_PATH", staging_db)
    monkeypatch.setattr(settings, "ALLOW_PUBLIC_REGISTRATION", False)
    monkeypatch.setattr(
        settings,
        "JWT_SECRET_KEY",
        "staging-test-key-at-least-32-chars-long-secure-random-2026",
    )

    init_db(db_path=staging_db)

    from app.main import app
    from app.auth.rate_limiter import auth_rate_limiter, scan_rate_limiter

    auth_rate_limiter.reset_all()
    scan_rate_limiter.reset_all()

    # Clear dependency overrides to test genuine authentication and RBAC
    app.dependency_overrides.clear()

    client = TestClient(app)
    return {
        "client": client,
        "db_path": staging_db,
        "settings": settings,
        "app": app,
    }


class TestStagingEndToEndWorkflow:
    """Validates the complete staging application workflow."""

    def test_complete_staging_lifecycle(self, staging_env):
        client = staging_env["client"]
        db_path = staging_env["db_path"]

        # 1. Health readiness probe reports resolved staging db path
        resp = client.get("/api/health/ready")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ready"
        assert data["database"] == "connected"
        assert os.path.normpath(data["resolved_db_path"]) == os.path.normpath(db_path)

        # 2. Check bootstrap status (must be True for empty database)
        resp = client.get("/api/v1/auth/bootstrap-status")
        assert resp.status_code == 200
        assert resp.json()["requires_bootstrap"] is True

        # 3. Public registration is disabled by policy
        reg_resp = client.post(
            "/api/v1/auth/register",
            json={
                "username": "intruder_user",
                "email": "intruder@domain.com",
                "password": "Password123!Secure",
            },
        )
        assert reg_resp.status_code == 403
        assert "disabled by enterprise security policy" in reg_resp.json()["detail"]

        # 4. Administrator Bootstrap Setup
        setup_resp = client.post(
            "/api/v1/auth/setup-admin",
            json={
                "username": "staging_admin",
                "email": "admin@staging.datashield.ai",
                "password": "StagingAdminPassword2026!",
            },
        )
        assert setup_resp.status_code == 201
        admin_tokens = setup_resp.json()
        admin_token = admin_tokens["access_token"]
        assert admin_token is not None
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        # Verify bootstrap is now permanently locked down
        locked_resp = client.post(
            "/api/v1/auth/setup-admin",
            json={
                "username": "second_admin",
                "email": "second@staging.datashield.ai",
                "password": "Password123!",
            },
        )
        assert locked_resp.status_code == 403

        # 5. Dashboard loading immediately without manual refresh
        overview_resp = client.get("/api/v1/scan/records?limit=10", headers=admin_headers)
        assert overview_resp.status_code == 200
        assert overview_resp.json()["total"] == 0

        # 6. Administrator user provisioning (creating an Analyst user)
        create_user_resp = client.post(
            "/api/v1/users",
            headers=admin_headers,
            json={
                "username": "staging_analyst",
                "email": "analyst@staging.datashield.ai",
                "password": "AnalystPassword2026!",
                "role": "analyst",
                "org_id": "default",
            },
        )
        assert create_user_resp.status_code == 201
        created_analyst = create_user_resp.json()
        assert created_analyst["role"] == "analyst"

        # 7. Analyst login
        analyst_login_resp = client.post(
            "/api/v1/auth/login",
            json={
                "username": "staging_analyst",
                "password": "AnalystPassword2026!",
            },
        )
        assert analyst_login_resp.status_code == 200
        analyst_token = analyst_login_resp.json()["access_token"]
        analyst_headers = {"Authorization": f"Bearer {analyst_token}"}

        # 8. Role enforcement: Analyst cannot create users (Admin only)
        forbidden_resp = client.post(
            "/api/v1/users",
            headers=analyst_headers,
            json={
                "username": "rogue_user",
                "email": "rogue@staging.datashield.local",
                "password": "Password123!",
                "role": "admin",
            },
        )
        assert forbidden_resp.status_code == 403

        # 9. Text Scan & Policy Enforcement
        scan_payload = {
            "text": "AWS_KEY = AKIAIOSFODNN7EXAMPLE and customer email jane.doe@corporate.com",
            "context": {
                "destination": "PUBLIC_LLM",
                "recipient": "PUBLIC",
                "classification": "CONFIDENTIAL",
                "actor_id": "staging_analyst",
            },
        }
        scan_resp = client.post("/api/v1/scan/text", headers=analyst_headers, json=scan_payload)
        assert scan_resp.status_code == 200
        scan_data = scan_resp.json()
        assert scan_data["policy_decision"] == "BLOCK"
        assert len(scan_data["findings"]) >= 2
        # Ensure raw secret is not in findings
        for f in scan_data["findings"]:
            assert "AKIAIOSFODNN7EXAMPLE" not in f.get("masked_evidence", "")
        # Redaction verified
        assert "AKIAIOSFODNN7EXAMPLE" not in scan_data["redacted_text"]

        # 10. Scan history persistence
        history_resp = client.get("/api/v1/scan/records", headers=analyst_headers)
        assert history_resp.status_code == 200
        records = history_resp.json()["items"]
        assert len(records) >= 1
        assert records[0]["final_decision"] == "BLOCK"

        # 11. Audit-chain cryptographic verification
        audit_resp = client.get("/api/v1/audit/verify", headers=admin_headers)
        assert audit_resp.status_code == 200
        audit_data = audit_resp.json()
        assert audit_data["is_valid"] is True
        assert audit_data["verified_events"] >= 1
        assert audit_data["errors"] == []

        # 12. Logout and revoked-session behavior
        logout_resp = client.post("/api/v1/auth/logout", headers=analyst_headers)
        assert logout_resp.status_code == 200

        # Attempt to reuse revoked token must be rejected with 401
        revoked_resp = client.get("/api/v1/scan/records", headers=analyst_headers)
        assert revoked_resp.status_code == 401
        assert "revoked" in revoked_resp.json()["detail"].lower()

        # 13. Application restart & database persistence
        # Re-verify through direct SQLite connection that data persisted
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM users")
        user_count = c.fetchone()[0]
        assert user_count == 2  # admin + analyst

        c.execute("SELECT COUNT(*) FROM scan_records")
        scan_count = c.fetchone()[0]
        assert scan_count == 1

        c.execute("SELECT COUNT(*) FROM audit_events")
        audit_count = c.fetchone()[0]
        assert audit_count >= 1

        c.execute("SELECT COUNT(*) FROM revoked_tokens")
        revoked_count = c.fetchone()[0]
        assert revoked_count == 1
        conn.close()

        # Final audit chain verification via AuditService directly
        audit_service = AuditService(db_path=db_path)
        chain_result = audit_service.verify_chain(org_id="default")
        assert chain_result.is_valid is True
        assert chain_result.verified_events == audit_count
