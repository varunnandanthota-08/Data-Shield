import io
import json
import os
import tempfile
import time
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from typing import Dict, List
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import settings
from app.auth.models import UserRole
from app.auth.repository import UserRepository, TokenRevocationRepository
from app.auth.security import (
    create_access_token,
    decode_access_token,
    generate_csrf_token,
    hash_password,
    verify_password,
)
from app.auth.rate_limiter import scan_rate_limiter, auth_rate_limiter
from app.audit.service import AuditService, compute_event_hash
from app.db.schema import init_db
from app.db.repository import PolicyRepository, ScanRecordRepository
from app.policy.engine import policy_engine
from app.policy.schemas import (
    DataClassification,
    DestinationType,
    PolicyAction,
    PolicyRule,
    RecipientType,
    SharingContext,
)
from app.engine.schemas import ConfidenceBand, Finding, FindingCategory, ScanResponse, SeverityLevel

client = TestClient(app)


# ---------------------------------------------------------------------------
# Test Fixture: Isolated Temporary Database for Phase 5 E2E Acceptance
# ---------------------------------------------------------------------------

@pytest.fixture
def e2e_env():
    fd, path = tempfile.mkstemp(suffix="_e2e.db")
    os.close(fd)
    init_db(path)

    u_repo = UserRepository(db_path=path)
    t_repo = TokenRevocationRepository(db_path=path)
    p_repo = PolicyRepository(db_path=path)
    s_repo = ScanRecordRepository(db_path=path)
    a_svc = AuditService(db_path=path)

    # Patch module repositories to use this isolated database
    from app.auth import repository as auth_repo_mod
    from app.auth import dependencies as auth_dep_mod
    from app.api.routes import auth as auth_route_mod
    from app.api.routes import users as user_route_mod
    from app.api.routes import policies as policy_route_mod
    from app.api.routes import scan as scan_route_mod
    from app.api.routes import audit as audit_route_mod

    orig_u_repo = auth_repo_mod.user_repo
    orig_t_repo = auth_repo_mod.token_revocation_repo
    orig_dep_u = auth_dep_mod.user_repo
    orig_dep_t = auth_dep_mod.token_revocation_repo
    orig_route_u = auth_route_mod.user_repo
    orig_route_t = auth_route_mod.token_revocation_repo
    orig_user_route_u = user_route_mod.user_repo
    orig_p_repo = policy_route_mod.policy_repo
    orig_s_repo = scan_route_mod.scan_record_repo
    orig_scan_audit = scan_route_mod.audit_service
    orig_audit_svc = audit_route_mod.audit_service

    auth_repo_mod.user_repo = u_repo
    auth_repo_mod.token_revocation_repo = t_repo
    auth_dep_mod.user_repo = u_repo
    auth_dep_mod.token_revocation_repo = t_repo
    auth_route_mod.user_repo = u_repo
    auth_route_mod.token_revocation_repo = t_repo
    user_route_mod.user_repo = u_repo
    policy_route_mod.policy_repo = p_repo
    scan_route_mod.scan_record_repo = s_repo
    scan_route_mod.audit_service = a_svc
    audit_route_mod.audit_service = a_svc

    from app.auth.rate_limiter import SqliteRateLimiterStorage
    sqlite_storage = SqliteRateLimiterStorage(db_path=path)
    orig_auth_limiter_storage = auth_rate_limiter._storage
    orig_scan_limiter_storage = scan_rate_limiter._storage
    auth_rate_limiter.set_storage(sqlite_storage)
    scan_rate_limiter.set_storage(sqlite_storage)

    # Synchronize policy engine with isolated DB
    orig_policy_rules = policy_engine.rules
    policy_engine.set_rules(p_repo.list_policies())
    scan_rate_limiter.reset_all()
    auth_rate_limiter.reset_all()

    yield {
        "user_repo": u_repo,
        "token_repo": t_repo,
        "policy_repo": p_repo,
        "scan_repo": s_repo,
        "audit_service": a_svc,
        "db_path": path,
    }

    # Teardown: restore originals
    auth_repo_mod.user_repo = orig_u_repo
    auth_repo_mod.token_revocation_repo = orig_t_repo
    auth_dep_mod.user_repo = orig_dep_u
    auth_dep_mod.token_revocation_repo = orig_dep_t
    auth_route_mod.user_repo = orig_route_u
    auth_route_mod.token_revocation_repo = orig_route_t
    user_route_mod.user_repo = orig_user_route_u
    policy_route_mod.policy_repo = orig_p_repo
    scan_route_mod.scan_record_repo = orig_s_repo
    scan_route_mod.audit_service = orig_scan_audit
    audit_route_mod.audit_service = orig_audit_svc

    policy_engine.set_rules(orig_policy_rules)
    sqlite_storage.reset_all()
    auth_rate_limiter.set_storage(orig_auth_limiter_storage)
    scan_rate_limiter.set_storage(orig_scan_limiter_storage)

    if os.path.exists(path):
        os.remove(path)


# Helper to generate test DOCX bytes
def create_dummy_docx(text_content: str) -> bytes:
    import docx
    doc = docx.Document()
    doc.add_paragraph(text_content)
    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


# Helper to generate test PDF bytes
def create_dummy_pdf(text_content: str) -> bytes:
    clean_line = text_content.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    stream_content = f"BT\n/F1 12 Tf\n50 700 Td\n({clean_line}) Tj\nET\n".encode("latin-1")
    stream_len = len(stream_content)

    pdf = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n"
        b"4 0 obj\n<< /Length " + str(stream_len).encode("ascii") + b" >>\nstream\n"
        + stream_content +
        b"endstream\nendobj\n"
        b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"
        b"xref\n0 6\n"
        b"0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"0000000058 00000 n \n"
        b"0000000115 00000 n \n"
        b"0000000224 00000 n \n"
        b"0000000348 00000 n \n"
        b"trailer\n<< /Size 6 /Root 1 0 R >>\n"
        b"startxref\n450\n%%EOF\n"
    )
    return pdf


# ---------------------------------------------------------------------------
# Section 2: Authentication and RBAC Verification
# ---------------------------------------------------------------------------

class TestPhase5AuthAndRBAC:
    def test_bootstrap_initial_admin_safely(self, e2e_env):
        # 1. Zero users initially
        res_status = client.get("/api/v1/auth/bootstrap-status")
        assert res_status.status_code == 200
        assert res_status.json()["requires_bootstrap"] is True

        # 2. Bootstrap setup-admin
        res_setup = client.post(
            "/api/v1/auth/setup-admin",
            json={
                "username": "superadmin",
                "email": "superadmin@datashield.ai",
                "password": "InitialAdminPassword2026!",
            },
        )
        assert res_setup.status_code == 201
        data = res_setup.json()
        assert "access_token" in data
        assert data["user"]["role"] == "admin"
        assert data["user"]["org_id"] == "default"

        # 3. Second bootstrap attempt must be rejected permanently
        res_second = client.post(
            "/api/v1/auth/setup-admin",
            json={
                "username": "attacker",
                "email": "attacker@datashield.ai",
                "password": "AnotherPassword2026!",
            },
        )
        assert res_second.status_code == 403
        assert "already bootstrapped" in res_second.json()["detail"].lower()

    def test_login_and_logout_revocation_lifecycle(self, e2e_env):
        u_repo = e2e_env["user_repo"]
        pwd = "TestValidPassword2026!"
        user = u_repo.create_user(
            username="analyst_alice",
            email="alice@datashield.test",
            password_hash=hash_password(pwd),
            role=UserRole.ANALYST.value,
            org_id="org_alpha",
        )

        # 1. Reject invalid password
        res_bad_pwd = client.post(
            "/api/v1/auth/login",
            json={"username": "analyst_alice", "password": "WrongPassword123!"},
        )
        assert res_bad_pwd.status_code == 401
        assert "invalid username or password" in res_bad_pwd.json()["detail"].lower()

        # 2. Reject non-existent user with identical error message
        res_no_user = client.post(
            "/api/v1/auth/login",
            json={"username": "non_existent_user_999", "password": pwd},
        )
        assert res_no_user.status_code == 401
        assert "invalid username or password" in res_no_user.json()["detail"].lower()

        # 3. Valid login succeeds
        res_login = client.post(
            "/api/v1/auth/login",
            json={"username": "analyst_alice", "password": pwd},
        )
        assert res_login.status_code == 200
        token = res_login.json()["access_token"]

        # 4. Access protected profile
        res_me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert res_me.status_code == 200
        assert res_me.json()["username"] == "analyst_alice"

        # 5. Logout revokes token
        res_logout = client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})
        assert res_logout.status_code == 200

        # 6. Subsequent call with revoked token returns 401
        res_revoked = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert res_revoked.status_code == 401
        assert "revoked" in res_revoked.json()["detail"].lower()

    def test_inactive_user_cannot_access_protected_endpoints(self, e2e_env):
        u_repo = e2e_env["user_repo"]
        user = u_repo.create_user(
            username="inactive_bob",
            email="bob@datashield.test",
            password_hash=hash_password("Password123!"),
            role=UserRole.ANALYST.value,
            org_id="org_alpha",
        )
        token = create_access_token(
            user_id=user["id"],
            username=user["username"],
            role=user["role"],
            org_id=user["org_id"],
        )

        # Deactivate user
        u_repo.update_user(user["id"], is_active=False)

        res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert res.status_code == 401

    def test_rbac_access_matrix_enforcement(self, e2e_env):
        u_repo = e2e_env["user_repo"]
        # Provision Admin, Analyst, and Viewer in org_alpha
        admin = u_repo.create_user("adm", "adm@test.local", hash_password("P!"), UserRole.ADMIN.value, "org_alpha")
        analyst = u_repo.create_user("ana", "ana@test.local", hash_password("P!"), UserRole.ANALYST.value, "org_alpha")
        viewer = u_repo.create_user("viw", "viw@test.local", hash_password("P!"), UserRole.VIEWER.value, "org_alpha")

        tok_admin = create_access_token(admin["id"], admin["username"], admin["role"], admin["org_id"])
        tok_analyst = create_access_token(analyst["id"], analyst["username"], analyst["role"], analyst["org_id"])
        tok_viewer = create_access_token(viewer["id"], viewer["username"], viewer["role"], viewer["org_id"])

        # 1. User Management (/api/v1/users) -> Admin only
        assert client.get("/api/v1/users", headers={"Authorization": f"Bearer {tok_admin}"}).status_code == 200
        assert client.get("/api/v1/users", headers={"Authorization": f"Bearer {tok_analyst}"}).status_code == 403
        assert client.get("/api/v1/users", headers={"Authorization": f"Bearer {tok_viewer}"}).status_code == 403

        # 2. Audit Trail (/api/v1/audit/events) -> Admin & Analyst only
        assert client.get("/api/v1/audit/events", headers={"Authorization": f"Bearer {tok_admin}"}).status_code == 200
        assert client.get("/api/v1/audit/events", headers={"Authorization": f"Bearer {tok_analyst}"}).status_code == 200
        assert client.get("/api/v1/audit/events", headers={"Authorization": f"Bearer {tok_viewer}"}).status_code == 403

        # 3. Scanning (/api/v1/scan/text) -> Admin & Analyst only
        scan_body = {"text": "Clean payload for RBAC check"}
        assert client.post("/api/v1/scan/text", headers={"Authorization": f"Bearer {tok_admin}"}, json=scan_body).status_code == 200
        assert client.post("/api/v1/scan/text", headers={"Authorization": f"Bearer {tok_analyst}"}, json=scan_body).status_code == 200
        assert client.post("/api/v1/scan/text", headers={"Authorization": f"Bearer {tok_viewer}"}, json=scan_body).status_code == 403

        # 4. Policies Read (/api/v1/policies) -> Admin, Analyst, and Viewer
        assert client.get("/api/v1/policies", headers={"Authorization": f"Bearer {tok_admin}"}).status_code == 200
        assert client.get("/api/v1/policies", headers={"Authorization": f"Bearer {tok_analyst}"}).status_code == 200
        assert client.get("/api/v1/policies", headers={"Authorization": f"Bearer {tok_viewer}"}).status_code == 200

        # 5. Policy Modification (/api/v1/policies/POL-001/toggle) -> Admin only
        assert client.patch("/api/v1/policies/POL-001/toggle", headers={"Authorization": f"Bearer {tok_analyst}"}).status_code == 403
        assert client.patch("/api/v1/policies/POL-001/toggle", headers={"Authorization": f"Bearer {tok_viewer}"}).status_code == 403


# ---------------------------------------------------------------------------
# Section 3: Tenant Isolation Verification (Org Alpha vs Org Beta)
# ---------------------------------------------------------------------------

class TestPhase5TenantIsolation:
    def test_strict_cross_organization_isolation(self, e2e_env):
        u_repo = e2e_env["user_repo"]
        # Org Alpha & Beta users
        user_alpha = u_repo.create_user("alpha_lead", "alpha@t.com", hash_password("P!"), UserRole.ADMIN.value, "org_alpha")
        user_beta = u_repo.create_user("beta_lead", "beta@t.com", hash_password("P!"), UserRole.ADMIN.value, "org_beta")

        tok_alpha = create_access_token(user_alpha["id"], user_alpha["username"], user_alpha["role"], user_alpha["org_id"])
        tok_beta = create_access_token(user_beta["id"], user_beta["username"], user_beta["role"], user_beta["org_id"])

        # 1. Org Alpha executes scan
        res_scan_alpha = client.post(
            "/api/v1/scan/text",
            headers={"Authorization": f"Bearer {tok_alpha}"},
            json={"text": "Confidential Alpha internal project details"},
        )
        assert res_scan_alpha.status_code == 200
        scan_id_alpha = res_scan_alpha.json()["scan_id"]

        # 2. Org Beta CANNOT retrieve Org Alpha scan record by ID (IDOR prevention)
        res_idor = client.get(
            f"/api/v1/scan/records/{scan_id_alpha}",
            headers={"Authorization": f"Bearer {tok_beta}"},
        )
        assert res_idor.status_code == 404

        # 3. Org Beta scan listing contains zero Org Alpha scans
        res_beta_list = client.get("/api/v1/scan/records", headers={"Authorization": f"Bearer {tok_beta}"})
        assert res_beta_list.status_code == 200
        beta_scan_ids = [s["scan_id"] for s in res_beta_list.json()["items"]]
        assert scan_id_alpha not in beta_scan_ids

        # 4. Org Alpha creates custom policy
        custom_pol = {
            "id": "POL-ALPHA-CUSTOM",
            "name": "Alpha Strict Customer Data Rule",
            "description": "Custom block rule for Alpha",
            "action": "BLOCK",
            "priority": 30,
            "applicable_categories": ["PII"],
            "applicable_sensitivities": ["CONFIDENTIAL"],
            "target_destinations": ["PUBLIC_LLM"],
            "target_recipients": ["PUBLIC"],
            "intent_explanation": "Protects customer identifiers in Alpha cloud apps",
        }
        res_create_pol = client.post(
            "/api/v1/policies",
            headers={"Authorization": f"Bearer {tok_alpha}"},
            json=custom_pol,
        )
        assert res_create_pol.status_code in (200, 201)

        # 5. Org Beta CANNOT retrieve or toggle Org Alpha policy
        res_beta_get_pol = client.get("/api/v1/policies/POL-ALPHA-CUSTOM", headers={"Authorization": f"Bearer {tok_beta}"})
        assert res_beta_get_pol.status_code == 404

        res_beta_toggle = client.patch(
            "/api/v1/policies/POL-ALPHA-CUSTOM/toggle",
            headers={"Authorization": f"Bearer {tok_beta}"},
        )
        assert res_beta_toggle.status_code == 404

        # 6. Tenant Admin cannot modify or disable global baseline policy
        res_mod_baseline = client.patch(
            "/api/v1/policies/POL-001/toggle",
            headers={"Authorization": f"Bearer {tok_alpha}"},
        )
        assert res_mod_baseline.status_code == 403

        # 7. Changing client org_id in request body cannot override authenticated identity
        res_spoof = client.post(
            "/api/v1/scan/text",
            headers={"Authorization": f"Bearer {tok_alpha}"},
            json={
                "text": "Clean payload",
                "context": {
                    "destination": "INTERNAL_SERVICE",
                    "recipient": "INTERNAL_EMPLOYEE",
                    "classification": "INTERNAL",
                    "org_id": "org_beta",  # Attacker attempts to spoof org_beta
                },
            },
        )
        assert res_spoof.status_code == 200
        # Verified server-side: stamped with caller's verified org_alpha
        assert res_spoof.json()["context"]["org_id"] == "org_alpha"


# ---------------------------------------------------------------------------
# Section 4: Comprehensive Text and File Scanning
# ---------------------------------------------------------------------------

class TestPhase5ScanningWorkflows:
    def test_clean_text_allowed(self, e2e_env):
        u_repo = e2e_env["user_repo"]
        user = u_repo.create_user("scanner_1", "s1@test.com", hash_password("P!"), UserRole.ANALYST.value, "org_alpha")
        tok = create_access_token(user["id"], user["username"], user["role"], user["org_id"])

        res = client.post(
            "/api/v1/scan/text",
            headers={"Authorization": f"Bearer {tok}"},
            json={
                "text": "Routine weekly engineering status: all unit tests passing smoothly.",
                "context": {
                    "destination": DestinationType.INTERNAL_SERVICE.value,
                    "recipient": RecipientType.INTERNAL_EMPLOYEE.value,
                    "classification": DataClassification.INTERNAL.value,
                },
            },
        )
        assert res.status_code == 200
        data = res.json()
        assert data["policy_decision"] == "ALLOW"
        assert data["risk_band"] == "LOW"
        assert len(data["findings"]) == 0

    def test_synthetic_secrets_hard_blocked(self, e2e_env):
        u_repo = e2e_env["user_repo"]
        user = u_repo.create_user("scanner_2", "s2@test.com", hash_password("P!"), UserRole.ANALYST.value, "org_alpha")
        tok = create_access_token(user["id"], user["username"], user["role"], user["org_id"])

        # Synthetic AWS Key
        text = "Emergency credentials: AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE for quick sync"
        res = client.post(
            "/api/v1/scan/text",
            headers={"Authorization": f"Bearer {tok}"},
            json={
                "text": text,
                "context": {
                    "destination": DestinationType.PUBLIC_LLM.value,
                    "recipient": RecipientType.PUBLIC.value,
                    "classification": DataClassification.CONFIDENTIAL.value,
                },
            },
        )
        assert res.status_code == 200
        data = res.json()
        assert data["policy_decision"] == "BLOCK"
        assert data["risk_band"] == "CRITICAL"
        assert "AKIAIOSFODNN7EXAMPLE" not in data["redacted_text"]

    def test_supported_file_types_scanning(self, e2e_env):
        u_repo = e2e_env["user_repo"]
        user = u_repo.create_user("scanner_files", "sf@test.com", hash_password("P!"), UserRole.ANALYST.value, "org_alpha")
        tok = create_access_token(user["id"], user["username"], user["role"], user["org_id"])

        files_to_test = [
            ("config.env", b"DATABASE_URL=postgres://user:pass@db:5432\nAPI_KEY=AKIAIOSFODNN7EXAMPLE\n", "text/plain"),
            ("export.csv", b"id,name,secret\n1,alpha,AKIAIOSFODNN7EXAMPLE\n", "text/csv"),
            ("payload.json", json.dumps({"token": "AKIAIOSFODNN7EXAMPLE"}).encode("utf-8"), "application/json"),
            ("document.txt", b"Plain text containing secret AKIAIOSFODNN7EXAMPLE", "text/plain"),
            ("report.docx", create_dummy_docx("Sensitive DOCX text with AKIAIOSFODNN7EXAMPLE"), "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
            ("audit.pdf", create_dummy_pdf("Sensitive PDF text with AKIAIOSFODNN7EXAMPLE"), "application/pdf"),
        ]

        for fname, content, ctype in files_to_test:
            res = client.post(
                "/api/v1/scan/file",
                headers={"Authorization": f"Bearer {tok}"},
                files={"file": (fname, content, ctype)},
                data={
                    "destination": DestinationType.PUBLIC_LLM.value,
                    "recipient": RecipientType.PUBLIC.value,
                    "classification": DataClassification.CONFIDENTIAL.value,
                },
            )
            assert res.status_code == 200, f"File {fname} failed scan with {res.status_code}"
            data = res.json()
            assert data["policy_decision"] == "BLOCK", f"File {fname} did not enforce BLOCK"
            assert "AKIAIOSFODNN7EXAMPLE" not in data["redacted_text"]

    def test_unsupported_and_oversized_file_rejection(self, e2e_env):
        u_repo = e2e_env["user_repo"]
        user = u_repo.create_user("scanner_edge", "se@test.com", hash_password("P!"), UserRole.ANALYST.value, "org_alpha")
        tok = create_access_token(user["id"], user["username"], user["role"], user["org_id"])

        # 1. Unsupported executable
        res_exe = client.post(
            "/api/v1/scan/file",
            headers={"Authorization": f"Bearer {tok}"},
            files={"file": ("malware.exe", b"MZexecutablebytes", "application/octet-stream")},
        )
        assert res_exe.status_code == 400

        # 2. Empty file
        res_empty = client.post(
            "/api/v1/scan/file",
            headers={"Authorization": f"Bearer {tok}"},
            files={"file": ("empty.txt", b"", "text/plain")},
        )
        assert res_empty.status_code == 400

        # 3. Oversized file (> 5 MB)
        oversized = b"X" * (settings.MAX_UPLOAD_SIZE_BYTES + 4096)
        res_large = client.post(
            "/api/v1/scan/file",
            headers={"Authorization": f"Bearer {tok}"},
            files={"file": ("large.txt", oversized, "text/plain")},
        )
        assert res_large.status_code == 413


# ---------------------------------------------------------------------------
# Section 5: Gemini Failure Behavior and Boundary Invariance
# ---------------------------------------------------------------------------

class TestPhase5GeminiDegradation:
    def test_gemini_timeout_or_error_preserves_deterministic_blocking(self, monkeypatch, e2e_env):
        u_repo = e2e_env["user_repo"]
        user = u_repo.create_user("gemini_user", "gu@test.com", hash_password("P!"), UserRole.ANALYST.value, "org_alpha")
        tok = create_access_token(user["id"], user["username"], user["role"], user["org_id"])

        # Simulate Gemini connection exception
        from app.ai.service import ai_analysis_service
        def mock_broken_gemini(*args, **kwargs):
            from app.ai.fallback import generate_deterministic_explanation
            return generate_deterministic_explanation(
                findings=kwargs.get("findings", []),
                context=kwargs.get("context", SharingContext()),
                policy_result=kwargs.get("policy_result"),
                risk_result=kwargs.get("risk_result"),
                failure_reason="Upstream Google Gemini Gateway 504 Gateway Timeout",
            )
        monkeypatch.setattr(ai_analysis_service, "analyze_context", mock_broken_gemini)

        # Critical transfer destined for public destination
        res = client.post(
            "/api/v1/scan/text",
            headers={"Authorization": f"Bearer {tok}"},
            json={
                "text": "Critical secret: AKIAIOSFODNN7EXAMPLE",
                "context": {
                    "destination": DestinationType.PUBLIC_LLM.value,
                    "recipient": RecipientType.PUBLIC.value,
                    "classification": DataClassification.CONFIDENTIAL.value,
                },
            },
        )
        assert res.status_code == 200
        data = res.json()

        # Deterministic security decision is unaffected
        assert data["policy_decision"] == "BLOCK"
        assert data["risk_band"] == "CRITICAL"
        assert data["ai_analysis"]["is_ai_assisted"] is False
        assert data["ai_analysis"]["ai_status"] in ("FALLBACK", "UNAVAILABLE")
        assert "504 Gateway Timeout" in data["ai_analysis"]["disclaimer"]


# ---------------------------------------------------------------------------
# Section 6: Audit and Policy Integrity Verification
# ---------------------------------------------------------------------------

class TestPhase5AuditAndPolicyIntegrity:
    def test_audit_chain_tamper_detection_and_tenant_privacy(self, e2e_env):
        u_repo = e2e_env["user_repo"]
        a_svc = e2e_env["audit_service"]
        db_path = e2e_env["db_path"]

        user_alpha = u_repo.create_user("a_auditor", "aa@test.com", hash_password("P!"), UserRole.ANALYST.value, "org_alpha")
        tok_alpha = create_access_token(user_alpha["id"], user_alpha["username"], user_alpha["role"], user_alpha["org_id"])

        # 1. Append valid events
        ev1 = a_svc.append_event(
            event_type="SCAN_EXECUTED",
            sanitized_metadata={"finding_count": 0},
            scan_id="s1",
            actor_id="user1",
            policy_decision="ALLOW",
            policy_references=["POL-005"],
            org_id="org_alpha",
        )
        ev2 = a_svc.append_event(
            event_type="SCAN_EXECUTED",
            sanitized_metadata={"finding_count": 1},
            scan_id="s2",
            actor_id="user2",
            policy_decision="BLOCK",
            policy_references=["POL-001"],
            org_id="org_beta",
        )

        # 2. Intact chain verifies cleanly
        verify_clean = a_svc.verify_chain(org_id="org_alpha")
        assert verify_clean.is_valid is True
        assert verify_clean.total_events == 1

        # 3. Tamper ev2 (belonging to org_beta) directly in the SQLite database
        from app.db.connection import get_db_cursor
        with get_db_cursor(db_path) as cursor:
            cursor.execute(
                "UPDATE audit_events SET policy_decision = 'ALLOW' WHERE event_id = ?",
                (ev2.event_id,),
            )

        # 4. Org Alpha checks integrity: verification fails, but Org Beta's event ID is suppressed
        verify_tampered = a_svc.verify_chain(org_id="org_alpha")
        assert verify_tampered.is_valid is False
        assert verify_tampered.tampered_event_id is None
        for err in verify_tampered.errors:
            assert ev2.event_id not in err
            assert "s2" not in err

    def test_policy_precedence_hierarchy(self):
        # Verify deterministic priority order: BLOCK > REQUIRE_APPROVAL > REDACT > WARN > ALLOW
        from app.policy.engine import PolicyEngine
        engine = PolicyEngine()

        finding = Finding(
            id="f1",
            category=FindingCategory.SECRET,
            rule_id="AWS_KEY",
            severity=SeverityLevel.CRITICAL,
            detector_name="regex_pattern",
            confidence=0.99,
            confidence_band=ConfidenceBand.VERY_HIGH,
            start_offset=0,
            end_offset=20,
            masked_evidence="AKIAIOS...EXAMPLE",
            suggested_remediation="Revoke and rotate immediately.",
        )
        ctx = SharingContext(
            destination=DestinationType.PUBLIC_LLM,
            recipient=RecipientType.PUBLIC,
            classification=DataClassification.CONFIDENTIAL,
        )

        res = engine.evaluate([finding], ctx)
        assert res.final_decision == PolicyAction.BLOCK
