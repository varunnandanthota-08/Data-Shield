import os
import tempfile
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict
import jwt
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import Settings, settings
from app.auth.models import UserRole
from app.auth.repository import UserRepository, TokenRevocationRepository
from app.auth.security import (
    create_access_token,
    decode_access_token,
    generate_csrf_token,
    hash_password,
    verify_csrf_token,
)
from app.auth.rate_limiter import (
    AuthRateLimiter,
    EndpointRateLimiter,
    InMemoryRateLimiterStorage,
    SqliteRateLimiterStorage,
    get_client_ip,
)
from app.audit.service import AuditService, compute_event_hash
from app.db.schema import init_db
from app.policy.engine import policy_engine
from app.policy.defaults import DEFAULT_POLICIES
from app.policy.schemas import (
    DataClassification,
    DestinationType,
    FindingCategory,
    PolicyAction,
    RecipientType,
    SharingContext,
)
from app.engine.schemas import Finding, ScanResponse, SeverityLevel

client = TestClient(app)


# ---------------------------------------------------------------------------
# Test Fixture: Isolated Database & Clean Repositories
# ---------------------------------------------------------------------------

@pytest.fixture
def hardened_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(path)

    u_repo = UserRepository(db_path=path)
    t_repo = TokenRevocationRepository(db_path=path)
    sqlite_storage = SqliteRateLimiterStorage(db_path=path)

    # Patch global repos and rate limiters to target this isolated database
    from app.auth import repository as auth_repo_mod
    from app.auth import dependencies as auth_dep_mod
    from app.api.routes import auth as auth_route_mod
    from app.api.routes import users as user_route_mod
    from app.auth.rate_limiter import auth_rate_limiter, scan_rate_limiter
    from app.auth.dependencies import get_current_user

    # Ensure no stale dependency overrides affect isolated hardening tests
    app.dependency_overrides.pop(get_current_user, None)

    orig_user_repo = auth_repo_mod.user_repo
    orig_token_repo = auth_repo_mod.token_revocation_repo
    orig_dep_user_repo = auth_dep_mod.user_repo
    orig_dep_token_repo = auth_dep_mod.token_revocation_repo
    orig_route_user_repo = auth_route_mod.user_repo
    orig_route_token_repo = auth_route_mod.token_revocation_repo
    orig_user_route_repo = user_route_mod.user_repo

    orig_auth_limiter_storage = auth_rate_limiter._storage
    orig_scan_limiter_storage = scan_rate_limiter._storage

    auth_repo_mod.user_repo = u_repo
    auth_repo_mod.token_revocation_repo = t_repo
    auth_dep_mod.user_repo = u_repo
    auth_dep_mod.token_revocation_repo = t_repo
    auth_route_mod.user_repo = u_repo
    auth_route_mod.token_revocation_repo = t_repo
    user_route_mod.user_repo = u_repo

    # Bind rate limiters to this isolated temporary database
    auth_rate_limiter.set_storage(sqlite_storage)
    scan_rate_limiter.set_storage(sqlite_storage)

    yield u_repo, t_repo, sqlite_storage, path

    auth_repo_mod.user_repo = orig_user_repo
    auth_repo_mod.token_revocation_repo = orig_token_repo
    auth_dep_mod.user_repo = orig_dep_user_repo
    auth_dep_mod.token_revocation_repo = orig_dep_token_repo
    auth_route_mod.user_repo = orig_route_user_repo
    auth_route_mod.token_revocation_repo = orig_route_token_repo
    user_route_mod.user_repo = orig_user_route_repo

    # Restore rate limiters to original global storage and clear temporary state
    sqlite_storage.reset_all()
    auth_rate_limiter.set_storage(orig_auth_limiter_storage)
    scan_rate_limiter.set_storage(orig_scan_limiter_storage)
    app.dependency_overrides.pop(get_current_user, None)

    if os.path.exists(path):
        os.remove(path)


# ---------------------------------------------------------------------------
# 1. JWT and Session Security Tests
# ---------------------------------------------------------------------------

class TestJWTAndSessionSecurity:
    def test_jwt_contains_required_claims_and_jti(self):
        token = create_access_token(
            user_id="usr_test_123",
            username="analyst_bob",
            role=UserRole.ANALYST.value,
            org_id="org_alpha",
        )
        payload = decode_access_token(token)

        assert payload["sub"] == "usr_test_123"
        assert payload["username"] == "analyst_bob"
        assert payload["role"] == "analyst"
        assert payload["org_id"] == "org_alpha"
        assert payload["iss"] == "datashield-ai"
        assert payload["token_type"] == "access"
        assert "jti" in payload and len(payload["jti"]) > 10
        assert "iat" in payload and "exp" in payload
        assert payload["exp"] > payload["iat"]

    def test_expired_jwt_rejected(self):
        expired_token = create_access_token(
            user_id="usr_expired",
            username="expired_user",
            role=UserRole.ANALYST.value,
            org_id="org_alpha",
            expires_delta=timedelta(seconds=-10),
        )
        res = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {expired_token}"},
        )
        assert res.status_code == 401
        assert "expired" in res.json()["detail"].lower()

    def test_tampered_and_malformed_jwt_rejected(self):
        token = create_access_token(
            user_id="usr_tamper",
            username="tamper_user",
            role=UserRole.ANALYST.value,
            org_id="org_alpha",
        )
        # Tamper signature
        parts = token.split(".")
        tampered_token = f"{parts[0]}.{parts[1]}.invalidsignaturehere123"

        res = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {tampered_token}"},
        )
        assert res.status_code == 401
        assert "could not validate credentials" in res.json()["detail"].lower()

    def test_token_revocation_on_logout(self, hardened_db):
        u_repo, t_repo, _, _ = hardened_db
        user = u_repo.create_user(
            username="logout_user",
            email="logout@datashield.test",
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

        # 1. Valid before logout
        res_before = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert res_before.status_code == 200

        # 2. Call logout with token
        res_logout = client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})
        assert res_logout.status_code == 200

        # 3. Subsequent request with revoked token must be rejected
        res_after = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert res_after.status_code == 401
        assert "revoked" in res_after.json()["detail"].lower()

    def test_account_deactivation_invalidates_all_sessions(self, hardened_db):
        u_repo, _, _, _ = hardened_db
        user = u_repo.create_user(
            username="deactivate_me",
            email="deact@datashield.test",
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

        # Token is valid initially
        res_before = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert res_before.status_code == 200

        # Deactivate user
        u_repo.update_user(user["id"], is_active=False)

        # Token must immediately fail with inactive or revoked error
        res_after = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert res_after.status_code == 401

    def test_revoke_all_sessions_endpoint(self, hardened_db):
        u_repo, _, _, _ = hardened_db
        user = u_repo.create_user(
            username="session_reset_user",
            email="reset@datashield.test",
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

        # Call /revoke-all-sessions
        res_revoke = client.post(
            "/api/v1/auth/revoke-all-sessions",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res_revoke.status_code == 200

        # Token must now be rejected
        res_check = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert res_check.status_code == 401


# ---------------------------------------------------------------------------
# 2. CSRF and Cookie Protection Tests
# ---------------------------------------------------------------------------

class TestCSRFAndCookieProtection:
    def test_bearer_token_exempt_from_csrf(self, hardened_db):
        u_repo, _, _, _ = hardened_db
        user = u_repo.create_user(
            username="api_client",
            email="api@datashield.test",
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

        # Bearer token requests (API clients) must succeed without CSRF headers
        res = client.post(
            "/api/v1/scan/text",
            headers={"Authorization": f"Bearer {token}"},
            json={"text": "Clean payload without findings"},
        )
        assert res.status_code == 200

    def test_cookie_auth_rejects_missing_csrf_on_state_change(self, hardened_db):
        u_repo, _, _, _ = hardened_db
        user = u_repo.create_user(
            username="cookie_client",
            email="cookie@datashield.test",
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

        # Only session_token cookie, NO CSRF header -> 403 Forbidden
        client.cookies.set("session_token", token)
        try:
            res = client.post(
                "/api/v1/scan/text",
                json={"text": "Clean test payload"},
            )
            assert res.status_code == 403
            assert "csrf" in res.json()["detail"].lower()
        finally:
            client.cookies.clear()

    def test_cookie_auth_rejects_mismatched_csrf(self, hardened_db):
        u_repo, _, _, _ = hardened_db
        user = u_repo.create_user(
            username="cookie_mismatch",
            email="mismatch@datashield.test",
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

        client.cookies.set("session_token", token)
        client.cookies.set("csrf_token", "legitimate_csrf_token_123")
        try:
            res = client.post(
                "/api/v1/scan/text",
                headers={"X-CSRF-Token": "attacker_forged_csrf_token_999"},
                json={"text": "Clean test payload"},
            )
            assert res.status_code == 403
            assert "csrf" in res.json()["detail"].lower()
        finally:
            client.cookies.clear()

    def test_cookie_auth_succeeds_with_valid_matching_csrf(self, hardened_db):
        u_repo, _, _, _ = hardened_db
        user = u_repo.create_user(
            username="cookie_valid",
            email="valid@datashield.test",
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

        csrf_val = generate_csrf_token()
        client.cookies.set("session_token", token)
        client.cookies.set("csrf_token", csrf_val)
        try:
            res = client.post(
                "/api/v1/scan/text",
                headers={"X-CSRF-Token": csrf_val},
                json={"text": "Clean test payload"},
            )
            assert res.status_code == 200
        finally:
            client.cookies.clear()


# ---------------------------------------------------------------------------
# 3. Production Configuration and Insecure-Secret Rejection
# ---------------------------------------------------------------------------

class TestProductionConfigurationSecurity:
    def test_rejects_default_dev_secret_in_production(self):
        with pytest.raises(ValueError, match="Insecure or default JWT_SECRET_KEY"):
            Settings(
                ENVIRONMENT="production",
                JWT_SECRET_KEY="datashield-dev-jwt-secret-replace-in-production-2026-secure-key",
                DEBUG=False,
                CORS_ORIGINS=["https://soc.company.com"],
            )

    def test_rejects_short_secret_in_production(self):
        with pytest.raises(ValueError, match="Insecure or default JWT_SECRET_KEY"):
            Settings(
                ENVIRONMENT="production",
                JWT_SECRET_KEY="too-short-key",
                DEBUG=False,
                CORS_ORIGINS=["https://soc.company.com"],
            )

    def test_rejects_debug_true_in_production(self):
        with pytest.raises(ValueError, match="DEBUG mode must be disabled"):
            Settings(
                ENVIRONMENT="production",
                JWT_SECRET_KEY="cryptographically-strong-production-secret-min-32-chars!",
                DEBUG=True,
                CORS_ORIGINS=["https://soc.company.com"],
            )

    def test_rejects_wildcard_cors_with_credentials_in_production(self):
        with pytest.raises(ValueError, match="Wildcard CORS origin"):
            Settings(
                ENVIRONMENT="production",
                JWT_SECRET_KEY="cryptographically-strong-production-secret-min-32-chars!",
                DEBUG=False,
                CORS_ORIGINS=["*"],
            )

    def test_accepts_valid_hardened_production_config(self):
        prod_settings = Settings(
            ENVIRONMENT="production",
            JWT_SECRET_KEY="cryptographically-strong-production-secret-min-32-chars!",
            DEBUG=False,
            CORS_ORIGINS=["https://soc.company.com"],
        )
        assert prod_settings.ENVIRONMENT == "production"
        assert prod_settings.is_cookie_secure is True


# ---------------------------------------------------------------------------
# 4. Rate Limiting and Abuse Prevention Tests
# ---------------------------------------------------------------------------

class TestRateLimitingAndAbusePrevention:
    def test_in_memory_storage_sliding_window_and_lockout(self):
        storage = InMemoryRateLimiterStorage()
        key = "test_user_ip_1"

        # Record 4 failures (max 5)
        for _ in range(4):
            assert storage.record_failure(key, window_seconds=60, max_attempts=5, lockout_seconds=300) is False

        is_locked, _ = storage.is_locked(key)
        assert is_locked is False

        # 5th failure triggers lockout
        locked = storage.record_failure(key, window_seconds=60, max_attempts=5, lockout_seconds=300)
        assert locked is True

        is_locked, remaining = storage.is_locked(key)
        assert is_locked is True
        assert remaining > 0

    def test_sqlite_shared_storage_sliding_window_and_lockout(self, hardened_db):
        _, _, sqlite_storage, _ = hardened_db
        key = "worker_shared_key_1"

        for _ in range(4):
            assert sqlite_storage.record_failure(key, window_seconds=60, max_attempts=5, lockout_seconds=300) is False

        is_locked, _ = sqlite_storage.is_locked(key)
        assert is_locked is False

        # 5th attempt locks out
        assert sqlite_storage.record_failure(key, window_seconds=60, max_attempts=5, lockout_seconds=300) is True

        is_locked, remaining = sqlite_storage.is_locked(key)
        assert is_locked is True
        assert remaining > 0

        # Success clears lockout
        sqlite_storage.record_success(key)
        is_locked, _ = sqlite_storage.is_locked(key)
        assert is_locked is False

    def test_client_ip_resolution_rejects_untrusted_forwarded_for(self):
        class DummyRequest:
            client = type("Client", (), {"host": "192.168.1.100"})()
            headers = {"X-Forwarded-For": "203.0.113.195"}

        # When TRUST_FORWARDED_FOR is False (default)
        resolved_ip = get_client_ip(DummyRequest())
        assert resolved_ip == "192.168.1.100"
        assert resolved_ip != "203.0.113.195"

    def test_scan_endpoint_rate_limiting(self, hardened_db):
        u_repo, _, sqlite_storage, _ = hardened_db
        user = u_repo.create_user(
            username="rapid_scanner",
            email="rapid@datashield.test",
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

        from app.auth.rate_limiter import scan_rate_limiter
        # Verify scan_rate_limiter is correctly bound to isolated storage
        assert scan_rate_limiter._storage is sqlite_storage

        key = f"scan_rate_user:{user['id']}_org:{user['org_id']}"
        scan_rate_limiter.reset_all()

        # Simulate hitting scan limit
        for _ in range(settings.SCAN_RATE_LIMIT_PER_MINUTE):
            scan_rate_limiter.check_rate_limit(key, max_requests=settings.SCAN_RATE_LIMIT_PER_MINUTE)

        # Next request must be throttled with HTTP 429 and Retry-After
        res = client.post(
            "/api/v1/scan/text",
            headers={"Authorization": f"Bearer {token}"},
            json={"text": "Clean payload"},
        )
        assert res.status_code == 429
        assert "Retry-After" in res.headers
        assert "rate limit exceeded" in res.json()["detail"].lower()

        # Different user in org_beta must NOT be throttled (per-user/per-tenant isolation)
        user_beta = u_repo.create_user(
            username="beta_scanner",
            email="beta@datashield.test",
            password_hash=hash_password("Password123!"),
            role=UserRole.ANALYST.value,
            org_id="org_beta",
        )
        token_beta = create_access_token(
            user_id=user_beta["id"],
            username=user_beta["username"],
            role=user_beta["role"],
            org_id=user_beta["org_id"],
        )
        res_beta = client.post(
            "/api/v1/scan/text",
            headers={"Authorization": f"Bearer {token_beta}"},
            json={"text": "Clean payload for beta"},
        )
        assert res_beta.status_code == 200

        scan_rate_limiter.reset_all()

    def test_rate_limiter_isolated_storage_restoration_and_no_cross_test_leakage(self, hardened_db):
        """Regression test ensuring test fixtures bind rate limiters to isolated storage
        and do not leak throttled keys or storage references to global state.
        """
        u_repo, _, sqlite_storage, path = hardened_db
        from app.auth.rate_limiter import scan_rate_limiter, auth_rate_limiter

        assert scan_rate_limiter._storage is sqlite_storage
        assert auth_rate_limiter._storage is sqlite_storage

        # Record a hit in isolated storage
        test_key = "test_scan_leakage_key"
        is_limited, _ = scan_rate_limiter.check_rate_limit(test_key, max_requests=1)
        assert is_limited is False

        # Exceed limit in isolated storage
        is_limited, _ = scan_rate_limiter.check_rate_limit(test_key, max_requests=1)
        assert is_limited is True


# ---------------------------------------------------------------------------
# 5. Tenant Isolation and Safe Audit Response Tests
# ---------------------------------------------------------------------------

class TestTenantIsolationHardening:
    def test_cross_tenant_scan_record_lookup_blocked(self, hardened_db):
        u_repo, _, _, db_path = hardened_db
        # Org Alpha user
        user_alpha = u_repo.create_user(
            username="alpha_analyst",
            email="alpha@datashield.test",
            password_hash=hash_password("Password123!"),
            role=UserRole.ANALYST.value,
            org_id="org_alpha",
        )
        token_alpha = create_access_token(
            user_id=user_alpha["id"],
            username=user_alpha["username"],
            role=user_alpha["role"],
            org_id="org_alpha",
        )

        # Org Beta user submits scan
        user_beta = u_repo.create_user(
            username="beta_analyst",
            email="beta@datashield.test",
            password_hash=hash_password("Password123!"),
            role=UserRole.ANALYST.value,
            org_id="org_beta",
        )
        token_beta = create_access_token(
            user_id=user_beta["id"],
            username=user_beta["username"],
            role=user_beta["role"],
            org_id="org_beta",
        )

        res_beta_scan = client.post(
            "/api/v1/scan/text",
            headers={"Authorization": f"Bearer {token_beta}"},
            json={"text": "Beta secret analysis"},
        )
        assert res_beta_scan.status_code == 200
        scan_id = res_beta_scan.json()["scan_id"]

        # Org Alpha tries to look up Beta's scan_id -> Must return 404
        res_cross = client.get(
            f"/api/v1/scan/records/{scan_id}",
            headers={"Authorization": f"Bearer {token_alpha}"},
        )
        assert res_cross.status_code == 404

    def test_global_baseline_policies_remain_immutable_to_tenant_admin(self, hardened_db):
        u_repo, _, _, _ = hardened_db
        admin_alpha = u_repo.create_user(
            username="alpha_admin",
            email="admin_alpha@datashield.test",
            password_hash=hash_password("Password123!"),
            role=UserRole.ADMIN.value,
            org_id="org_alpha",
        )
        token_alpha = create_access_token(
            user_id=admin_alpha["id"],
            username=admin_alpha["username"],
            role=admin_alpha["role"],
            org_id="org_alpha",
        )

        # Attempt to toggle baseline policy POL-001 -> Must return 403
        res_toggle = client.patch(
            "/api/v1/policies/POL-001/toggle",
            headers={"Authorization": f"Bearer {token_alpha}"},
        )
        assert res_toggle.status_code == 403
        assert "baseline" in res_toggle.json()["detail"].lower()

        # Attempt to delete baseline policy POL-001 -> Must be rejected (400 or 403)
        res_del = client.delete(
            "/api/v1/policies/POL-001",
            headers={"Authorization": f"Bearer {token_alpha}"},
        )
        assert res_del.status_code in (400, 403)

    def test_audit_verification_does_not_leak_foreign_tenant_metadata(self, hardened_db):
        _, _, _, db_path = hardened_db
        audit_svc = AuditService(db_path=db_path)

        # 1. Insert Org Alpha event
        ev_alpha = audit_svc.append_event(
            event_type="SCAN_EXECUTED",
            scan_id="scan_alpha_1",
            actor_id="user_alpha",
            policy_decision="ALLOW",
            policy_references=["POL-005"],
            sanitized_metadata={"finding_count": 0},
            org_id="org_alpha",
        )

        # 2. Insert Org Beta event in the same global sequence
        ev_beta = audit_svc.append_event(
            event_type="SCAN_EXECUTED",
            scan_id="scan_beta_1",
            actor_id="user_beta",
            policy_decision="BLOCK",
            policy_references=["POL-001"],
            sanitized_metadata={"finding_count": 1},
            org_id="org_beta",
        )

        # 3. Tamper Org Beta's event payload directly in SQLite
        from app.db.connection import get_db_cursor
        with get_db_cursor(db_path) as cursor:
            cursor.execute(
                "UPDATE audit_events SET policy_decision = 'ALLOW' WHERE event_id = ?",
                (ev_beta.event_id,),
            )

        # 4. Org Alpha verifies their audit chain
        # The chain integrity verification fails, but Org Alpha must NOT receive ev_beta's event_id
        res_alpha = audit_svc.verify_chain(org_id="org_alpha")
        assert res_alpha.is_valid is False
        assert res_alpha.tampered_event_id is None
        for err in res_alpha.errors:
            assert ev_beta.event_id not in err
            assert "scan_beta_1" not in err


# ---------------------------------------------------------------------------
# 6. Upload Safety and Gemini Degradation Tests
# ---------------------------------------------------------------------------

class TestUploadSafetyAndGeminiDegradation:
    def test_oversized_upload_rejected(self, hardened_db):
        u_repo, _, _, _ = hardened_db
        user = u_repo.create_user(
            username="upload_tester",
            email="upload@datashield.test",
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

        # Upload exceeding 5MB limit
        large_bytes = b"A" * (settings.MAX_UPLOAD_SIZE_BYTES + 5000)
        res = client.post(
            "/api/v1/scan/file",
            headers={"Authorization": f"Bearer {token}"},
            files={"file": ("oversized.txt", large_bytes, "text/plain")},
        )
        assert res.status_code == 413

    def test_dangerous_extension_rejected(self, hardened_db):
        u_repo, _, _, _ = hardened_db
        user = u_repo.create_user(
            username="upload_tester2",
            email="upload2@datashield.test",
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

        res = client.post(
            "/api/v1/scan/file",
            headers={"Authorization": f"Bearer {token}"},
            files={"file": ("malicious.exe", b"MZexecutablebytes", "application/octet-stream")},
        )
        assert res.status_code == 400
        assert "executable" in res.json()["detail"].lower() or "binary" in res.json()["detail"].lower()

    def test_gemini_failure_preserves_deterministic_enforcement(self, monkeypatch, hardened_db):
        u_repo, _, _, _ = hardened_db
        user = u_repo.create_user(
            username="gemini_tester",
            email="gemini@datashield.test",
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

        # Simulate Gemini API failure / network timeout
        from app.ai.service import ai_analysis_service
        def mock_error_analyze(*args, **kwargs):
            from app.ai.fallback import generate_deterministic_explanation
            return generate_deterministic_explanation(
                findings=kwargs.get("findings", []),
                context=kwargs.get("context", SharingContext()),
                policy_result=kwargs.get("policy_result"),
                risk_result=kwargs.get("risk_result"),
                failure_reason="Simulated upstream Gemini connection timeout",
            )
        monkeypatch.setattr(ai_analysis_service, "analyze_context", mock_error_analyze)

        # Scan text containing secret to public destination (must deterministically BLOCK)
        text_payload = "Sensitive AWS Secret: AKIAIOSFODNN7EXAMPLE to public"
        res = client.post(
            "/api/v1/scan/text",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "text": text_payload,
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
        assert data["ai_analysis"]["is_ai_assisted"] is False
        assert data["ai_analysis"]["ai_status"] in ("FALLBACK", "UNAVAILABLE")
        assert "Simulated upstream Gemini" in data["ai_analysis"]["disclaimer"]
