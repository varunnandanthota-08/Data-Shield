import os
import tempfile
import pytest
from fastapi.testclient import TestClient
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

from app.main import app
from app.auth.models import UserRole
from app.auth.repository import UserRepository
from app.auth.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
    verify_dummy_password,
)
from app.auth.rate_limiter import AuthRateLimiter
from app.db.schema import init_db
from app.core.config import settings

client = TestClient(app)


# ---------------------------------------------------------------------------
# Test Isolation Fixture: Temporary Database for Auth & User Repository
# ---------------------------------------------------------------------------

@pytest.fixture
def auth_repo_and_db(monkeypatch):
    """Provides a fresh isolated SQLite database and patches UserRepository.db_path
    so tests have zero impact on existing application or audit records.
    """
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(path)

    from app.auth.repository import user_repo
    old_path = user_repo.db_path
    user_repo.db_path = path

    rate_limiter = AuthRateLimiter()
    monkeypatch.setattr("app.api.routes.auth.auth_rate_limiter", rate_limiter)

    yield user_repo, path, rate_limiter

    user_repo.db_path = old_path
    if os.path.exists(path):
        os.remove(path)


# ---------------------------------------------------------------------------
# 1. Password Hashing and Cryptographic Verification (Argon2id)
# ---------------------------------------------------------------------------

class TestPasswordSecurity:
    def test_argon2id_hashing_and_verification(self):
        password = "P@ssw0rdSecure2026!"
        hashed = hash_password(password)

        assert hashed.startswith("$argon2id$")
        assert verify_password(password, hashed) is True
        assert verify_password("WrongPassword123!", hashed) is False

    def test_never_store_plaintext(self):
        password = "PlaintextSuperSecret!"
        hashed = hash_password(password)
        assert password not in hashed

    def test_dummy_verification_timing_mitigation(self):
        # Dummy verification against non-existent user must return False without throwing
        result = verify_dummy_password("any_attempted_password")
        assert result is False


# ---------------------------------------------------------------------------
# 2. JWT Access Token Creation, Expiration, and Validation
# ---------------------------------------------------------------------------

class TestJWTTokenSecurity:
    def test_create_and_decode_token(self):
        token = create_access_token(
            user_id="usr_test_123",
            username="admin_test",
            role=UserRole.ADMIN.value,
            org_id="test_org",
        )
        payload = decode_access_token(token)

        assert payload["sub"] == "usr_test_123"
        assert payload["role"] == "admin"
        assert payload["org_id"] == "test_org"
        assert payload["username"] == "admin_test"
        assert payload["iss"] == "datashield-ai"
        assert "exp" in payload
        assert "iat" in payload

    def test_token_expiration(self):
        from datetime import timedelta
        token = create_access_token(
            user_id="usr_expired",
            username="expired_user",
            role=UserRole.ANALYST.value,
            org_id="default",
            expires_delta=timedelta(minutes=-5),  # Already expired 5 minutes ago
        )
        with pytest.raises(ExpiredSignatureError):
            decode_access_token(token)

    def test_tampered_token_rejected(self):
        token = create_access_token(
            user_id="usr_valid",
            username="viewer_user",
            role=UserRole.VIEWER.value,
            org_id="default",
        )
        # Modify the signature part
        parts = token.split(".")
        tampered_token = f"{parts[0]}.{parts[1]}.tampered_signature_bytes"
        with pytest.raises(InvalidTokenError):
            decode_access_token(tampered_token)


# ---------------------------------------------------------------------------
# 3. Rate Limiter & Lockout Mechanism
# ---------------------------------------------------------------------------

class TestAuthRateLimiter:
    def test_rate_limiter_lockout_trigger(self):
        limiter = AuthRateLimiter()
        key = "127.0.0.1:attacker"

        # Settings allow 5 attempts by default
        for i in range(settings.AUTH_RATE_LIMIT_MAX_ATTEMPTS - 1):
            locked = limiter.record_failure(key)
            assert locked is False

        # Next failure triggers lockout
        locked = limiter.record_failure(key)
        assert locked is True

        is_locked, remaining = limiter.is_locked(key)
        assert is_locked is True
        assert remaining > 0

    def test_rate_limiter_success_clears_failures(self):
        limiter = AuthRateLimiter()
        key = "127.0.0.1:legit_user"

        limiter.record_failure(key)
        limiter.record_failure(key)
        limiter.record_success(key)

        is_locked, _ = limiter.is_locked(key)
        assert is_locked is False


# ---------------------------------------------------------------------------
# 4. Authentication Endpoints: Bootstrap, Setup, Login, Logout, /me
# ---------------------------------------------------------------------------

class TestAuthEndpoints:
    def test_bootstrap_flow_and_lockdown(self, auth_repo_and_db):
        user_repo, _, _ = auth_repo_and_db

        # 1. Initial state: 0 users -> requires_bootstrap = True
        res = client.get("/api/v1/auth/bootstrap-status")
        assert res.status_code == 200
        assert res.json()["requires_bootstrap"] is True
        assert res.json()["user_count"] == 0

        # 2. Setup initial administrator
        setup_payload = {
            "username": "superadmin",
            "email": "superadmin@datashield.ai",
            "password": "InitialAdminPassword2026!",
        }
        res_setup = client.post("/api/v1/auth/setup-admin", json=setup_payload)
        assert res_setup.status_code == 201
        data = res_setup.json()
        assert data["user"]["username"] == "superadmin"
        assert data["user"]["role"] == "admin"
        assert "access_token" in data

        # 3. Subsequent calls to setup-admin must be permanently blocked (403)
        res_closed = client.post("/api/v1/auth/setup-admin", json=setup_payload)
        assert res_closed.status_code == 403
        assert "disabled" in res_closed.json()["detail"].lower() or "bootstrapped" in res_closed.json()["detail"].lower()

        # 4. Bootstrap status now reports requires_bootstrap = False
        res_status = client.get("/api/v1/auth/bootstrap-status")
        assert res_status.status_code == 200
        assert res_status.json()["requires_bootstrap"] is False
        assert res_status.json()["user_count"] == 1

    def test_login_success_and_logout(self, auth_repo_and_db):
        user_repo, _, _ = auth_repo_and_db

        # Create user
        user_repo.create_user(
            username="analyst_jane",
            email="jane@datashield.ai",
            password_hash=hash_password("JaneStrongPassword123!"),
            role="analyst",
        )

        # Login with correct password
        login_res = client.post(
            "/api/v1/auth/login",
            json={"username": "analyst_jane", "password": "JaneStrongPassword123!"},
        )
        assert login_res.status_code == 200
        token_data = login_res.json()
        assert token_data["user"]["username"] == "analyst_jane"
        assert token_data["user"]["role"] == "analyst"
        assert "access_token" in token_data
        token = token_data["access_token"]

        # Call /me with bearer token
        me_res = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert me_res.status_code == 200
        assert me_res.json()["username"] == "analyst_jane"

        # Logout clears session cookie
        logout_res = client.post("/api/v1/auth/logout")
        assert logout_res.status_code == 200

    def test_login_invalid_credentials_returns_generic_401(self, auth_repo_and_db):
        user_repo, _, _ = auth_repo_and_db

        user_repo.create_user(
            username="existing_user",
            email="existing@datashield.ai",
            password_hash=hash_password("RealPassword123!"),
            role="viewer",
        )

        # 1. Invalid password for existing user
        res1 = client.post(
            "/api/v1/auth/login",
            json={"username": "existing_user", "password": "WrongPassword123!"},
        )
        assert res1.status_code == 401
        assert res1.json()["detail"] == "Invalid username or password"

        # 2. Non-existent username
        res2 = client.post(
            "/api/v1/auth/login",
            json={"username": "ghost_user_xyz", "password": "AnyPassword123!"},
        )
        assert res2.status_code == 401
        assert res2.json()["detail"] == "Invalid username or password"

    def test_login_rate_limiting_enforcement(self, auth_repo_and_db):
        user_repo, _, limiter = auth_repo_and_db

        # Fail repeatedly until locked out
        for _ in range(settings.AUTH_RATE_LIMIT_MAX_ATTEMPTS):
            client.post(
                "/api/v1/auth/login",
                json={"username": "target_account", "password": "WrongPassword!"},
            )

        # Next attempt must receive 429 Too Many Requests
        lockout_res = client.post(
            "/api/v1/auth/login",
            json={"username": "target_account", "password": "WrongPassword!"},
        )
        assert lockout_res.status_code == 429
        assert "temporarily locked" in lockout_res.json()["detail"]


# ---------------------------------------------------------------------------
# 5. Role-Based Access Control (RBAC) & Endpoint Protection Matrix
# ---------------------------------------------------------------------------

class TestRBACPermissionMatrix:
    @pytest.fixture(autouse=True)
    def setup_roles_and_tokens(self, auth_repo_and_db):
        user_repo, _, _ = auth_repo_and_db

        # Provision Admin
        admin = user_repo.create_user(
            username="soc_admin",
            email="admin@soc.corp.com",
            password_hash=hash_password("AdminPass123!"),
            role="admin",
        )
        self.admin_token = create_access_token(
            user_id=admin["id"],
            username="soc_admin",
            role=UserRole.ADMIN.value,
            org_id="default",
        )

        # Provision Analyst
        analyst = user_repo.create_user(
            username="soc_analyst",
            email="analyst@soc.corp.com",
            password_hash=hash_password("AnalystPass123!"),
            role="analyst",
        )
        self.analyst_token = create_access_token(
            user_id=analyst["id"],
            username="soc_analyst",
            role=UserRole.ANALYST.value,
            org_id="default",
        )

        # Provision Viewer
        viewer = user_repo.create_user(
            username="soc_viewer",
            email="viewer@soc.corp.com",
            password_hash=hash_password("ViewerPass123!"),
            role="viewer",
        )
        self.viewer_token = create_access_token(
            user_id=viewer["id"],
            username="soc_viewer",
            role=UserRole.VIEWER.value,
            org_id="default",
        )

    def test_unauthenticated_requests_blocked_with_401(self):
        # Scan endpoints require authentication
        res = client.post("/api/v1/scan/text", json={"text": "Confidential payload"})
        assert res.status_code == 401

        # Policies endpoints require authentication
        res = client.get("/api/v1/policies")
        assert res.status_code == 401

        # Audit endpoints require authentication
        res = client.get("/api/v1/audit/events")
        assert res.status_code == 401

        # User management requires authentication
        res = client.get("/api/v1/users")
        assert res.status_code == 401

    def test_viewer_role_boundaries(self):
        headers = {"Authorization": f"Bearer {self.viewer_token}"}

        # Viewer CAN read scan records and metrics
        res_rec = client.get("/api/v1/scan/records", headers=headers)
        assert res_rec.status_code == 200

        res_met = client.get("/api/v1/scan/metrics", headers=headers)
        assert res_met.status_code == 200

        # Viewer CAN read policies
        res_pol = client.get("/api/v1/policies", headers=headers)
        assert res_pol.status_code == 200

        # Viewer CANNOT execute scans (403)
        res_scan = client.post("/api/v1/scan/text", json={"text": "test"}, headers=headers)
        assert res_scan.status_code == 403

        # Viewer CANNOT mutate policies (403)
        res_pol_create = client.post("/api/v1/policies", json={"id": "POL-999"}, headers=headers)
        assert res_pol_create.status_code == 403

        # Viewer CANNOT access audit logs (403)
        res_aud = client.get("/api/v1/audit/events", headers=headers)
        assert res_aud.status_code == 403

        # Viewer CANNOT access user management (403)
        res_usr = client.get("/api/v1/users", headers=headers)
        assert res_usr.status_code == 403

    def test_analyst_role_boundaries(self):
        headers = {"Authorization": f"Bearer {self.analyst_token}"}

        # Analyst CAN run text scan
        res_scan = client.post(
            "/api/v1/scan/text",
            json={"text": "Analyst inspecting internal memo"},
            headers=headers,
        )
        assert res_scan.status_code == 200

        # Analyst CAN inspect audit events and verify audit chain
        res_aud = client.get("/api/v1/audit/events", headers=headers)
        assert res_aud.status_code == 200

        res_ver = client.get("/api/v1/audit/verify", headers=headers)
        assert res_ver.status_code == 200

        # Analyst CANNOT create or delete policies (403 - Admin only)
        res_pol = client.post("/api/v1/policies", json={"id": "POL-TEST"}, headers=headers)
        assert res_pol.status_code == 403

        # Analyst CANNOT manage users (403 - Admin only)
        res_usr = client.get("/api/v1/users", headers=headers)
        assert res_usr.status_code == 403

        res_usr_create = client.post(
            "/api/v1/users",
            json={
                "username": "escalated_user",
                "email": "esc@datashield.ai",
                "password": "EscalatedPass123!",
                "role": "admin",
            },
            headers=headers,
        )
        assert res_usr_create.status_code == 403

    def test_admin_full_access_and_self_preservation(self):
        admin_headers = {"Authorization": f"Bearer {self.admin_token}"}

        # Admin CAN list users
        res_users = client.get("/api/v1/users", headers=admin_headers)
        assert res_users.status_code == 200
        user_list = res_users.json()
        assert len(user_list) >= 3

        # Admin CAN provision a new user
        new_usr_res = client.post(
            "/api/v1/users",
            json={
                "username": "newly_hired_analyst",
                "email": "new_hire@soc.corp.com",
                "password": "NewHirePassword123!",
                "role": "analyst",
            },
            headers=admin_headers,
        )
        assert new_usr_res.status_code == 201
        created_id = new_usr_res.json()["id"]

        # Admin CAN delete other users
        del_res = client.delete(f"/api/v1/users/{created_id}", headers=admin_headers)
        assert del_res.status_code == 200

        # Admin CANNOT delete or demote their own active account
        me_res = client.get("/api/v1/auth/me", headers=admin_headers)
        my_id = me_res.json()["id"]

        self_del_res = client.delete(f"/api/v1/users/{my_id}", headers=admin_headers)
        assert self_del_res.status_code == 400
        assert "cannot delete" in self_del_res.json()["detail"].lower()

        self_demote_res = client.put(
            f"/api/v1/users/{my_id}",
            json={"role": "viewer"},
            headers=admin_headers,
        )
        assert self_demote_res.status_code == 400
        assert "cannot demote" in self_demote_res.json()["detail"].lower()
