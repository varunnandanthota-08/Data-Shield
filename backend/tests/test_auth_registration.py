import os
import tempfile
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.auth.models import UserRole
from app.auth.security import create_access_token, hash_password, verify_password
from app.auth.rate_limiter import AuthRateLimiter
from app.db.schema import init_db
from app.db.connection import get_db_cursor
from app.core.config import settings

client = TestClient(app)


@pytest.fixture
def isolated_auth_db(monkeypatch):
    """Provides a fresh isolated SQLite database and rate limiter for auth testing."""
    fd, path = tempfile.mkstemp(suffix="_auth_test.db")
    os.close(fd)
    init_db(path)

    from app.auth.repository import user_repo
    old_path = user_repo.db_path
    user_repo.db_path = path

    limiter = AuthRateLimiter()
    monkeypatch.setattr("app.api.routes.auth.auth_rate_limiter", limiter)

    yield user_repo, path, limiter

    user_repo.db_path = old_path
    if os.path.exists(path):
        os.remove(path)


class TestAuthenticationAndLogin:
    def test_successful_login(self, isolated_auth_db):
        user_repo, _, _ = isolated_auth_db
        user_repo.create_user(
            username="analyst_test",
            email="analyst@testcorp.com",
            password_hash=hash_password("ValidPassword123!"),
            role="analyst",
        )

        res = client.post(
            "/api/v1/auth/login",
            json={"username": "analyst_test", "password": "ValidPassword123!"},
        )
        assert res.status_code == 200
        data = res.json()
        assert "access_token" in data
        assert data["user"]["username"] == "analyst_test"
        assert data["user"]["role"] == "analyst"

    def test_failed_login_invalid_password(self, isolated_auth_db):
        user_repo, _, _ = isolated_auth_db
        user_repo.create_user(
            username="analyst_test",
            email="analyst@testcorp.com",
            password_hash=hash_password("ValidPassword123!"),
            role="analyst",
        )

        res = client.post(
            "/api/v1/auth/login",
            json={"username": "analyst_test", "password": "IncorrectPassword!"},
        )
        assert res.status_code == 401
        assert "Invalid username or password" in res.json()["detail"]

    def test_failed_login_nonexistent_user(self, isolated_auth_db):
        res = client.post(
            "/api/v1/auth/login",
            json={"username": "nonexistent_user_999", "password": "AnyPassword123!"},
        )
        assert res.status_code == 401
        assert "Invalid username or password" in res.json()["detail"]


class TestAdministratorUserProvisioning:
    def test_administrator_creates_users_with_permitted_roles(self, isolated_auth_db):
        user_repo, _, _ = isolated_auth_db
        admin = user_repo.create_user(
            username="super_admin",
            email="admin@corp.internal",
            password_hash=hash_password("AdminSecurePassword123!"),
            role="admin",
        )
        admin_token = create_access_token(
            user_id=admin["id"],
            username="super_admin",
            role=UserRole.ADMIN.value,
            org_id="default",
        )
        headers = {"Authorization": f"Bearer {admin_token}"}

        # 1. Admin creates an analyst user
        res_analyst = client.post(
            "/api/v1/users",
            json={
                "username": "new_analyst_01",
                "email": "analyst01@corp.internal",
                "password": "AnalystPassword123!",
                "role": "analyst",
                "org_id": "default",
            },
            headers=headers,
        )
        assert res_analyst.status_code == 201
        analyst_data = res_analyst.json()
        assert analyst_data["username"] == "new_analyst_01"
        assert analyst_data["role"] == "analyst"

        # 2. Admin creates a viewer user
        res_viewer = client.post(
            "/api/v1/users",
            json={
                "username": "new_viewer_01",
                "email": "viewer01@corp.internal",
                "password": "ViewerPassword123!",
                "role": "viewer",
                "org_id": "default",
            },
            headers=headers,
        )
        assert res_viewer.status_code == 201
        viewer_data = res_viewer.json()
        assert viewer_data["username"] == "new_viewer_01"
        assert viewer_data["role"] == "viewer"

        # 3. Newly created analyst signs in successfully
        login_res = client.post(
            "/api/v1/auth/login",
            json={"username": "new_analyst_01", "password": "AnalystPassword123!"},
        )
        assert login_res.status_code == 200
        assert login_res.json()["user"]["username"] == "new_analyst_01"

    def test_duplicate_usernames_and_emails_prevented(self, isolated_auth_db):
        user_repo, _, _ = isolated_auth_db
        admin = user_repo.create_user(
            username="super_admin",
            email="admin@corp.internal",
            password_hash=hash_password("AdminSecurePassword123!"),
            role="admin",
        )
        admin_token = create_access_token(
            user_id=admin["id"],
            username="super_admin",
            role=UserRole.ADMIN.value,
            org_id="default",
        )
        headers = {"Authorization": f"Bearer {admin_token}"}

        # Create first user
        client.post(
            "/api/v1/users",
            json={
                "username": "unique_analyst",
                "email": "unique@corp.internal",
                "password": "UniquePassword123!",
                "role": "analyst",
            },
            headers=headers,
        )

        # Attempt duplicate username
        res_dup_user = client.post(
            "/api/v1/users",
            json={
                "username": "unique_analyst",
                "email": "different_email@corp.internal",
                "password": "OtherPassword123!",
                "role": "analyst",
            },
            headers=headers,
        )
        assert res_dup_user.status_code == 400
        assert "already" in res_dup_user.json()["detail"].lower()

        # Attempt duplicate email
        res_dup_email = client.post(
            "/api/v1/users",
            json={
                "username": "another_analyst",
                "email": "unique@corp.internal",
                "password": "OtherPassword123!",
                "role": "analyst",
            },
            headers=headers,
        )
        assert res_dup_email.status_code == 400
        assert "already" in res_dup_email.json()["detail"].lower()

    def test_unauthorized_users_cannot_create_users(self, isolated_auth_db):
        user_repo, _, _ = isolated_auth_db
        analyst = user_repo.create_user(
            username="regular_analyst",
            email="analyst@corp.internal",
            password_hash=hash_password("AnalystPassword123!"),
            role="analyst",
        )
        analyst_token = create_access_token(
            user_id=analyst["id"],
            username="regular_analyst",
            role=UserRole.ANALYST.value,
            org_id="default",
        )

        # 1. Analyst attempting to create user is forbidden (403)
        res_analyst = client.post(
            "/api/v1/users",
            json={
                "username": "sneaky_user",
                "email": "sneaky@corp.internal",
                "password": "SneakyPassword123!",
                "role": "admin",
            },
            headers={"Authorization": f"Bearer {analyst_token}"},
        )
        assert res_analyst.status_code == 403

        # 2. Anonymous / unauthenticated request is rejected (401)
        res_anon = client.post(
            "/api/v1/users",
            json={
                "username": "anon_user",
                "email": "anon@corp.internal",
                "password": "AnonPassword123!",
                "role": "admin",
            },
        )
        assert res_anon.status_code in (401, 403)


class TestRegistrationPolicyAndEndpoints:
    def test_registration_status_endpoint(self, monkeypatch):
        # Default configuration: public registration disabled
        monkeypatch.setattr(settings, "ALLOW_PUBLIC_REGISTRATION", False)
        res = client.get("/api/v1/auth/registration-status")
        assert res.status_code == 200
        data = res.json()
        assert data["allow_public_registration"] is False
        assert data["registration_mode"] == "admin_provisioned"

        # Explicitly enabled configuration
        monkeypatch.setattr(settings, "ALLOW_PUBLIC_REGISTRATION", True)
        res_enabled = client.get("/api/v1/auth/registration-status")
        assert res_enabled.status_code == 200
        data_enabled = res_enabled.json()
        assert data_enabled["allow_public_registration"] is True
        assert data_enabled["registration_mode"] == "public"

    def test_public_registration_disabled_by_default(self, isolated_auth_db, monkeypatch):
        monkeypatch.setattr(settings, "ALLOW_PUBLIC_REGISTRATION", False)

        res = client.post(
            "/api/v1/auth/register",
            json={
                "username": "public_applicant",
                "email": "applicant@outside.com",
                "password": "PublicPassword123!",
            },
        )
        assert res.status_code == 403
        assert "disabled by enterprise security policy" in res.json()["detail"].lower()

    def test_public_registration_allowed_when_configured(self, isolated_auth_db, monkeypatch):
        monkeypatch.setattr(settings, "ALLOW_PUBLIC_REGISTRATION", True)

        res = client.post(
            "/api/v1/auth/register",
            json={
                "username": "registered_user",
                "email": "registered@outside.com",
                "password": "ValidRegPassword123!",
            },
        )
        assert res.status_code == 201
        data = res.json()
        assert data["username"] == "registered_user"
        assert data["role"] == "viewer"  # Publicly registered accounts safely default to viewer

        # Verify newly registered user can sign in
        login_res = client.post(
            "/api/v1/auth/login",
            json={"username": "registered_user", "password": "ValidRegPassword123!"},
        )
        assert login_res.status_code == 200
        assert login_res.json()["user"]["username"] == "registered_user"


class TestSQLiteDatabasePersistenceAcrossSessions:
    def test_users_persist_across_database_connections(self, isolated_auth_db):
        user_repo, db_path, _ = isolated_auth_db

        # Session 1: Create user via repository
        user_repo.create_user(
            username="persistent_officer",
            email="officer@soc.defense.gov",
            password_hash=hash_password("PersistentPass2026!"),
            role="analyst",
            org_id="soc_sector_7",
        )

        # Session 2: Open a fresh, distinct SQLite database connection to verify row persistence
        with get_db_cursor(db_path) as cursor:
            cursor.execute("SELECT id, username, email, role, org_id, password_hash FROM users WHERE username = ?", ("persistent_officer",))
            row = cursor.fetchone()

            assert row is not None
            assert row["username"] == "persistent_officer"
            assert row["email"] == "officer@soc.defense.gov"
            assert row["role"] == "analyst"
            assert row["org_id"] == "soc_sector_7"
            assert verify_password("PersistentPass2026!", row["password_hash"]) is True


class TestLoginToDashboardTransition:
    def test_unauthenticated_dashboard_endpoints_reject_with_401(self):
        client.cookies.clear()
        # 1. Calling dashboard metrics without token returns 401
        res_metrics = client.get("/api/v1/scan/metrics")
        assert res_metrics.status_code == 401
        assert "Authentication required" in res_metrics.json()["detail"]

        # 2. Calling scan records without token returns 401
        res_records = client.get("/api/v1/scan/records?limit=5&offset=0")
        assert res_records.status_code == 401
        assert "Authentication required" in res_records.json()["detail"]

        # 3. Calling audit verify without token returns 401
        res_audit = client.get("/api/v1/audit/verify")
        assert res_audit.status_code == 401
        assert "Authentication required" in res_audit.json()["detail"]

    def test_immediate_dashboard_metrics_loading_post_login(self, isolated_auth_db):
        user_repo, _, _ = isolated_auth_db
        user_repo.create_user(
            username="analyst_dashboard_user",
            email="analyst@enterprise.corp",
            password_hash=hash_password("DashboardPass2026!"),
            role="analyst",
        )

        # Step 1: User authenticates via /auth/login
        login_res = client.post(
            "/api/v1/auth/login",
            json={"username": "analyst_dashboard_user", "password": "DashboardPass2026!"},
        )
        assert login_res.status_code == 200
        token_data = login_res.json()
        token = token_data["access_token"]
        assert token is not None

        # Step 2: Dashboard mounts and requests metrics with token
        headers = {"Authorization": f"Bearer {token}"}

        res_metrics = client.get("/api/v1/scan/metrics", headers=headers)
        assert res_metrics.status_code == 200
        metrics = res_metrics.json()
        assert "total_scans" in metrics
        assert "total_findings" in metrics

        res_records = client.get("/api/v1/scan/records?limit=5&offset=0", headers=headers)
        assert res_records.status_code == 200
        records = res_records.json()
        assert "items" in records

        res_audit = client.get("/api/v1/audit/verify", headers=headers)
        assert res_audit.status_code == 200
        audit = res_audit.json()
        assert "is_valid" in audit

    def test_revoked_token_terminates_dashboard_access_with_clean_401(self, isolated_auth_db):
        user_repo, _, _ = isolated_auth_db
        user_repo.create_user(
            username="logged_out_analyst",
            email="analyst_out@enterprise.corp",
            password_hash=hash_password("PassOut12345!"),
            role="analyst",
        )

        login_res = client.post(
            "/api/v1/auth/login",
            json={"username": "logged_out_analyst", "password": "PassOut12345!"},
        )
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Verify access works
        res_before = client.get("/api/v1/scan/metrics", headers=headers)
        assert res_before.status_code == 200

        # User logs out
        logout_res = client.post("/api/v1/auth/logout", headers=headers)
        assert logout_res.status_code == 200

        # Subsequent dashboard fetch returns 401 with revocation details
        res_after = client.get("/api/v1/scan/metrics", headers=headers)
        assert res_after.status_code == 401
        assert "revoked" in res_after.json()["detail"].lower()
