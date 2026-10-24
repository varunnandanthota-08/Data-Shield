import os
import tempfile
import threading
import time
from datetime import datetime, timezone
from unittest.mock import MagicMock, PropertyMock, patch
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.main import app
from app.ai.budget import AIBudgetService, BudgetCheckResult, ai_budget_service
from app.ai.service import GeminiContextAnalysisService
from app.audit.service import audit_service
from app.auth.models import UserResponse, UserRole
from app.auth.repository import UserRepository, token_revocation_repo, user_repo
from app.auth.security import create_access_token, hash_password
from app.core.config import Settings, settings
from app.db.repository import policy_repo, scan_record_repo
from app.db.schema import init_db
from app.engine.orchestrator import engine
from app.engine.schemas import Finding, FindingCategory, SeverityLevel
from app.policy.engine import policy_engine
from app.policy.risk_scorer import risk_scorer
from app.policy.schemas import (
    DataClassification,
    DestinationType,
    PolicyAction,
    RecipientType,
    SharingContext,
)


# ---------------------------------------------------------------------------
# Test Fixture: Isolated SQLite Database
# ---------------------------------------------------------------------------
@pytest.fixture
def isolated_budget_db(tmp_path, monkeypatch):
    """Provides a fresh isolated SQLite database with full schema for AI budget testing."""
    test_db = str(tmp_path / "datashield_budget_test.db")
    monkeypatch.setenv("SQLITE_DB_PATH", test_db)
    monkeypatch.setenv("AI_BUDGET_ENABLED", "true")
    monkeypatch.setenv("AI_BUDGET_USER_DAILY_LIMIT", "200")
    monkeypatch.setenv("AI_BUDGET_TENANT_DAILY_LIMIT", "2500")
    monkeypatch.setenv("AI_BUDGET_TENANT_HARD_CEILING", "5000")
    monkeypatch.setenv("AI_BUDGET_WINDOW_SECONDS", "86400")

    init_db(test_db)

    # Patch global repo and service paths to target isolated database
    old_budget_db = ai_budget_service._db_path
    old_user_db = user_repo.db_path
    old_token_db = token_revocation_repo.db_path
    old_pol_db = policy_repo.db_path
    old_scan_db = scan_record_repo.db_path
    old_audit_db = audit_service.db_path

    ai_budget_service._db_path = test_db
    user_repo.db_path = test_db
    token_revocation_repo.db_path = test_db
    policy_repo.db_path = test_db
    scan_record_repo.db_path = test_db
    audit_service.db_path = test_db

    policy_engine.set_rules(policy_repo.list_policies())

    yield test_db

    ai_budget_service._db_path = old_budget_db
    user_repo.db_path = old_user_db
    token_revocation_repo.db_path = old_token_db
    policy_repo.db_path = old_pol_db
    scan_record_repo.db_path = old_scan_db
    audit_service.db_path = old_audit_db


# ---------------------------------------------------------------------------
# SECTION 1: CONFIGURATION VALIDATION & HIERARCHY
# ---------------------------------------------------------------------------
class TestAIBudgetConfiguration:
    """Verifies startup configuration constraints, hierarchy invariants,
    and positive integer enforcement.
    """

    def test_valid_default_configuration(self):
        cfg = Settings(
            AI_BUDGET_ENABLED=True,
            AI_BUDGET_USER_DAILY_LIMIT=200,
            AI_BUDGET_TENANT_DAILY_LIMIT=2500,
            AI_BUDGET_TENANT_HARD_CEILING=5000,
            AI_BUDGET_WINDOW_SECONDS=86400,
        )
        assert cfg.AI_BUDGET_USER_DAILY_LIMIT == 200
        assert cfg.AI_BUDGET_TENANT_DAILY_LIMIT == 2500
        assert cfg.AI_BUDGET_TENANT_HARD_CEILING == 5000
        assert cfg.AI_BUDGET_WINDOW_SECONDS == 86400

    def test_rejects_negative_or_zero_limits(self):
        with pytest.raises(ValidationError) as exc:
            Settings(AI_BUDGET_USER_DAILY_LIMIT=0)
        assert "positive integer (> 0)" in str(exc.value)

        with pytest.raises(ValidationError) as exc:
            Settings(AI_BUDGET_TENANT_DAILY_LIMIT=-10)
        assert "positive integer (> 0)" in str(exc.value)

        with pytest.raises(ValidationError) as exc:
            Settings(AI_BUDGET_TENANT_HARD_CEILING=0)
        assert "positive integer (> 0)" in str(exc.value)

        with pytest.raises(ValidationError) as exc:
            Settings(AI_BUDGET_WINDOW_SECONDS=-100)
        assert "positive integer (> 0)" in str(exc.value)

    def test_rejects_tenant_limit_exceeding_hard_ceiling(self):
        """Configured tenant limit cannot exceed the platform hard safety ceiling."""
        with pytest.raises(ValidationError) as exc:
            Settings(
                AI_BUDGET_TENANT_DAILY_LIMIT=6000,
                AI_BUDGET_TENANT_HARD_CEILING=5000,
            )
        assert "cannot exceed tenant hard ceiling" in str(exc.value)

    def test_rejects_user_limit_exceeding_tenant_limit(self):
        """User daily limit cannot exceed tenant total daily limit."""
        with pytest.raises(ValidationError) as exc:
            Settings(
                AI_BUDGET_USER_DAILY_LIMIT=3000,
                AI_BUDGET_TENANT_DAILY_LIMIT=2500,
                AI_BUDGET_TENANT_HARD_CEILING=5000,
            )
        assert "cannot exceed tenant daily limit" in str(exc.value)


# ---------------------------------------------------------------------------
# SECTION 2: ATOMIC RESERVATION & PERSISTENCE
# ---------------------------------------------------------------------------
class TestAIBudgetAccountingAndPersistence:
    """Verifies atomic reservations, user limits, tenant limits, hard-ceiling bounds,
    rolling-window expiry, and SQLite restart persistence.
    """

    def test_user_limit_enforcement(self, isolated_budget_db, monkeypatch):
        """User is capped after exceeding their daily quota."""
        monkeypatch.setattr(settings, "AI_BUDGET_USER_DAILY_LIMIT", 5)
        monkeypatch.setattr(settings, "AI_BUDGET_TENANT_DAILY_LIMIT", 100)
        monkeypatch.setattr(settings, "AI_BUDGET_TENANT_HARD_CEILING", 200)

        svc = AIBudgetService(db_path=isolated_budget_db)

        # First 5 reservations succeed
        for i in range(5):
            res = svc.check_and_reserve(user_id="user_1", org_id="org_alpha")
            assert res.allowed is True
            assert res.user_usage == i + 1

        # 6th reservation is rejected
        rejected = svc.check_and_reserve(user_id="user_1", org_id="org_alpha")
        assert rejected.allowed is False
        assert rejected.exhausted_scope == "user"
        assert "User AI daily usage budget exhausted" in rejected.reason
        assert rejected.user_usage == 5

        # Different user in the same tenant is unaffected
        res_user2 = svc.check_and_reserve(user_id="user_2", org_id="org_alpha")
        assert res_user2.allowed is True
        assert res_user2.user_usage == 1

    def test_tenant_limit_enforcement(self, isolated_budget_db, monkeypatch):
        """Tenant aggregate limit exhausts even if individual users haven't exhausted theirs."""
        monkeypatch.setattr(settings, "AI_BUDGET_USER_DAILY_LIMIT", 50)
        monkeypatch.setattr(settings, "AI_BUDGET_TENANT_DAILY_LIMIT", 4)
        monkeypatch.setattr(settings, "AI_BUDGET_TENANT_HARD_CEILING", 10)

        svc = AIBudgetService(db_path=isolated_budget_db)

        # 4 different users each make 1 request
        for i in range(4):
            res = svc.check_and_reserve(user_id=f"user_{i}", org_id="org_alpha")
            assert res.allowed is True
            assert res.tenant_usage == i + 1

        # 5th request from a fresh user is rejected due to tenant budget exhaustion
        rejected = svc.check_and_reserve(user_id="user_fresh", org_id="org_alpha")
        assert rejected.allowed is False
        assert rejected.exhausted_scope == "tenant"
        assert "Tenant AI daily usage budget exhausted" in rejected.reason
        assert rejected.tenant_usage == 4

    def test_tenant_hard_ceiling_enforcement(self, isolated_budget_db, monkeypatch):
        """Tenant hard ceiling is strictly enforced if tenant limit is set to the ceiling."""
        monkeypatch.setattr(settings, "AI_BUDGET_USER_DAILY_LIMIT", 50)
        monkeypatch.setattr(settings, "AI_BUDGET_TENANT_DAILY_LIMIT", 3)
        monkeypatch.setattr(settings, "AI_BUDGET_TENANT_HARD_CEILING", 3)

        svc = AIBudgetService(db_path=isolated_budget_db)

        for i in range(3):
            res = svc.check_and_reserve(user_id=f"user_{i}", org_id="org_alpha")
            assert res.allowed is True

        rejected = svc.check_and_reserve(user_id="user_next", org_id="org_alpha")
        assert rejected.allowed is False
        assert rejected.exhausted_scope in ("tenant_hard_ceiling", "tenant")

    def test_rolling_window_expiry(self, isolated_budget_db, monkeypatch):
        """Reservations older than 24 hours (86,400s) expire and restore quota."""
        monkeypatch.setattr(settings, "AI_BUDGET_USER_DAILY_LIMIT", 2)
        monkeypatch.setattr(settings, "AI_BUDGET_TENANT_DAILY_LIMIT", 10)
        monkeypatch.setattr(settings, "AI_BUDGET_TENANT_HARD_CEILING", 20)
        monkeypatch.setattr(settings, "AI_BUDGET_WINDOW_SECONDS", 86400)

        svc = AIBudgetService(db_path=isolated_budget_db)
        base_time = 1700000000.0

        # User makes 2 reservations 25 hours ago
        old_time = base_time - 90000.0  # 25 hours prior
        r1 = svc.check_and_reserve(user_id="user_1", org_id="org_alpha", now=old_time)
        r2 = svc.check_and_reserve(user_id="user_1", org_id="org_alpha", now=old_time)
        assert r1.allowed is True
        assert r2.allowed is True

        # Now at base_time (25 hours later), old reservations have expired
        r3 = svc.check_and_reserve(user_id="user_1", org_id="org_alpha", now=base_time)
        assert r3.allowed is True
        assert r3.user_usage == 1

    def test_persistence_after_restart(self, isolated_budget_db, monkeypatch):
        """Usage records persist across separate service instantiations pointing to SQLite."""
        monkeypatch.setattr(settings, "AI_BUDGET_USER_DAILY_LIMIT", 3)
        monkeypatch.setattr(settings, "AI_BUDGET_TENANT_DAILY_LIMIT", 10)
        monkeypatch.setattr(settings, "AI_BUDGET_TENANT_HARD_CEILING", 20)

        # Instance 1 reserves 2 slots
        svc1 = AIBudgetService(db_path=isolated_budget_db)
        svc1.check_and_reserve(user_id="user_persist", org_id="org_alpha")
        svc1.check_and_reserve(user_id="user_persist", org_id="org_alpha")

        # Simulate restart by creating completely new service instance pointing to same DB
        svc2 = AIBudgetService(db_path=isolated_budget_db)
        summary = svc2.get_usage_summary(user_id="user_persist", org_id="org_alpha")
        assert summary["user_budget"]["used"] == 2
        assert summary["user_budget"]["remaining"] == 1

        # 3rd reservation succeeds
        r3 = svc2.check_and_reserve(user_id="user_persist", org_id="org_alpha")
        assert r3.allowed is True

        # 4th reservation is blocked
        r4 = svc2.check_and_reserve(user_id="user_persist", org_id="org_alpha")
        assert r4.allowed is False

    def test_concurrent_reservations_atomicity(self, isolated_budget_db, monkeypatch):
        """Concurrent requests cannot bypass configured limits."""
        monkeypatch.setattr(settings, "AI_BUDGET_USER_DAILY_LIMIT", 10)
        monkeypatch.setattr(settings, "AI_BUDGET_TENANT_DAILY_LIMIT", 100)
        monkeypatch.setattr(settings, "AI_BUDGET_TENANT_HARD_CEILING", 200)

        svc = AIBudgetService(db_path=isolated_budget_db)
        results = []

        def worker():
            res = svc.check_and_reserve(user_id="user_concurrent", org_id="org_alpha")
            results.append(res.allowed)

        # Spawn 25 concurrent threads attempting to reserve 10 available slots
        threads = [threading.Thread(target=worker) for _ in range(25)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        successes = sum(1 for allowed in results if allowed)
        rejections = sum(1 for allowed in results if not allowed)

        assert successes == 10, f"Expected exactly 10 successes, got {successes}"
        assert rejections == 15, f"Expected exactly 15 rejections, got {rejections}"

        summary = svc.get_usage_summary(user_id="user_concurrent", org_id="org_alpha")
        assert summary["user_budget"]["used"] == 10
        assert summary["user_budget"]["remaining"] == 0

    def test_tenant_isolation(self, isolated_budget_db, monkeypatch):
        """Org Alpha exhausting its daily budget does not affect Org Beta."""
        monkeypatch.setattr(settings, "AI_BUDGET_USER_DAILY_LIMIT", 100)
        monkeypatch.setattr(settings, "AI_BUDGET_TENANT_DAILY_LIMIT", 2)
        monkeypatch.setattr(settings, "AI_BUDGET_TENANT_HARD_CEILING", 10)

        svc = AIBudgetService(db_path=isolated_budget_db)

        # Org Alpha uses its 2 slots
        svc.check_and_reserve(user_id="alpha_1", org_id="org_alpha")
        svc.check_and_reserve(user_id="alpha_2", org_id="org_alpha")

        # Org Alpha is now exhausted
        r_alpha = svc.check_and_reserve(user_id="alpha_3", org_id="org_alpha")
        assert r_alpha.allowed is False
        assert r_alpha.exhausted_scope == "tenant"

        # Org Beta is completely unblocked
        r_beta1 = svc.check_and_reserve(user_id="beta_1", org_id="org_beta")
        r_beta2 = svc.check_and_reserve(user_id="beta_2", org_id="org_beta")
        assert r_beta1.allowed is True
        assert r_beta2.allowed is True
        assert r_beta2.tenant_usage == 2

        alpha_sum = svc.get_usage_summary(user_id="alpha_1", org_id="org_alpha")
        beta_sum = svc.get_usage_summary(user_id="beta_1", org_id="org_beta")
        assert alpha_sum["tenant_budget"]["used"] == 2
        assert alpha_sum["tenant_budget"]["is_exhausted"] is True
        assert beta_sum["tenant_budget"]["used"] == 2


# ---------------------------------------------------------------------------
# SECTION 3: DLP ENFORCEMENT & GEMINI PROVIDER PRESERVATION
# ---------------------------------------------------------------------------
class TestDLPEnforcementWithBudgetExhaustion:
    """Verifies that when AI budget is exhausted:
    1. Gemini provider call is skipped entirely.
    2. Deterministic explanation fallback is returned.
    3. Mandatory BLOCK and policy decisions are preserved.
    4. Scans are never rejected due to AI budget exhaustion alone.
    """

    def test_skipped_gemini_call_when_budget_exhausted(self, isolated_budget_db, monkeypatch):
        """When budget is exhausted, Gemini API client is never initialized or called."""
        monkeypatch.setattr(settings, "AI_BUDGET_USER_DAILY_LIMIT", 1)
        monkeypatch.setattr(settings, "AI_BUDGET_TENANT_DAILY_LIMIT", 10)
        monkeypatch.setattr(settings, "AI_BUDGET_TENANT_HARD_CEILING", 20)

        ai_svc = GeminiContextAnalysisService()
        ctx = SharingContext(actor_id="user_exhaust", org_id="org_alpha")
        pol_res = policy_engine.evaluate([], ctx)
        risk_res = risk_scorer.calculate_risk([], ctx, pol_res)

        # Exhaust 1 slot
        res1 = ai_budget_service.check_and_reserve(user_id="user_exhaust", org_id="org_alpha")
        assert res1.allowed is True

        with patch.object(GeminiContextAnalysisService, "is_configured", new_callable=PropertyMock, return_value=True):
            with patch.object(ai_svc, "_get_client") as mock_get_client:
                # Call analyze_context on exhausted user
                analysis = ai_svc.analyze_context(
                    sanitized_text="Non-sensitive operational review text.",
                    findings=[],
                    context=ctx,
                    policy_result=pol_res,
                    risk_result=risk_res,
                    user_id="user_exhaust",
                )

                # Provider client must NOT have been called
                mock_get_client.assert_not_called()

                # Analysis must truthfully declare fallback
                assert analysis.ai_status == "FALLBACK"
                assert analysis.is_ai_assisted is False
                assert analysis.usage is not None
                assert analysis.usage.budget_exhausted is True
                assert analysis.usage.budget_scope == "user"
                assert analysis.usage.error_type == "AI_BUDGET_EXHAUSTED"
                assert analysis.usage.api_calls_count == 0
                assert "budget reached" in analysis.disclaimer.lower()

    def test_mandatory_block_preserved_during_budget_exhaustion(self, isolated_budget_db, monkeypatch):
        """Mandatory BLOCK policy decision is preserved and cannot be downgraded by AI fallback."""
        monkeypatch.setattr(settings, "AI_BUDGET_USER_DAILY_LIMIT", 1)
        monkeypatch.setattr(settings, "AI_BUDGET_TENANT_DAILY_LIMIT", 10)

        ai_svc = GeminiContextAnalysisService()
        ctx = SharingContext(
            destination=DestinationType.PUBLIC_LLM,
            recipient=RecipientType.PUBLIC,
            classification=DataClassification.CONFIDENTIAL,
            actor_id="user_block_test",
            org_id="default",
        )
        scan_res = engine.scan_and_redact("Deploying worker using AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE' into production.")
        pol_res = policy_engine.evaluate(scan_res.findings, ctx)
        risk_res = risk_scorer.calculate_risk(scan_res.findings, ctx, pol_res)

        assert pol_res.final_decision == PolicyAction.BLOCK
        assert risk_res.final_decision == PolicyAction.BLOCK

        # Exhaust user budget
        ai_budget_service.check_and_reserve(user_id="user_block_test", org_id="default")

        analysis = ai_svc.analyze_context(
            sanitized_text=scan_res.redacted_text,
            findings=scan_res.findings,
            context=ctx,
            policy_result=pol_res,
            risk_result=risk_res,
            user_id="user_block_test",
        )

        # Verify deterministic fallback properties
        assert analysis.ai_status == "FALLBACK"
        assert analysis.usage.budget_exhausted is True
        assert analysis.human_review_recommended is True
        assert any("block" in r.lower() or "POL-001" in r for r in analysis.policy_rationales.keys())

    def test_scan_not_rejected_when_budget_exhausted(self, isolated_budget_db, monkeypatch):
        """A full scan via HTTP endpoint returns HTTP 200 with complete findings
        even when the AI budget is completely exhausted.
        """
        monkeypatch.setattr(settings, "AI_BUDGET_USER_DAILY_LIMIT", 1)
        monkeypatch.setattr(settings, "AI_BUDGET_TENANT_DAILY_LIMIT", 5)

        # Seed user and exhaust budget
        u_repo = UserRepository(db_path=isolated_budget_db)
        u_repo.create_user(
            username="analyst_01",
            email="analyst01@example.com",
            password_hash=hash_password("Password123!"),
            role=UserRole.ANALYST.value,
            org_id="default",
            user_id="usr_analyst_01",
        )
        # Exhaust user's 1 budget slot
        ai_budget_service.check_and_reserve(user_id="usr_analyst_01", org_id="default")

        token = create_access_token(
            user_id="usr_analyst_01",
            username="analyst_01",
            role="analyst",
            org_id="default",
        )
        headers = {"Authorization": f"Bearer {token}"}

        client = TestClient(app)
        payload = {
            "text": "Applicant government SSN is 123-45-6789 submitted for processing.",
            "context": {
                "destination": "PUBLIC_LLM",
                "recipient": "PUBLIC",
                "classification": "CONFIDENTIAL",
            },
        }

        resp = client.post("/api/v1/scan/text", json=payload, headers=headers)
        assert resp.status_code == 200, f"Expected 200 OK, got {resp.status_code}: {resp.text}"

        data = resp.json()
        # Scan findings must be completely preserved
        assert len(data["findings"]) >= 1
        assert any(f["rule_id"] == "pii_us_ssn" for f in data["findings"])
        assert "[REDACTED_SSN]" in data["redacted_text"]

        # Policy decision enforced deterministically
        assert data["policy_decision"] in ("BLOCK", "REQUIRE_APPROVAL")

        # AI analysis shows fallback with budget exhaustion indicated
        ai_info = data.get("ai_analysis", {})
        assert ai_info.get("ai_status") == "FALLBACK"
        usage = ai_info.get("usage", {})
        assert usage.get("budget_exhausted") is True
        assert usage.get("error_type") == "AI_BUDGET_EXHAUSTED"


# ---------------------------------------------------------------------------
# SECTION 4: AUTHORIZATION & USAGE SUMMARY ENDPOINT
# ---------------------------------------------------------------------------
class TestAIBudgetSummaryEndpoint:
    """Verifies that the /api/v1/scan/ai-budget endpoint enforces authentication,
    role-based breakdown access, and strict organization isolation.
    """

    def test_unauthenticated_request_rejected(self, isolated_budget_db):
        """Unauthenticated call to /api/v1/scan/ai-budget returns 401."""
        client = TestClient(app)
        resp = client.get("/api/v1/scan/ai-budget")
        assert resp.status_code == 401

    def test_authenticated_user_retrieves_own_budget(self, isolated_budget_db):
        """Authenticated Analyst retrieves own quota and tenant quota without seeing other tenants."""
        u_repo = UserRepository(db_path=isolated_budget_db)
        u_repo.create_user(
            username="analyst_alpha",
            email="analyst@alpha.org",
            password_hash=hash_password("Password123!"),
            role=UserRole.ANALYST.value,
            org_id="org_alpha",
            user_id="usr_analyst_alpha",
        )
        ai_budget_service.check_and_reserve(user_id="usr_analyst_alpha", org_id="org_alpha")

        token = create_access_token(
            user_id="usr_analyst_alpha",
            username="analyst_alpha",
            role="analyst",
            org_id="org_alpha",
        )
        headers = {"Authorization": f"Bearer {token}"}

        client = TestClient(app)
        resp = client.get("/api/v1/scan/ai-budget", headers=headers)
        assert resp.status_code == 200
        data = resp.json()

        assert data["enabled"] is True
        assert data["user_budget"]["user_id"] == "usr_analyst_alpha"
        assert data["user_budget"]["used"] == 1
        assert data["tenant_budget"]["org_id"] == "org_alpha"
        assert data["tenant_budget"]["used"] == 1
        assert "user_breakdown" not in data  # Regular Analyst does not receive user breakdown

    def test_admin_receives_tenant_user_breakdown(self, isolated_budget_db):
        """Tenant Admin receives aggregated per-user breakdown strictly within their tenant."""
        u_repo = UserRepository(db_path=isolated_budget_db)
        u_repo.create_user(
            username="admin_beta",
            email="admin@beta.org",
            password_hash=hash_password("Password123!"),
            role=UserRole.ADMIN.value,
            org_id="org_beta",
            user_id="usr_admin_beta",
        )
        # Seed 2 reservations for user_b1, 1 for user_b2 in org_beta
        ai_budget_service.check_and_reserve(user_id="user_b1", org_id="org_beta")
        ai_budget_service.check_and_reserve(user_id="user_b1", org_id="org_beta")
        ai_budget_service.check_and_reserve(user_id="user_b2", org_id="org_beta")

        # Seed reservation in org_gamma to verify isolation
        ai_budget_service.check_and_reserve(user_id="user_g1", org_id="org_gamma")

        token = create_access_token(
            user_id="usr_admin_beta",
            username="admin_beta",
            role="admin",
            org_id="org_beta",
        )
        headers = {"Authorization": f"Bearer {token}"}

        client = TestClient(app)
        resp = client.get("/api/v1/scan/ai-budget", headers=headers)
        assert resp.status_code == 200
        data = resp.json()

        assert data["tenant_budget"]["org_id"] == "org_beta"
        assert data["tenant_budget"]["used"] == 3
        assert "user_breakdown" in data

        breakdown = {u["user_id"]: u["scan_count"] for u in data["user_breakdown"]}
        assert breakdown["user_b1"] == 2
        assert breakdown["user_b2"] == 1
        # org_gamma user must NOT appear in org_beta breakdown
        assert "user_g1" not in breakdown
