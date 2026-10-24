import pytest
from app.main import app
from app.auth.dependencies import get_current_user
from app.auth.models import UserResponse, UserRole
from app.auth.rate_limiter import auth_rate_limiter, scan_rate_limiter


@pytest.fixture(autouse=True)
def manage_auth_overrides(request):
    """Provides a default authenticated Admin user for all legacy test suites
    to ensure zero regressions across existing tests, while allowing auth,
    tenant-isolation, and hardening suites to execute genuine unmocked security checks.
    """
    auth_rate_limiter.reset_all()
    scan_rate_limiter.reset_all()

    if (
        "test_auth_and_rbac" in request.node.nodeid
        or "test_tenant_isolation" in request.node.nodeid
        or "test_production_security_hardening" in request.node.nodeid
        or "test_phase5_e2e_acceptance" in request.node.nodeid
        or "test_auth_registration" in request.node.nodeid
        or "test_ai_usage_budgets" in request.node.nodeid
    ):
        # Do not override auth dependencies for dedicated security testing suites
        app.dependency_overrides.pop(get_current_user, None)
        yield
        app.dependency_overrides.pop(get_current_user, None)
        return

    mock_admin = UserResponse(
        id="test-admin-id",
        username="test_admin",
        email="test_admin@datashield.local",
        role=UserRole.ADMIN,
        org_id="default",
        is_active=True,
    )
    app.dependency_overrides[get_current_user] = lambda: mock_admin
    try:
        yield
    finally:
        app.dependency_overrides.pop(get_current_user, None)
