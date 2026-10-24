import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_root_endpoint():
    """Verify root endpoint provides discoverability links."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "DataShield AI"
    assert "version" in data
    assert data["health"] == "/api/health"


def test_health_check_endpoint():
    """Verify /api/health returns valid operational status."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "datashield-ai-backend"
    assert "version" in data
    assert "timestamp" in data
    assert "environment" in data
    assert "mode" in data["environment"]
    assert "llm_configured" in data["environment"]
    # Verify no raw secrets leaked
    assert "GEMINI_API_KEY" not in str(data)


def test_health_readiness_endpoint():
    """Verify /api/health/ready responds with 200 and database connectivity state."""
    response = client.get("/api/health/ready")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ready"
    assert data["database"] == "connected"
    assert "timestamp" in data

