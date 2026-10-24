import pytest
from unittest.mock import MagicMock, patch
from google.genai import errors

from app.ai.connectivity import (
    STATUS_API_ACCESS_OR_QUOTA_ISSUE,
    STATUS_AUTHENTICATION_FAILED,
    STATUS_CONNECTED,
    STATUS_MODEL_OR_REQUEST_ERROR,
    STATUS_NETWORK_ERROR,
    STATUS_NOT_CONFIGURED,
    check_gemini_connectivity,
)


class TestGeminiConnectivity:
    """Verifies that connectivity testing accurately reports status and protects secrets."""

    def test_unconfigured_api_key(self):
        with patch.dict("os.environ", {}, clear=True):
            with patch("app.core.config.settings.GEMINI_API_KEY", None):
                res = check_gemini_connectivity(api_key=None)
                assert res["configured"] is False
                assert res["connected"] is False
                assert res["status"] == STATUS_NOT_CONFIGURED
                assert res["error_type"] == "NOT_CONFIGURED"
                assert "GEMINI_API_KEY" in res["message"]
                # Must not contain any secrets
                assert "api_key" not in res or res["api_key"] is None

    def test_successful_connection(self):
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.text = "GEMINI_CONNECTION_OK"
        mock_client.models.generate_content.return_value = mock_resp

        with patch("google.genai.Client", return_value=mock_client):
            res = check_gemini_connectivity(api_key="valid-mock-key", model="gemini-2.5-flash")
            assert res["configured"] is True
            assert res["connected"] is True
            assert res["status"] == STATUS_CONNECTED
            assert res["model"] == "gemini-2.5-flash"
            assert res["latency_ms"] is not None
            assert res["latency_ms"] >= 0
            assert res["error_type"] is None
            assert res["response_preview"] == "GEMINI_CONNECTION_OK"
            # Ensure key is never returned
            assert "valid-mock-key" not in str(res)

    def test_authentication_failed_error(self):
        mock_client = MagicMock()
        mock_err = errors.APIError(
            400,
            {"error": {"code": 400, "message": "API key not valid. Please pass a valid API key.", "status": "INVALID_ARGUMENT"}},
        )
        mock_client.models.generate_content.side_effect = mock_err

        with patch("google.genai.Client", return_value=mock_client):
            res = check_gemini_connectivity(api_key="bad-key-1234")
            assert res["configured"] is True
            assert res["connected"] is False
            assert res["status"] == STATUS_AUTHENTICATION_FAILED
            assert res["error_type"] == "AUTHENTICATION_FAILED"
            assert "bad-key-1234" not in str(res)

    def test_quota_exhausted_error(self):
        mock_client = MagicMock()
        mock_err = errors.APIError(
            429,
            {"error": {"code": 429, "message": "Resource has been exhausted (e.g. check quota).", "status": "RESOURCE_EXHAUSTED"}},
        )
        mock_client.models.generate_content.side_effect = mock_err

        with patch("google.genai.Client", return_value=mock_client):
            res = check_gemini_connectivity(api_key="quota-key")
            assert res["configured"] is True
            assert res["connected"] is False
            assert res["status"] == STATUS_API_ACCESS_OR_QUOTA_ISSUE
            assert res["error_type"] == "API_ACCESS_OR_QUOTA_ISSUE"
            assert "quota-key" not in str(res)

    def test_model_not_found_error(self):
        mock_client = MagicMock()
        mock_err = errors.APIError(
            404,
            {"error": {"code": 404, "message": "models/nonexistent-model is not found", "status": "NOT_FOUND"}},
        )
        mock_client.models.generate_content.side_effect = mock_err

        with patch("google.genai.Client", return_value=mock_client):
            res = check_gemini_connectivity(api_key="test-key", model="nonexistent-model")
            assert res["configured"] is True
            assert res["connected"] is False
            assert res["status"] == STATUS_MODEL_OR_REQUEST_ERROR
            assert res["error_type"] == "MODEL_OR_REQUEST_ERROR"

    def test_network_failure_error(self):
        mock_client = MagicMock()
        mock_client.models.generate_content.side_effect = ConnectionError("Failed to establish a new connection: DNS resolution failure")

        with patch("google.genai.Client", return_value=mock_client):
            res = check_gemini_connectivity(api_key="test-key")
            assert res["configured"] is True
            assert res["connected"] is False
            assert res["status"] == STATUS_NETWORK_ERROR
            assert res["error_type"] == "NETWORK_ERROR"
