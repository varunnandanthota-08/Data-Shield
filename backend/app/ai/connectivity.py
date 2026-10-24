import logging
import os
import time
from typing import Any, Dict, Optional
from app.core.config import settings

logger = logging.getLogger(__name__)

# Canonical diagnostic status codes matching DataShield AI verification criteria
STATUS_CONNECTED = "CONNECTED"
STATUS_NOT_CONFIGURED = "NOT_CONFIGURED"
STATUS_AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
STATUS_API_ACCESS_OR_QUOTA_ISSUE = "API_ACCESS_OR_QUOTA_ISSUE"
STATUS_MODEL_OR_REQUEST_ERROR = "MODEL_OR_REQUEST_ERROR"
STATUS_NETWORK_ERROR = "NETWORK_ERROR"
STATUS_UNKNOWN_ERROR = "UNKNOWN_ERROR"

SAFE_TEST_PROMPT = "Reply with exactly: GEMINI_CONNECTION_OK"


def check_gemini_connectivity(
    api_key: Optional[str] = None,
    model: Optional[str] = None,
    timeout_seconds: Optional[float] = None,
) -> Dict[str, Any]:
    """Safely tests connectivity to Google Gemini API using google-genai SDK.
    
    Adheres strictly to zero-trust privacy controls:
    - Never logs, prints, or returns the API key or sensitive headers.
    - Sends only a harmless, non-sensitive verification prompt.
    - Handles and classifies exceptions accurately.
    - Returns structured diagnostic telemetry.
    """
    effective_model = model or settings.GEMINI_MODEL
    effective_timeout = timeout_seconds or settings.GEMINI_TIMEOUT_SECONDS
    key = (api_key or settings.GEMINI_API_KEY or os.environ.get("GEMINI_API_KEY") or "").strip()

    if not key:
        return {
            "configured": False,
            "connected": False,
            "status": STATUS_NOT_CONFIGURED,
            "model": effective_model,
            "latency_ms": None,
            "error_type": "NOT_CONFIGURED",
            "message": "GEMINI_API_KEY is not configured or is empty. Set the GEMINI_API_KEY environment variable or configure it in .env.",
        }

    # Verify google-genai SDK is available
    try:
        from google import genai
        from google.genai import errors, types
    except ImportError as imp_err:
        return {
            "configured": True,
            "connected": False,
            "status": STATUS_MODEL_OR_REQUEST_ERROR,
            "model": effective_model,
            "latency_ms": None,
            "error_type": "SDK_IMPORT_ERROR",
            "message": f"google-genai SDK is not installed or import failed: {imp_err}",
        }

    # Initialize client
    start_time = time.perf_counter()
    try:
        client = genai.Client(api_key=key)
    except Exception as init_err:
        return {
            "configured": True,
            "connected": False,
            "status": STATUS_MODEL_OR_REQUEST_ERROR,
            "model": effective_model,
            "latency_ms": None,
            "error_type": "CLIENT_INITIALIZATION_ERROR",
            "message": f"Failed to initialize GenAI client: {type(init_err).__name__}",
        }

    # Execute harmless connectivity probe with bounded retries for transient capacity demand
    max_retries = settings.GEMINI_MAX_RETRIES
    for attempt in range(max_retries + 1):
        try:
            response = client.models.generate_content(
                model=effective_model,
                contents=SAFE_TEST_PROMPT,
                config=types.GenerateContentConfig(
                    temperature=0.0,
                    max_output_tokens=512,
                ),
            )
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

            resp_text = (response.text or "").strip() if response else ""
            if not resp_text:
                return {
                    "configured": True,
                    "connected": False,
                    "status": STATUS_MODEL_OR_REQUEST_ERROR,
                    "model": effective_model,
                    "latency_ms": elapsed_ms,
                    "error_type": "EMPTY_RESPONSE",
                    "message": "Received empty response from Gemini API.",
                }

            return {
                "configured": True,
                "connected": True,
                "status": STATUS_CONNECTED,
                "model": effective_model,
                "latency_ms": elapsed_ms,
                "error_type": None,
                "message": "Successfully connected to Google Gemini API and verified response.",
                "response_preview": resp_text[:100],
            }

        except errors.APIError as api_err:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            code = getattr(api_err, "code", None)
            status_str = str(getattr(api_err, "status", "")).upper()
            raw_msg = (getattr(api_err, "message", "") or str(api_err)).lower()

            # Classify API error
            if (
                code in (401, 403)
                or "api key not valid" in raw_msg
                or "api_key_invalid" in raw_msg
                or "permission_denied" in status_str
                or "unauthenticated" in status_str
            ):
                return {
                    "configured": True,
                    "connected": False,
                    "status": STATUS_AUTHENTICATION_FAILED,
                    "model": effective_model,
                    "latency_ms": elapsed_ms,
                    "error_type": "AUTHENTICATION_FAILED",
                    "message": f"Gemini API rejected credentials (HTTP {code} / {status_str}): Invalid or unauthorized API key.",
                }

            if (
                code in (429, 503)
                or "resource_exhausted" in status_str
                or "unavailable" in status_str
                or "quota" in raw_msg
                or "rate limit" in raw_msg
                or "billing" in raw_msg
                or "high demand" in raw_msg
            ):
                if attempt < max_retries:
                    time.sleep(1.0 * (2 ** attempt))
                    continue
                return {
                    "configured": True,
                    "connected": False,
                    "status": STATUS_API_ACCESS_OR_QUOTA_ISSUE,
                    "model": effective_model,
                    "latency_ms": elapsed_ms,
                    "error_type": "API_ACCESS_OR_QUOTA_ISSUE",
                    "message": f"Gemini API quota, rate limit, capacity constraint, or high demand reached (HTTP {code} / {status_str}).",
                }

            if (
                code in (400, 404)
                or "not_found" in status_str
                or "model not found" in raw_msg
                or "invalid_argument" in status_str
            ):
                return {
                    "configured": True,
                    "connected": False,
                    "status": STATUS_MODEL_OR_REQUEST_ERROR,
                    "model": effective_model,
                    "latency_ms": elapsed_ms,
                    "error_type": "MODEL_OR_REQUEST_ERROR",
                    "message": f"Model '{effective_model}' or request parameters invalid (HTTP {code} / {status_str}).",
                }

            return {
                "configured": True,
                "connected": False,
                "status": STATUS_UNKNOWN_ERROR,
                "model": effective_model,
                "latency_ms": elapsed_ms,
                "error_type": f"API_ERROR_{code or 'UNKNOWN'}",
                "message": f"Gemini API returned error (HTTP {code} / {status_str}): {raw_msg[:200]}",
            }

        except Exception as exc:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            exc_name = type(exc).__name__
            exc_str = str(exc).lower()

            # Check for network connectivity or timeout issues
            if any(
                net_kw in exc_str or net_kw in exc_name.lower()
                for net_kw in [
                    "connecterror",
                    "connecttimeout",
                    "readtimeout",
                    "pooltimeout",
                    "network",
                    "connection refused",
                    "name resolution",
                    "dns",
                    "failed to establish a new connection",
                ]
            ):
                if attempt < max_retries:
                    time.sleep(1.0 * (2 ** attempt))
                    continue
                return {
                    "configured": True,
                    "connected": False,
                    "status": STATUS_NETWORK_ERROR,
                    "model": effective_model,
                    "latency_ms": elapsed_ms,
                    "error_type": "NETWORK_ERROR",
                    "message": f"Network error communicating with Google Gemini API: {exc_name}",
                }

            return {
                "configured": True,
                "connected": False,
                "status": STATUS_UNKNOWN_ERROR,
                "model": effective_model,
                "latency_ms": elapsed_ms,
                "error_type": exc_name,
                "message": f"Unexpected error during Gemini connectivity probe: {exc_name}",
            }
