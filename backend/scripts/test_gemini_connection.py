#!/usr/bin/env python3
"""DataShield AI — Google Gemini Connectivity Diagnostic Script.

Verifies live connectivity to Google Gemini API using existing project configuration.
Zero-trust security: Never prints or logs the API key or raw sensitive content.
"""

import argparse
import json
import os
import sys

# Ensure backend root is on Python module search path
backend_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_root not in sys.path:
    sys.path.insert(0, backend_root)

from app.ai.connectivity import (
    STATUS_AUTHENTICATION_FAILED,
    STATUS_API_ACCESS_OR_QUOTA_ISSUE,
    STATUS_CONNECTED,
    STATUS_MODEL_OR_REQUEST_ERROR,
    STATUS_NETWORK_ERROR,
    STATUS_NOT_CONFIGURED,
    check_gemini_connectivity,
)
from app.core.config import settings


def main():
    parser = argparse.ArgumentParser(
        description="Verify Google Gemini API connectivity in DataShield AI"
    )
    parser.add_argument(
        "--api-key",
        dest="api_key",
        default=None,
        help="Optional API key for manual local testing (not logged or persisted)",
    )
    parser.add_argument(
        "--model",
        dest="model",
        default=None,
        help=f"Target Gemini model (defaults to configured: {settings.GEMINI_MODEL})",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output result as JSON",
    )
    args = parser.parse_args()

    result = check_gemini_connectivity(
        api_key=args.api_key,
        model=args.model,
    )

    if args.json_output:
        print(json.dumps(result, indent=2))
        sys.exit(0 if result["connected"] else (1 if result["status"] == STATUS_NOT_CONFIGURED else 2))

    # Formatted human-readable output
    print("=" * 65)
    print("       DataShield AI — Google Gemini Connectivity Check")
    print("=" * 65)
    print(f"Configured:       {'YES' if result['configured'] else 'NO'}")
    print(f"Configured Model: {result['model']}")
    print(f"Connected:        {'YES' if result['connected'] else 'NO'}")
    if result["latency_ms"] is not None:
        print(f"Latency:          {result['latency_ms']} ms")
    print(f"Status / Result:  {result['status']}")
    print(f"Message:          {result['message']}")
    if result.get("response_preview"):
        print(f"Response Preview: {result['response_preview']}")
    print("-" * 65)

    if result["connected"]:
        print("[OK] Gemini API is fully operational and generating responses.")
        sys.exit(0)
    elif result["status"] == STATUS_NOT_CONFIGURED:
        print("[!] Backend cannot find a usable GEMINI_API_KEY.")
        print("    Remediation:")
        print("    1. Create or edit `backend/.env`:")
        print("       GEMINI_API_KEY=your_gemini_api_key_here")
        print("    2. Or set in your terminal environment:")
        print("       $env:GEMINI_API_KEY=\"your_gemini_api_key_here\"  (PowerShell)")
        print("       set GEMINI_API_KEY=your_gemini_api_key_here     (CMD)")
        print("    3. Restart the backend uvicorn service.")
        sys.exit(1)
    else:
        print(f"[ERROR] Gemini API request failed: {result['status']}")
        print(f"        Details: {result['message']}")
        sys.exit(2)


if __name__ == "__main__":
    main()
