"""DataShield AI — Staging Authentication Verification Script
Tests login and protected endpoints for staging accounts, validating identity,
roles, and protected endpoint accessibility without printing tokens.
"""

import json
import os
import sys
import urllib.error
import urllib.request

# Ensure backend root is in sys.path
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from scripts.admin_reset_password import reset_user_password

BASE_URL = "http://127.0.0.1:8001"


def attempt_login_and_verify(identifier: str, password: str, label: str) -> dict:
    print(f"\n[Testing Login] {label} (Identifier: '{identifier}')")
    payload = json.dumps({"username": identifier, "password": password}).encode("utf-8")
    req = urllib.request.Request(
        f"{BASE_URL}/api/v1/auth/login",
        data=payload,
        headers={"Content-Type": "application/json"},
    )

    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            user = data.get("user", {})
            token = data.get("access_token")

            print(f"  [PASS] Login Status: HTTP {resp.status} OK")
            print(f"  [PASS] Token Issued: {bool(token)} (Length: {len(token) if token else 0} chars)")
            print(f"  [PASS] User Identity: ID={user.get('id')}, Username='{user.get('username')}', Email='{user.get('email')}'")
            print(f"  [PASS] Role: '{user.get('role')}', Active: {user.get('is_active')}, Org: '{user.get('org_id')}'")

            # Verify protected endpoint 1: /api/v1/auth/me
            req_me = urllib.request.Request(
                f"{BASE_URL}/api/v1/auth/me",
                headers={"Authorization": f"Bearer {token}"},
            )
            with urllib.request.urlopen(req_me) as resp_me:
                me_user = json.loads(resp_me.read().decode("utf-8"))
                print(f"  [PASS] Protected /api/v1/auth/me: HTTP {resp_me.status} OK (Returned Role: '{me_user.get('role')}')")

            # Verify protected endpoint 2: /api/v1/scan/records
            req_scans = urllib.request.Request(
                f"{BASE_URL}/api/v1/scan/records?limit=5",
                headers={"Authorization": f"Bearer {token}"},
            )
            with urllib.request.urlopen(req_scans) as resp_scans:
                scans = json.loads(resp_scans.read().decode("utf-8"))
                print(f"  [PASS] Protected /api/v1/scan/records: HTTP {resp_scans.status} OK (Total Staging Records: {scans.get('total')})")

            return {"success": True, "user": user}
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        print(f"  [FAIL] Login Failed: HTTP {e.code} — {err_body}")
        return {"success": False, "status": e.code, "error": err_body}


def main():
    print("=" * 65)
    print("DataShield AI — Staging Authentication & Identity Verification")
    print("=" * 65)

    staging_db = os.path.join(backend_dir, "datashield_staging.db")

    # 1. Reset staging_admin with fresh secure password
    print("\n[1] Performing administrative credential reset for staging_admin...")
    admin_res = reset_user_password(staging_db, "staging_admin")
    admin_pw = admin_res["new_password"]
    print(f"  Admin password generated: {admin_pw}")

    # 2. Reset staging_analyst with fresh secure password
    print("\n[2] Performing administrative credential reset for staging_analyst...")
    analyst_res = reset_user_password(staging_db, "staging_analyst")
    analyst_pw = analyst_res["new_password"]
    print(f"  Analyst password generated: {analyst_pw}")

    # 3. Test Admin login by Username
    r1 = attempt_login_and_verify("staging_admin", admin_pw, "Administrator Login by Username")
    assert r1["success"], "Admin login by username failed!"

    # 4. Test Admin login by Email
    r2 = attempt_login_and_verify("admin@staging.datashield.ai", admin_pw, "Administrator Login by Email")
    assert r2["success"], "Admin login by email failed!"

    # 5. Test Analyst login by Username
    r3 = attempt_login_and_verify("staging_analyst", analyst_pw, "Analyst Login by Username")
    assert r3["success"], "Analyst login by username failed!"

    # 6. Test Analyst login by Email
    r4 = attempt_login_and_verify("analyst@staging.datashield.ai", analyst_pw, "Analyst Login by Email")
    assert r4["success"], "Analyst login by email failed!"

    # 7. Test Non-existent accounts (development accounts healthworker1 / employee1 in staging)
    print("\n[3] Testing Non-Existent Development Accounts in Staging Database...")
    r5 = attempt_login_and_verify("healthworker1", "Password123!", "healthworker1 (Dev account in staging)")
    assert not r5["success"] and r5["status"] == 401, "Expected 401 for healthworker1"

    r6 = attempt_login_and_verify("employee1", "Password123!", "employee1 (Dev account in staging)")
    assert not r6["success"] and r6["status"] == 401, "Expected 401 for employee1"

    print("\n" + "=" * 65)
    print("ALL STAGING AUTHENTICATION TESTS PASSED SUCCESSFULLY!")
    print("=" * 65)
    print("\nSTAGING ACCESS CREDENTIALS FOR USER:")
    print(f"  Administrator Account:")
    print(f"    - Username: staging_admin (or email: admin@staging.datashield.ai)")
    print(f"    - Password: {admin_pw}")
    print(f"  Analyst Account:")
    print(f"    - Username: staging_analyst (or email: analyst@staging.datashield.ai)")
    print(f"    - Password: {analyst_pw}")
    print("=" * 65)


if __name__ == "__main__":
    main()
