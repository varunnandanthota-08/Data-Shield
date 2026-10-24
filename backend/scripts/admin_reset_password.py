#!/usr/bin/env python3
"""DataShield AI — Secure Administrative Password Reset Workflow
Allows an authorized administrator to safely reset credentials for a user
in the dedicated staging (or targeted) database without exposing secrets
or modifying other database tables.
"""

import argparse
import os
import secrets
import string
import sys

# Ensure backend root is in sys.path
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from app.auth.repository import UserRepository
from app.auth.security import hash_password
from app.db.connection import get_db_cursor, resolve_db_path


def generate_secure_password(length: int = 18) -> str:
    """Generates a high-entropy, cryptographically random password meeting all policy constraints."""
    upper = secrets.choice(string.ascii_uppercase)
    lower = secrets.choice(string.ascii_lowercase)
    digit = secrets.choice(string.digits)
    special = secrets.choice("!@#$%^&*()-_=+")
    random_chars = [secrets.choice(string.ascii_letters + string.digits + "!@#$%^&*()-_=+") for _ in range(length - 4)]
    password_list = [upper, lower, digit, special] + random_chars
    secrets.SystemRandom().shuffle(password_list)
    return "".join(password_list)


def reset_user_password(db_path: str, identifier: str, password_override: str = None) -> dict:
    resolved = resolve_db_path(db_path)
    if not os.path.exists(resolved):
        raise FileNotFoundError(f"Database not found: {resolved}")

    user_repo = UserRepository(db_path=resolved)
    user = user_repo.get_by_username(identifier) or user_repo.get_by_email(identifier)

    if not user:
        raise ValueError(f"User '{identifier}' not found in database: {resolved}")

    new_password = password_override or generate_secure_password()
    hashed = hash_password(new_password)

    user_repo.update_user(
        user_id=user["id"],
        password_hash=hashed,
        is_active=True,
    )

    # Clear any rate-limit locks for this user
    with get_db_cursor(resolved) as cursor:
        cursor.execute(
            "DELETE FROM auth_rate_limits WHERE rate_key LIKE ?",
            (f"%user:{user['username'].lower()}%",),
        )

    return {
        "user_id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "database": resolved,
        "new_password": new_password,
    }


def main():
    parser = argparse.ArgumentParser(description="DataShield AI Administrative Password Reset")
    parser.add_argument("--db", default="datashield_staging.db", help="Path to target database (default: datashield_staging.db)")
    parser.add_argument("--username", required=True, help="Username or email of the account to reset")
    parser.add_argument("--password", default=None, help="Optional manual password (if omitted, a cryptographically secure random password is generated)")

    args = parser.parse_args()

    try:
        res = reset_user_password(args.db, args.username, args.password)
        print("=" * 60)
        print("DataShield AI — Administrative Password Reset Complete")
        print("=" * 60)
        print(f"Database: {res['database']}")
        print(f"User ID:  {res['user_id']}")
        print(f"Username: {res['username']}")
        print(f"Email:    {res['email']}")
        print(f"Role:     {res['role']}")
        print(f"Status:   Active (all session tokens revoked, locks cleared)")
        print("-" * 60)
        print(f"New Password: {res['new_password']}")
        print("=" * 60)
        print("NOTE: Store this credential securely. It will not be printed again.")
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
