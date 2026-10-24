import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from app.db.connection import get_db_cursor
from app.core.config import settings


class UserRepository:
    """Manages persistence and retrieval of User records in SQLite."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path

    def get_by_id(self, user_id: str, org_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        with get_db_cursor(self.db_path) as cursor:
            if org_id and org_id != "default" and org_id != "all":
                cursor.execute("SELECT * FROM users WHERE id = ? AND org_id = ?", (user_id, org_id))
            else:
                cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        with get_db_cursor(self.db_path) as cursor:
            cursor.execute("SELECT * FROM users WHERE LOWER(username) = LOWER(?)", (username.strip(),))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        with get_db_cursor(self.db_path) as cursor:
            cursor.execute("SELECT * FROM users WHERE LOWER(email) = LOWER(?)", (email.strip(),))
            row = cursor.fetchone()
            return dict(row) if row else None

    def create_user(
        self,
        username: str,
        email: str,
        password_hash: str,
        role: str,
        org_id: str = "default",
        user_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        user_id = user_id or f"usr_{uuid.uuid4().hex[:12]}"
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_cursor(self.db_path) as cursor:
            cursor.execute(
                """
                INSERT INTO users (
                    id, username, email, password_hash, role, org_id, is_active, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (user_id, username.strip(), email.strip().lower(), password_hash, role, org_id, now_iso, now_iso),
            )
        return self.get_by_id(user_id) or {}

    def update_user(
        self,
        user_id: str,
        email: Optional[str] = None,
        role: Optional[str] = None,
        is_active: Optional[bool] = None,
        password_hash: Optional[str] = None,
        org_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        now_iso = datetime.now(timezone.utc).isoformat()
        updates = ["updated_at = ?"]
        params: List[Any] = [now_iso]

        if email is not None:
            updates.append("email = ?")
            params.append(email.strip().lower())
        if role is not None:
            updates.append("role = ?")
            params.append(role)
        if is_active is not None:
            updates.append("is_active = ?")
            params.append(1 if is_active else 0)
            if not is_active:
                # Deactivating user revokes all active tokens immediately
                updates.append("tokens_revoked_before = ?")
                params.append(now_iso)
        if password_hash is not None:
            updates.append("password_hash = ?")
            params.append(password_hash)
            # Password change revokes all existing sessions
            updates.append("tokens_revoked_before = ?")
            params.append(now_iso)
        if org_id is not None:
            updates.append("org_id = ?")
            params.append(org_id)

        params.append(user_id)
        query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"

        with get_db_cursor(self.db_path) as cursor:
            cursor.execute(query, tuple(params))

        return self.get_by_id(user_id)

    def revoke_user_tokens(self, user_id: str) -> None:
        """Invalidates all tokens issued for this user prior to now."""
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_cursor(self.db_path) as cursor:
            cursor.execute("UPDATE users SET tokens_revoked_before = ? WHERE id = ?", (now_iso, user_id))

    def update_last_login(self, user_id: str) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_cursor(self.db_path) as cursor:
            cursor.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (now_iso, user_id))

    def delete_user(self, user_id: str, org_id: Optional[str] = None) -> bool:
        with get_db_cursor(self.db_path) as cursor:
            if org_id and org_id != "default" and org_id != "all":
                cursor.execute("DELETE FROM users WHERE id = ? AND org_id = ?", (user_id, org_id))
            else:
                cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
            return cursor.rowcount > 0

    def list_users(self, org_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with get_db_cursor(self.db_path) as cursor:
            if org_id:
                cursor.execute("SELECT * FROM users WHERE org_id = ? ORDER BY created_at DESC", (org_id,))
            else:
                cursor.execute("SELECT * FROM users ORDER BY created_at DESC")
            return [dict(r) for r in cursor.fetchall()]

    def count_users(self) -> int:
        with get_db_cursor(self.db_path) as cursor:
            cursor.execute("SELECT COUNT(*) AS cnt FROM users")
            row = cursor.fetchone()
            return row["cnt"] if row else 0


class TokenRevocationRepository:
    """Manages persistence of revoked JWT identifiers (jti) in SQLite."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path

    def revoke_token(self, jti: str, user_id: str, expires_at: int, reason: str = "logout") -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_cursor(self.db_path) as cursor:
            cursor.execute(
                """
                INSERT OR REPLACE INTO revoked_tokens (jti, user_id, revoked_at, expires_at, reason)
                VALUES (?, ?, ?, ?, ?)
                """,
                (jti, user_id, now_iso, expires_at, reason),
            )

    def is_revoked(self, jti: str) -> bool:
        with get_db_cursor(self.db_path) as cursor:
            cursor.execute("SELECT 1 FROM revoked_tokens WHERE jti = ?", (jti,))
            return cursor.fetchone() is not None

    def cleanup_expired_tokens(self) -> int:
        """Removes entries whose original JWT expiration has passed."""
        now_ts = int(datetime.now(timezone.utc).timestamp())
        with get_db_cursor(self.db_path) as cursor:
            cursor.execute("DELETE FROM revoked_tokens WHERE expires_at < ?", (now_ts,))
            return cursor.rowcount


user_repo = UserRepository()
token_revocation_repo = TokenRevocationRepository()
