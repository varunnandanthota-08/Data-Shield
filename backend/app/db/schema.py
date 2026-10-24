import json
from datetime import datetime, timezone
from typing import Optional
from app.db.connection import get_db_cursor
from app.policy.defaults import DEFAULT_POLICIES

CREATE_TABLES_SQL = """
CREATE TABLE IF NOT EXISTS policies (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL DEFAULT 'default',
    version TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    action TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 10,
    applicable_categories TEXT NOT NULL DEFAULT '[]',
    applicable_sensitivities TEXT NOT NULL DEFAULT '[]',
    target_destinations TEXT NOT NULL DEFAULT '[]',
    target_recipients TEXT NOT NULL DEFAULT '[]',
    intent_explanation TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_records (
    scan_id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL DEFAULT 'default',
    timestamp TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    destination TEXT NOT NULL,
    recipient TEXT NOT NULL,
    classification TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    risk_band TEXT NOT NULL,
    final_decision TEXT NOT NULL,
    finding_count INTEGER NOT NULL,
    categories_detected TEXT NOT NULL,
    processing_duration_ms REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
    event_id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL DEFAULT 'default',
    sequence_number INTEGER NOT NULL UNIQUE,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    scan_id TEXT,
    actor_id TEXT,
    policy_decision TEXT,
    policy_references TEXT NOT NULL DEFAULT '[]',
    sanitized_metadata TEXT NOT NULL DEFAULT '{}',
    prev_event_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    org_id TEXT NOT NULL DEFAULT 'default',
    is_active INTEGER NOT NULL DEFAULT 1,
    tokens_revoked_before TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_login_at TEXT
);

CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    revoked_at TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    reason TEXT NOT NULL DEFAULT 'logout'
);

CREATE TABLE IF NOT EXISTS auth_rate_limits (
    rate_key TEXT PRIMARY KEY,
    attempts INTEGER NOT NULL DEFAULT 0,
    window_start REAL NOT NULL,
    locked_until REAL NOT NULL DEFAULT 0.0,
    updated_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_seq ON audit_events(sequence_number);
CREATE INDEX IF NOT EXISTS idx_audit_scan ON audit_events(scan_id);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_org ON users(org_id);
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_user ON revoked_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_exp ON revoked_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_rate_limits_locked ON auth_rate_limits(locked_until);
"""


def init_db(db_path: Optional[str] = None) -> None:
    """Initializes SQLite schema and seeds default policies if empty."""
    with get_db_cursor(db_path) as cursor:
        # 1. Create tables without org_id indexes that might fail on pre-existing legacy tables
        cursor.executescript(CREATE_TABLES_SQL)

        # 2. Check and migrate org_id column in policies if table pre-existed
        cursor.execute("PRAGMA table_info(policies)")
        cols = [c["name"] for c in cursor.fetchall()]
        if "org_id" not in cols:
            cursor.execute("ALTER TABLE policies ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default'")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_policy_org ON policies(org_id)")

        # 3. Check and migrate org_id column in scan_records if table pre-existed
        cursor.execute("PRAGMA table_info(scan_records)")
        scan_cols = [c["name"] for c in cursor.fetchall()]
        if "org_id" not in scan_cols:
            cursor.execute("ALTER TABLE scan_records ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default'")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_records_org ON scan_records(org_id)")

        # 4. Check and migrate org_id column in audit_events if table pre-existed
        cursor.execute("PRAGMA table_info(audit_events)")
        audit_cols = [c["name"] for c in cursor.fetchall()]
        if "org_id" not in audit_cols:
            cursor.execute("ALTER TABLE audit_events ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default'")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_events(org_id)")

        # 5. Check and migrate tokens_revoked_before column in users if pre-existed
        cursor.execute("PRAGMA table_info(users)")
        user_cols = [c["name"] for c in cursor.fetchall()]
        if "tokens_revoked_before" not in user_cols:
            cursor.execute("ALTER TABLE users ADD COLUMN tokens_revoked_before TEXT")

        # Check if policies exist; if not, seed default policies
        cursor.execute("SELECT COUNT(*) AS cnt FROM policies")
        row = cursor.fetchone()
        if row and row["cnt"] == 0:
            now_iso = datetime.now(timezone.utc).isoformat()
            for p in DEFAULT_POLICIES:
                cursor.execute(
                    """
                    INSERT INTO policies (
                        id, org_id, version, name, description, enabled, action, priority,
                        applicable_categories, applicable_sensitivities,
                        target_destinations, target_recipients, intent_explanation,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        p.id,
                        getattr(p, "org_id", "default"),
                        p.version,
                        p.name,
                        p.description,
                        1 if p.enabled else 0,
                        p.action.value,
                        p.priority,
                        json.dumps([c.value for c in p.applicable_categories]),
                        json.dumps([s.value for s in p.applicable_sensitivities]),
                        json.dumps([d.value for d in p.target_destinations]),
                        json.dumps([r.value for r in p.target_recipients]),
                        p.intent_explanation,
                        now_iso,
                        now_iso,
                    ),
                )
