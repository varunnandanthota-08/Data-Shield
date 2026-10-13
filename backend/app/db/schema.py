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

CREATE INDEX IF NOT EXISTS idx_audit_seq ON audit_events(sequence_number);
CREATE INDEX IF NOT EXISTS idx_audit_scan ON audit_events(scan_id);
"""


def init_db(db_path: Optional[str] = None) -> None:
    """Initializes SQLite schema and seeds default policies if empty."""
    with get_db_cursor(db_path) as cursor:
        cursor.executescript(CREATE_TABLES_SQL)

        # Check and migrate org_id column if table pre-existed
        cursor.execute("PRAGMA table_info(policies)")
        cols = [c["name"] for c in cursor.fetchall()]
        if "org_id" not in cols:
            cursor.execute("ALTER TABLE policies ADD COLUMN org_id TEXT NOT NULL DEFAULT 'default'")

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_policy_org ON policies(org_id)")

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
