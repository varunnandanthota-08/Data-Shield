import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from app.db.connection import get_db_cursor
from app.engine.schemas import FindingCategory
from app.policy.schemas import (
    DataClassification,
    DestinationType,
    PolicyAction,
    PolicyRule,
    RecipientType,
)


class PolicyRepository:
    """Repository abstraction for Policy definitions stored in SQLite."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path

    def list_policies(self, enabled_only: bool = False) -> List[PolicyRule]:
        with get_db_cursor(self.db_path) as cursor:
            query = "SELECT * FROM policies"
            params = []
            if enabled_only:
                query += " WHERE enabled = 1"
            query += " ORDER BY priority DESC, id ASC"

            cursor.execute(query, params)
            rows = cursor.fetchall()
            policies: List[PolicyRule] = []
            for r in rows:
                cats = [FindingCategory(c) for c in json.loads(r["applicable_categories"])]
                sens = [DataClassification(s) for s in json.loads(r["applicable_sensitivities"])]
                dests = [DestinationType(d) for d in json.loads(r["target_destinations"])]
                recips = [RecipientType(rec) for rec in json.loads(r["target_recipients"])]

                policies.append(
                    PolicyRule(
                        id=r["id"],
                        version=r["version"],
                        name=r["name"],
                        description=r["description"],
                        enabled=bool(r["enabled"]),
                        applicable_categories=cats,
                        applicable_sensitivities=sens,
                        target_destinations=dests,
                        target_recipients=recips,
                        action=PolicyAction(r["action"]),
                        priority=r["priority"],
                        intent_explanation=r["intent_explanation"],
                    )
                )
            return policies

    def get_policy(self, policy_id: str) -> Optional[PolicyRule]:
        with get_db_cursor(self.db_path) as cursor:
            cursor.execute("SELECT * FROM policies WHERE id = ?", (policy_id,))
            r = cursor.fetchone()
            if not r:
                return None
            return PolicyRule(
                id=r["id"],
                version=r["version"],
                name=r["name"],
                description=r["description"],
                enabled=bool(r["enabled"]),
                applicable_categories=[FindingCategory(c) for c in json.loads(r["applicable_categories"])],
                applicable_sensitivities=[DataClassification(s) for s in json.loads(r["applicable_sensitivities"])],
                target_destinations=[DestinationType(d) for d in json.loads(r["target_destinations"])],
                target_recipients=[RecipientType(rec) for rec in json.loads(r["target_recipients"])],
                action=PolicyAction(r["action"]),
                priority=r["priority"],
                intent_explanation=r["intent_explanation"],
            )

    def save_policy(self, policy: PolicyRule) -> PolicyRule:
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_cursor(self.db_path) as cursor:
            cursor.execute(
                """
                INSERT INTO policies (
                    id, version, name, description, enabled, action, priority,
                    applicable_categories, applicable_sensitivities,
                    target_destinations, target_recipients, intent_explanation,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    version = excluded.version,
                    name = excluded.name,
                    description = excluded.description,
                    enabled = excluded.enabled,
                    action = excluded.action,
                    priority = excluded.priority,
                    applicable_categories = excluded.applicable_categories,
                    applicable_sensitivities = excluded.applicable_sensitivities,
                    target_destinations = excluded.target_destinations,
                    target_recipients = excluded.target_recipients,
                    intent_explanation = excluded.intent_explanation,
                    updated_at = excluded.updated_at
                """,
                (
                    policy.id,
                    policy.version,
                    policy.name,
                    policy.description,
                    1 if policy.enabled else 0,
                    policy.action.value,
                    policy.priority,
                    json.dumps([c.value for c in policy.applicable_categories]),
                    json.dumps([s.value for s in policy.applicable_sensitivities]),
                    json.dumps([d.value for d in policy.target_destinations]),
                    json.dumps([r.value for r in policy.target_recipients]),
                    policy.intent_explanation,
                    now_iso,
                    now_iso,
                ),
            )
            return policy


class ScanRecordRepository:
    """Repository abstraction for scan evaluation metadata in SQLite.
    Never stores raw input text, unredacted secrets, or original documents.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path

    def save_scan_record(
        self,
        scan_id: str,
        actor_id: str,
        destination: str,
        recipient: str,
        classification: str,
        risk_score: int,
        risk_band: str,
        final_decision: str,
        finding_count: int,
        categories_detected: List[str],
        processing_duration_ms: float,
    ) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        with get_db_cursor(self.db_path) as cursor:
            cursor.execute(
                """
                INSERT INTO scan_records (
                    scan_id, timestamp, actor_id, destination, recipient, classification,
                    risk_score, risk_band, final_decision, finding_count,
                    categories_detected, processing_duration_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    now_iso,
                    actor_id,
                    destination,
                    recipient,
                    classification,
                    risk_score,
                    risk_band,
                    final_decision,
                    finding_count,
                    json.dumps(categories_detected),
                    processing_duration_ms,
                ),
            )

    def get_scan_record(self, scan_id: str) -> Optional[Dict[str, Any]]:
        with get_db_cursor(self.db_path) as cursor:
            cursor.execute("SELECT * FROM scan_records WHERE scan_id = ?", (scan_id,))
            r = cursor.fetchone()
            if not r:
                return None
            return {
                "scan_id": r["scan_id"],
                "timestamp": r["timestamp"],
                "actor_id": r["actor_id"],
                "destination": r["destination"],
                "recipient": r["recipient"],
                "classification": r["classification"],
                "risk_score": r["risk_score"],
                "risk_band": r["risk_band"],
                "final_decision": r["final_decision"],
                "finding_count": r["finding_count"],
                "categories_detected": json.loads(r["categories_detected"]),
                "processing_duration_ms": r["processing_duration_ms"],
            }


# Global default repository instances
policy_repo = PolicyRepository()
scan_record_repo = ScanRecordRepository()
