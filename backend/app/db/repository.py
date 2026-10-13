import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
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
                "categories_detected": json.loads(r["categories_detected"]) if r["categories_detected"] else [],
                "processing_duration_ms": r["processing_duration_ms"],
            }

    def list_scan_records(
        self,
        limit: int = 50,
        offset: int = 0,
        action: Optional[str] = None,
        risk_band: Optional[str] = None,
        destination: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        query = "SELECT * FROM scan_records WHERE 1=1"
        count_query = "SELECT COUNT(*) AS total FROM scan_records WHERE 1=1"
        params: List[Any] = []

        if action:
            query += " AND final_decision = ?"
            count_query += " AND final_decision = ?"
            params.append(action)
        if risk_band:
            query += " AND risk_band = ?"
            count_query += " AND risk_band = ?"
            params.append(risk_band)
        if destination:
            query += " AND destination = ?"
            count_query += " AND destination = ?"
            params.append(destination)

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        exec_params = list(params) + [limit, offset]

        with get_db_cursor(self.db_path) as cursor:
            cursor.execute(count_query, params)
            total = cursor.fetchone()["total"]

            cursor.execute(query, exec_params)
            rows = cursor.fetchall()
            records = []
            for r in rows:
                records.append({
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
                    "categories_detected": json.loads(r["categories_detected"]) if r["categories_detected"] else [],
                    "processing_duration_ms": r["processing_duration_ms"],
                })
            return records, total

    def get_metrics(self) -> Dict[str, Any]:
        with get_db_cursor(self.db_path) as cursor:
            cursor.execute("""
                SELECT 
                    COUNT(*) as total_scans,
                    COALESCE(SUM(CASE WHEN final_decision = 'BLOCK' THEN 1 ELSE 0 END), 0) as blocked_count,
                    COALESCE(SUM(CASE WHEN final_decision = 'REQUIRE_APPROVAL' THEN 1 ELSE 0 END), 0) as approval_count,
                    COALESCE(SUM(CASE WHEN final_decision = 'WARN' THEN 1 ELSE 0 END), 0) as warn_count,
                    COALESCE(SUM(CASE WHEN final_decision = 'ALLOW' THEN 1 ELSE 0 END), 0) as allow_count,
                    COALESCE(SUM(CASE WHEN risk_band = 'CRITICAL' THEN 1 ELSE 0 END), 0) as critical_count,
                    COALESCE(SUM(CASE WHEN risk_band = 'HIGH' THEN 1 ELSE 0 END), 0) as high_count,
                    COALESCE(AVG(risk_score), 0.0) as avg_risk_score,
                    COALESCE(SUM(finding_count), 0) as total_findings
                FROM scan_records
            """)
            r = cursor.fetchone()
            return {
                "total_scans": r["total_scans"],
                "blocked_count": r["blocked_count"],
                "approval_count": r["approval_count"],
                "warn_count": r["warn_count"],
                "allow_count": r["allow_count"],
                "critical_count": r["critical_count"],
                "high_count": r["high_count"],
                "avg_risk_score": round(float(r["avg_risk_score"]), 1),
                "total_findings": r["total_findings"],
            }


# Global default repository instances
policy_repo = PolicyRepository()
scan_record_repo = ScanRecordRepository()
