import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
import threading
from app.db.connection import get_db_cursor
from app.policy.schemas import AuditEvent, AuditVerificationResult

# Documented 64-character hex genesis hash
GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"


class AuditPersistenceError(Exception):
    """Raised when an audit event fails to persist.
    Fail-closed policy: audit failures must never falsely report success.
    """
    pass


def canonical_serialize_event(
    event_id: str,
    sequence_number: int,
    timestamp: str,
    event_type: str,
    scan_id: Optional[str],
    actor_id: Optional[str],
    policy_decision: Optional[str],
    policy_references: List[str],
    sanitized_metadata: Dict[str, Any],
    prev_event_hash: str,
) -> str:
    """Deterministically serializes event fields into a canonical JSON string
    with sorted keys and compact separators.
    """
    payload = {
        "actor_id": actor_id or "",
        "event_id": event_id,
        "event_type": event_type,
        "policy_decision": policy_decision or "",
        "policy_references": sorted(policy_references or []),
        "prev_event_hash": prev_event_hash,
        "sanitized_metadata": sanitized_metadata,
        "scan_id": scan_id or "",
        "sequence_number": sequence_number,
        "timestamp": timestamp,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def compute_event_hash(
    event_id: str,
    sequence_number: int,
    timestamp: str,
    event_type: str,
    scan_id: Optional[str],
    actor_id: Optional[str],
    policy_decision: Optional[str],
    policy_references: List[str],
    sanitized_metadata: Dict[str, Any],
    prev_event_hash: str,
) -> str:
    """Computes SHA-256 digest over the canonical event payload + previous event hash."""
    canonical_json = canonical_serialize_event(
        event_id=event_id,
        sequence_number=sequence_number,
        timestamp=timestamp,
        event_type=event_type,
        scan_id=scan_id,
        actor_id=actor_id,
        policy_decision=policy_decision,
        policy_references=policy_references,
        sanitized_metadata=sanitized_metadata,
        prev_event_hash=prev_event_hash,
    )
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


class AuditService:
    """Tamper-evident audit logging engine using SHA-256 hash chaining.
    IMPORTANT SECURITY NOTICE:
    Local SHA-256 chaining provides tamper evidence and forward integrity detection,
    not absolute cryptographic immutability against an administrator who can rewrite the database
    and recompute all hashes.
    CRITICAL: Never store raw secrets or full unredacted document content in audit records.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path
        self._write_lock = threading.Lock()

    def append_event(
        self,
        event_type: str,
        sanitized_metadata: Dict[str, Any],
        scan_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        policy_decision: Optional[str] = None,
        policy_references: Optional[List[str]] = None,
        scan_record_data: Optional[Dict[str, Any]] = None,
        org_id: str = "default",
    ) -> AuditEvent:
        """Appends a new audit event to the hash-chain.
        Atomically queries the latest sequence and previous hash.
        Optionally writes associated scan record in the same atomic transaction.
        Thread-synchronized to prevent sequence allocation race conditions.
        Fails closed on database errors.
        """
        refs = policy_references or []
        event_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        with self._write_lock:
            try:
                with get_db_cursor(self.db_path) as cursor:
                    # Query the latest event in the chain
                    cursor.execute(
                        "SELECT sequence_number, event_hash FROM audit_events ORDER BY sequence_number DESC LIMIT 1"
                    )
                    last_row = cursor.fetchone()

                    if last_row:
                        sequence_number = last_row["sequence_number"] + 1
                        prev_event_hash = last_row["event_hash"]
                    else:
                        sequence_number = 1
                        prev_event_hash = GENESIS_HASH

                    # Compute deterministic hash
                    event_hash = compute_event_hash(
                        event_id=event_id,
                        sequence_number=sequence_number,
                        timestamp=timestamp,
                        event_type=event_type,
                        scan_id=scan_id,
                        actor_id=actor_id,
                        policy_decision=policy_decision,
                        policy_references=refs,
                        sanitized_metadata=sanitized_metadata,
                        prev_event_hash=prev_event_hash,
                    )

                    cursor.execute(
                        """
                        INSERT INTO audit_events (
                            event_id, sequence_number, timestamp, event_type, scan_id, actor_id, org_id,
                            policy_decision, policy_references, sanitized_metadata,
                            prev_event_hash, event_hash
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            event_id,
                            sequence_number,
                            timestamp,
                            event_type,
                            scan_id,
                            actor_id,
                            org_id,
                            policy_decision,
                            json.dumps(refs),
                            json.dumps(sanitized_metadata),
                            prev_event_hash,
                            event_hash,
                        ),
                    )

                    # Persist associated scan record in the SAME atomic transaction if provided
                    if scan_record_data:
                        scan_org = scan_record_data.get("org_id", org_id)
                        cursor.execute(
                            """
                            INSERT INTO scan_records (
                                scan_id, timestamp, actor_id, org_id, destination, recipient, classification,
                                risk_score, risk_band, final_decision, finding_count,
                                categories_detected, processing_duration_ms
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                scan_record_data["scan_id"],
                                scan_record_data.get("timestamp", timestamp),
                                scan_record_data["actor_id"],
                                scan_org,
                                scan_record_data["destination"],
                                scan_record_data["recipient"],
                                scan_record_data["classification"],
                                scan_record_data["risk_score"],
                                scan_record_data["risk_band"],
                                scan_record_data["final_decision"],
                                scan_record_data["finding_count"],
                                json.dumps(scan_record_data["categories_detected"]),
                                scan_record_data["processing_duration_ms"],
                            ),
                        )

                    return AuditEvent(
                        event_id=event_id,
                        sequence_number=sequence_number,
                        timestamp=timestamp,
                        event_type=event_type,
                        scan_id=scan_id,
                        actor_id=actor_id,
                        org_id=org_id,
                        policy_decision=policy_decision,
                        policy_references=refs,
                        sanitized_metadata=sanitized_metadata,
                        prev_event_hash=prev_event_hash,
                        event_hash=event_hash,
                    )
            except Exception as exc:
                # Explicitly fail closed; persistence failure must not be masked
                raise AuditPersistenceError(f"Failed to persist tamper-evident audit record: {exc}") from exc

    def list_events(self, limit: int = 50, offset: int = 0, org_id: Optional[str] = None) -> Tuple[List[AuditEvent], int]:
        """Returns paginated audit events ordered by sequence number descending."""
        with get_db_cursor(self.db_path) as cursor:
            if org_id and org_id != "all":
                cursor.execute("SELECT COUNT(*) AS total FROM audit_events WHERE org_id = ?", (org_id,))
                total = cursor.fetchone()["total"]

                cursor.execute(
                    """
                    SELECT event_id, sequence_number, timestamp, event_type, scan_id, actor_id,
                           org_id, policy_decision, policy_references, sanitized_metadata,
                           prev_event_hash, event_hash
                    FROM audit_events
                    WHERE org_id = ?
                    ORDER BY sequence_number DESC
                    LIMIT ? OFFSET ?
                    """,
                    (org_id, limit, offset),
                )
            else:
                cursor.execute("SELECT COUNT(*) AS total FROM audit_events")
                total = cursor.fetchone()["total"]

                cursor.execute(
                    """
                    SELECT event_id, sequence_number, timestamp, event_type, scan_id, actor_id,
                           org_id, policy_decision, policy_references, sanitized_metadata,
                           prev_event_hash, event_hash
                    FROM audit_events
                    ORDER BY sequence_number DESC
                    LIMIT ? OFFSET ?
                    """,
                    (limit, offset),
                )
            rows = cursor.fetchall()
            events = []
            for r in rows:
                row_keys = r.keys()
                row_org = r["org_id"] if "org_id" in row_keys else "default"
                try:
                    refs = json.loads(r["policy_references"]) if r["policy_references"] else []
                except Exception:
                    refs = []
                try:
                    meta = json.loads(r["sanitized_metadata"]) if r["sanitized_metadata"] else {}
                except Exception:
                    meta = {"_corrupted": True}
                events.append(
                    AuditEvent(
                        event_id=r["event_id"],
                        sequence_number=r["sequence_number"],
                        timestamp=r["timestamp"],
                        event_type=r["event_type"],
                        scan_id=r["scan_id"],
                        actor_id=r["actor_id"],
                        org_id=row_org,
                        policy_decision=r["policy_decision"],
                        policy_references=refs,
                        sanitized_metadata=meta,
                        prev_event_hash=r["prev_event_hash"],
                        event_hash=r["event_hash"],
                    )
                )
            return events, total

    def get_all_events_ordered(self) -> List[AuditEvent]:
        """Returns all audit events ordered strictly ascending by sequence number."""
        with get_db_cursor(self.db_path) as cursor:
            cursor.execute(
                """
                SELECT event_id, sequence_number, timestamp, event_type, scan_id, actor_id,
                       policy_decision, policy_references, sanitized_metadata,
                       prev_event_hash, event_hash
                FROM audit_events
                ORDER BY sequence_number ASC
                """
            )
            rows = cursor.fetchall()
            events = []
            for r in rows:
                try:
                    refs = json.loads(r["policy_references"]) if r["policy_references"] else []
                except Exception:
                    refs = []
                try:
                    meta = json.loads(r["sanitized_metadata"]) if r["sanitized_metadata"] else {}
                except Exception:
                    meta = {"_corrupted": True}
                events.append(
                    AuditEvent(
                        event_id=r["event_id"],
                        sequence_number=r["sequence_number"],
                        timestamp=r["timestamp"],
                        event_type=r["event_type"],
                        scan_id=r["scan_id"],
                        actor_id=r["actor_id"],
                        policy_decision=r["policy_decision"],
                        policy_references=refs,
                        sanitized_metadata=meta,
                        prev_event_hash=r["prev_event_hash"],
                        event_hash=r["event_hash"],
                    )
                )
            return events

    def verify_chain(self, org_id: Optional[str] = None) -> AuditVerificationResult:
        """Verifies the integrity of the audit log chain:
        1. Checks sequence continuity (1, 2, 3... no gaps).
        2. Checks previous hash linkage (event[i].prev_event_hash == event[i-1].event_hash).
        3. Recomputes SHA-256 for each event payload to detect in-place tampering or corruption.
        4. Fails safely on malformed or missing audit fields.
        5. Scopes verified counts and event heads to tenant organization when specified.
        """
        with get_db_cursor(self.db_path) as cursor:
            cursor.execute(
                """
                SELECT event_id, sequence_number, timestamp, event_type, scan_id, actor_id,
                       org_id, policy_decision, policy_references, sanitized_metadata,
                       prev_event_hash, event_hash
                FROM audit_events
                ORDER BY sequence_number ASC
                """
            )
            rows = cursor.fetchall()

        if not rows:
            return AuditVerificationResult(
                is_valid=True,
                total_events=0,
                verified_events=0,
                tampered_event_id=None,
                errors=[],
                chain_head_hash=GENESIS_HASH,
                details="Audit trail is empty. Genesis state valid.",
            )

        tenant_rows = []
        if org_id and org_id != "all":
            tenant_rows = [r for r in rows if (r["org_id"] if "org_id" in r.keys() else "default") == org_id]
            if not tenant_rows:
                return AuditVerificationResult(
                    is_valid=True,
                    total_events=0,
                    verified_events=0,
                    tampered_event_id=None,
                    errors=[],
                    chain_head_hash=GENESIS_HASH,
                    details=f"Tenant '{org_id}' audit trail is empty. State valid.",
                )

        expected_prev_hash = GENESIS_HASH
        errors: List[str] = []
        verified_count = 0

        for i, r in enumerate(rows):
            expected_seq = i + 1
            ev_id = r["event_id"]
            seq_num = r["sequence_number"]
            prev_hash = r["prev_event_hash"]
            event_hash = r["event_hash"]
            row_org = r["org_id"] if "org_id" in r.keys() else "default"
            is_own_tenant_event = (row_org == org_id) if org_id else True

            # Helper to create safe, non-leaking verification result for tenant users
            def make_failure_result(msg: str, detail_msg: str) -> AuditVerificationResult:
                if org_id and not is_own_tenant_event:
                    # Do NOT leak other tenants' event IDs, sequence numbers, or payload errors
                    return AuditVerificationResult(
                        is_valid=False,
                        total_events=len(tenant_rows) if tenant_rows else len(rows),
                        verified_events=min(verified_count, len(tenant_rows) if tenant_rows else len(rows)),
                        tampered_event_id=None,
                        errors=["Audit chain verification failed: ledger discontinuity detected."],
                        chain_head_hash="",
                        details="Audit chain integrity verification failed. Ledger state is inconsistent.",
                    )
                return AuditVerificationResult(
                    is_valid=False,
                    total_events=len(tenant_rows) if tenant_rows else len(rows),
                    verified_events=verified_count,
                    tampered_event_id=ev_id,
                    errors=[msg],
                    chain_head_hash=event_hash or "",
                    details=detail_msg,
                )

            # Check sequence continuity
            if seq_num is None or seq_num != expected_seq:
                err = f"Sequence break at index {i}: Expected sequence {expected_seq}, found {seq_num} (event_id={ev_id})."
                return make_failure_result(err, f"Sequence discontinuity detected at event {ev_id}.")

            # Check hash chain link
            if prev_hash != expected_prev_hash:
                err = (
                    f"Broken hash link at sequence {seq_num} (event_id={ev_id}): "
                    f"prev_event_hash '{prev_hash}' does not match expected '{expected_prev_hash}'."
                )
                return make_failure_result(err, f"Hash chain broken at event {ev_id}.")

            # Safely parse JSON fields to catch malformed payloads
            try:
                refs = json.loads(r["policy_references"]) if r["policy_references"] else []
                meta = json.loads(r["sanitized_metadata"]) if r["sanitized_metadata"] else {}
            except Exception as parse_err:
                err = f"Malformed or corrupted payload JSON in event {ev_id} (sequence {seq_num}): {parse_err}"
                return make_failure_result(err, f"Malformed audit payload detected at event {ev_id}.")

            # Recompute event hash to detect payload tampering
            recomputed = compute_event_hash(
                event_id=ev_id,
                sequence_number=seq_num,
                timestamp=r["timestamp"] or "",
                event_type=r["event_type"] or "",
                scan_id=r["scan_id"],
                actor_id=r["actor_id"],
                policy_decision=r["policy_decision"],
                policy_references=refs,
                sanitized_metadata=meta,
                prev_event_hash=prev_hash or "",
            )

            if recomputed != event_hash:
                err = (
                    f"Tampered event payload at sequence {seq_num} (event_id={ev_id}): "
                    f"Stored hash '{event_hash}' differs from recomputed '{recomputed}'."
                )
                return make_failure_result(err, f"Tampered content detected in event {ev_id}.")

            expected_prev_hash = event_hash
            verified_count += 1

        if tenant_rows:
            last_hash = tenant_rows[-1]["event_hash"]
            return AuditVerificationResult(
                is_valid=True,
                total_events=len(tenant_rows),
                verified_events=len(tenant_rows),
                tampered_event_id=None,
                errors=[],
                chain_head_hash=last_hash,
                details=f"Audit chain fully verified across {len(tenant_rows)} event(s) for organization '{org_id}'. Zero anomalies detected.",
            )

        last_hash = rows[-1]["event_hash"]
        return AuditVerificationResult(
            is_valid=True,
            total_events=len(rows),
            verified_events=verified_count,
            tampered_event_id=None,
            errors=[],
            chain_head_hash=last_hash,
            details=f"Audit chain fully verified across {verified_count} sequential event(s). Zero anomalies detected.",
        )


# Global default audit service instance
audit_service = AuditService()
