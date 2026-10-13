import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
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
    not absolute cryptographic immutability against an attacker with root database access
    who could theoretically rewrite the entire table and recompute all hashes.
    CRITICAL: Never store raw secrets or full unredacted document content in audit records.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path

    def append_event(
        self,
        event_type: str,
        sanitized_metadata: Dict[str, Any],
        scan_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        policy_decision: Optional[str] = None,
        policy_references: Optional[List[str]] = None,
    ) -> AuditEvent:
        """Appends a new audit event to the hash-chain.
        Atomically queries the latest sequence and previous hash.
        Fails closed on database errors.
        """
        refs = policy_references or []
        event_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

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
                        event_id, sequence_number, timestamp, event_type, scan_id, actor_id,
                        policy_decision, policy_references, sanitized_metadata,
                        prev_event_hash, event_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_id,
                        sequence_number,
                        timestamp,
                        event_type,
                        scan_id,
                        actor_id,
                        policy_decision,
                        json.dumps(refs),
                        json.dumps(sanitized_metadata),
                        prev_event_hash,
                        event_hash,
                    ),
                )

                return AuditEvent(
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
                    event_hash=event_hash,
                )
        except Exception as exc:
            # Explicitly fail closed; persistence failure must not be masked
            raise AuditPersistenceError(f"Failed to persist tamper-evident audit record: {exc}") from exc

    def list_events(self, limit: int = 50, offset: int = 0) -> Tuple[List[AuditEvent], int]:
        """Returns paginated audit events ordered by sequence number descending."""
        with get_db_cursor(self.db_path) as cursor:
            cursor.execute("SELECT COUNT(*) AS total FROM audit_events")
            total = cursor.fetchone()["total"]

            cursor.execute(
                """
                SELECT event_id, sequence_number, timestamp, event_type, scan_id, actor_id,
                       policy_decision, policy_references, sanitized_metadata,
                       prev_event_hash, event_hash
                FROM audit_events
                ORDER BY sequence_number DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            )
            rows = cursor.fetchall()
            events = [
                AuditEvent(
                    event_id=r["event_id"],
                    sequence_number=r["sequence_number"],
                    timestamp=r["timestamp"],
                    event_type=r["event_type"],
                    scan_id=r["scan_id"],
                    actor_id=r["actor_id"],
                    policy_decision=r["policy_decision"],
                    policy_references=json.loads(r["policy_references"]),
                    sanitized_metadata=json.loads(r["sanitized_metadata"]),
                    prev_event_hash=r["prev_event_hash"],
                    event_hash=r["event_hash"],
                )
                for r in rows
            ]
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
            return [
                AuditEvent(
                    event_id=r["event_id"],
                    sequence_number=r["sequence_number"],
                    timestamp=r["timestamp"],
                    event_type=r["event_type"],
                    scan_id=r["scan_id"],
                    actor_id=r["actor_id"],
                    policy_decision=r["policy_decision"],
                    policy_references=json.loads(r["policy_references"]),
                    sanitized_metadata=json.loads(r["sanitized_metadata"]),
                    prev_event_hash=r["prev_event_hash"],
                    event_hash=r["event_hash"],
                )
                for r in rows
            ]

    def verify_chain(self) -> AuditVerificationResult:
        """Verifies the integrity of the audit log chain:
        1. Checks sequence continuity (1, 2, 3... no gaps).
        2. Checks previous hash linkage (event[i].prev_event_hash == event[i-1].event_hash).
        3. Recomputes SHA-256 for each event payload to detect in-place tampering.
        """
        events = self.get_all_events_ordered()
        if not events:
            return AuditVerificationResult(
                is_valid=True,
                total_events=0,
                verified_events=0,
                tampered_event_id=None,
                errors=[],
                chain_head_hash=GENESIS_HASH,
                details="Audit trail is empty. Genesis state valid.",
            )

        expected_prev_hash = GENESIS_HASH
        errors: List[str] = []
        verified_count = 0

        for i, ev in enumerate(events):
            expected_seq = i + 1

            # Check sequence continuity
            if ev.sequence_number != expected_seq:
                err = f"Sequence break at index {i}: Expected sequence {expected_seq}, found {ev.sequence_number} (event_id={ev.event_id})."
                errors.append(err)
                return AuditVerificationResult(
                    is_valid=False,
                    total_events=len(events),
                    verified_events=verified_count,
                    tampered_event_id=ev.event_id,
                    errors=errors,
                    chain_head_hash=ev.event_hash,
                    details=f"Sequence discontinuity detected at event {ev.event_id}.",
                )

            # Check hash chain link
            if ev.prev_event_hash != expected_prev_hash:
                err = (
                    f"Broken hash link at sequence {ev.sequence_number} (event_id={ev.event_id}): "
                    f"prev_event_hash '{ev.prev_event_hash}' does not match expected '{expected_prev_hash}'."
                )
                errors.append(err)
                return AuditVerificationResult(
                    is_valid=False,
                    total_events=len(events),
                    verified_events=verified_count,
                    tampered_event_id=ev.event_id,
                    errors=errors,
                    chain_head_hash=ev.event_hash,
                    details=f"Hash chain broken at event {ev.event_id}.",
                )

            # Recompute event hash to detect payload tampering
            recomputed = compute_event_hash(
                event_id=ev.event_id,
                sequence_number=ev.sequence_number,
                timestamp=ev.timestamp,
                event_type=ev.event_type,
                scan_id=ev.scan_id,
                actor_id=ev.actor_id,
                policy_decision=ev.policy_decision,
                policy_references=ev.policy_references,
                sanitized_metadata=ev.sanitized_metadata,
                prev_event_hash=ev.prev_event_hash,
            )

            if recomputed != ev.event_hash:
                err = (
                    f"Tampered event payload at sequence {ev.sequence_number} (event_id={ev.event_id}): "
                    f"Stored hash '{ev.event_hash}' differs from recomputed '{recomputed}'."
                )
                errors.append(err)
                return AuditVerificationResult(
                    is_valid=False,
                    total_events=len(events),
                    verified_events=verified_count,
                    tampered_event_id=ev.event_id,
                    errors=errors,
                    chain_head_hash=ev.event_hash,
                    details=f"Tampered content detected in event {ev.event_id}.",
                )

            expected_prev_hash = ev.event_hash
            verified_count += 1

        last_hash = events[-1].event_hash
        return AuditVerificationResult(
            is_valid=True,
            total_events=len(events),
            verified_events=verified_count,
            tampered_event_id=None,
            errors=[],
            chain_head_hash=last_hash,
            details=f"Audit chain fully verified across {verified_count} sequential event(s). Zero anomalies detected.",
        )


# Global default audit service instance
audit_service = AuditService()
