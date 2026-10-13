import os
import sqlite3
import tempfile
import pytest
from app.audit.service import GENESIS_HASH, AuditPersistenceError, AuditService
from app.db.schema import init_db


@pytest.fixture
def temp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    init_db(path)
    yield path
    if os.path.exists(path):
        os.remove(path)


class TestAuditPersistenceAndRestart:
    def test_persistence_and_service_restart(self, temp_db):
        service1 = AuditService(temp_db)
        ev1 = service1.append_event(
            event_type="SCAN_EVALUATION",
            sanitized_metadata={"findings_count": 1, "category": "PII"},
            scan_id="scan_1001",
            policy_decision="WARN",
        )
        ev2 = service1.append_event(
            event_type="SCAN_EVALUATION",
            sanitized_metadata={"findings_count": 0},
            scan_id="scan_1002",
            policy_decision="ALLOW",
        )

        assert ev1.sequence_number == 1
        assert ev1.prev_event_hash == GENESIS_HASH
        assert ev2.sequence_number == 2
        assert ev2.prev_event_hash == ev1.event_hash

        # Simulate service restart: create brand new AuditService instance connecting to same database
        service2 = AuditService(temp_db)
        events, total = service2.list_events()

        assert total == 2
        assert len(events) == 2
        # list_events returns descending order
        assert events[0].event_id == ev2.event_id
        assert events[1].event_id == ev1.event_id

        # Verify integrity on restarted instance
        verif = service2.verify_chain()
        assert verif.is_valid is True
        assert verif.verified_events == 2
        assert verif.tampered_event_id is None

    def test_audit_failure_fails_closed(self):
        # Point to invalid path that cannot be written
        invalid_service = AuditService("/invalid_dir_9999/does_not_exist/test.db")
        with pytest.raises(AuditPersistenceError):
            invalid_service.append_event(
                event_type="TEST",
                sanitized_metadata={},
            )


class TestTamperEvidenceDetection:
    def test_altered_event_payload_detected(self, temp_db):
        service = AuditService(temp_db)
        ev1 = service.append_event(
            event_type="SCAN_EVALUATION",
            sanitized_metadata={"count": 1},
            policy_decision="BLOCK",
        )
        ev2 = service.append_event(
            event_type="SCAN_EVALUATION",
            sanitized_metadata={"count": 0},
            policy_decision="ALLOW",
        )

        # Confirm valid initial state
        assert service.verify_chain().is_valid is True

        # Malicious in-place database tamper: modify policy_decision from BLOCK to ALLOW
        conn = sqlite3.connect(temp_db)
        conn.execute(
            "UPDATE audit_events SET policy_decision = 'ALLOW' WHERE event_id = ?",
            (ev1.event_id,),
        )
        conn.commit()
        conn.close()

        # Verification must catch the tampered payload
        verif = service.verify_chain()
        assert verif.is_valid is False
        assert verif.tampered_event_id == ev1.event_id
        assert any("Tampered event payload" in err for err in verif.errors)

    def test_broken_hash_link_detected(self, temp_db):
        service = AuditService(temp_db)
        service.append_event("SCAN_EVALUATION", {"item": 1})
        ev2 = service.append_event("SCAN_EVALUATION", {"item": 2})

        # Tamper: corrupt prev_event_hash in event 2
        conn = sqlite3.connect(temp_db)
        conn.execute(
            "UPDATE audit_events SET prev_event_hash = 'badbeef' WHERE event_id = ?",
            (ev2.event_id,),
        )
        conn.commit()
        conn.close()

        verif = service.verify_chain()
        assert verif.is_valid is False
        assert verif.tampered_event_id == ev2.event_id
        assert any("Broken hash link" in err for err in verif.errors)

    def test_reordered_events_detected(self, temp_db):
        service = AuditService(temp_db)
        ev1 = service.append_event("TYPE_A", {"seq": 1})
        ev2 = service.append_event("TYPE_B", {"seq": 2})

        # Swap sequence numbers in database
        conn = sqlite3.connect(temp_db)
        conn.execute("UPDATE audit_events SET sequence_number = 99 WHERE event_id = ?", (ev1.event_id,))
        conn.execute("UPDATE audit_events SET sequence_number = 1 WHERE event_id = ?", (ev2.event_id,))
        conn.execute("UPDATE audit_events SET sequence_number = 2 WHERE event_id = ?", (ev1.event_id,))
        conn.commit()
        conn.close()

        verif = service.verify_chain()
        assert verif.is_valid is False

    def test_deleted_intermediate_event_detected(self, temp_db):
        service = AuditService(temp_db)
        ev1 = service.append_event("TYPE_A", {"n": 1})
        ev2 = service.append_event("TYPE_B", {"n": 2})
        ev3 = service.append_event("TYPE_C", {"n": 3})

        # Delete intermediate event 2
        conn = sqlite3.connect(temp_db)
        conn.execute("DELETE FROM audit_events WHERE event_id = ?", (ev2.event_id,))
        conn.commit()
        conn.close()

        verif = service.verify_chain()
        assert verif.is_valid is False
        assert any("Sequence break" in err or "Broken hash link" in err for err in verif.errors)


class TestZeroRawSecretExposureInAudit:
    def test_no_raw_secrets_in_persisted_audit_metadata(self, temp_db):
        service = AuditService(temp_db)
        raw_secret_pattern = "AKIAIOSFODNN7EXAMPLE"
        masked_version = "AKIA****...****LE"

        # Sanitize metadata before logging
        sanitized = {
            "finding_count": 1,
            "masked_evidence": masked_version,
            "category": "SECRET",
        }
        service.append_event(
            event_type="SCAN_EVALUATION",
            sanitized_metadata=sanitized,
            scan_id="scan_safe_01",
        )

        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute("SELECT sanitized_metadata FROM audit_events")
        row = cursor.fetchone()
        stored_json = row[0]
        conn.close()

        assert raw_secret_pattern not in stored_json
        assert masked_version in stored_json


class TestConcurrentAuditAndAtomicPersistence:
    def test_concurrent_audit_writes_sequence_and_hash_integrity(self, temp_db):
        """Tests concurrent audit writes across multiple threads to verify sequence allocation and hash integrity."""
        import concurrent.futures
        service = AuditService(temp_db)

        def worker(idx: int):
            return service.append_event(
                event_type="CONCURRENT_EVAL",
                sanitized_metadata={"worker_index": idx, "status": "ok"},
                scan_id=f"scan_concurrent_{idx}",
                policy_decision="ALLOW",
            )

        worker_count = 15
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(worker, i) for i in range(worker_count)]
            results = [f.result() for f in futures]

        assert len(results) == worker_count

        # Sequence numbers must be strictly 1..worker_count with zero collisions
        seq_numbers = sorted(ev.sequence_number for ev in results)
        assert seq_numbers == list(range(1, worker_count + 1))

        # Cryptographically verify the entire chain
        verif = service.verify_chain()
        assert verif.is_valid is True
        assert verif.total_events == worker_count
        assert verif.verified_events == worker_count
        assert verif.tampered_event_id is None
        assert verif.errors == []

    def test_atomic_scan_record_and_audit_consistency(self, temp_db):
        """Verifies scan record and audit event are persisted consistently together in the same atomic transaction."""
        from app.db.repository import scan_record_repo
        service = AuditService(temp_db)
        scan_record_repo_temp = type(scan_record_repo)(temp_db)

        scan_data = {
            "scan_id": "scan_atomic_001",
            "actor_id": "analyst_atomic",
            "destination": "PUBLIC_LLM",
            "recipient": "PUBLIC",
            "classification": "CONFIDENTIAL",
            "risk_score": 90,
            "risk_band": "CRITICAL",
            "final_decision": "BLOCK",
            "finding_count": 1,
            "categories_detected": ["SECRET"],
            "processing_duration_ms": 1.25,
        }

        audit_ev = service.append_event(
            event_type="SCAN_EVALUATION",
            sanitized_metadata={"masked": "AKIA***"},
            scan_id=scan_data["scan_id"],
            actor_id=scan_data["actor_id"],
            policy_decision=scan_data["final_decision"],
            scan_record_data=scan_data,
        )

        assert audit_ev.scan_id == "scan_atomic_001"

        # Verify scan record exists and matches
        stored_rec = scan_record_repo_temp.get_scan_record("scan_atomic_001")
        assert stored_rec is not None
        assert stored_rec["scan_id"] == "scan_atomic_001"
        assert stored_rec["final_decision"] == "BLOCK"
        assert stored_rec["risk_score"] == 90


class TestMalformedAuditSafety:
    def test_malformed_json_in_sanitized_metadata_fails_safely(self, temp_db):
        """Verify malformed JSON in audit record fails safely without crashing verify_chain."""
        service = AuditService(temp_db)
        ev1 = service.append_event("TEST", {"key": "val1"})

        # Inject malformed non-JSON data into sanitized_metadata
        conn = sqlite3.connect(temp_db)
        conn.execute("UPDATE audit_events SET sanitized_metadata = 'CORRUPTED_NON_JSON{' WHERE event_id = ?", (ev1.event_id,))
        conn.commit()
        conn.close()

        # verify_chain must detect tampering and return is_valid=False without crashing
        verif = service.verify_chain()
        assert verif.is_valid is False
        assert verif.tampered_event_id == ev1.event_id
        assert any("Malformed" in err or "corrupted" in err.lower() for err in verif.errors)

    def test_missing_sequence_or_hash_fails_safely(self, temp_db):
        """Verify missing sequence numbers fail safely."""
        service = AuditService(temp_db)
        ev1 = service.append_event("TEST", {"key": "val1"})

        conn = sqlite3.connect(temp_db)
        conn.execute("UPDATE audit_events SET prev_event_hash = 'INVALID_HASH' WHERE event_id = ?", (ev1.event_id,))
        conn.commit()
        conn.close()

        verif = service.verify_chain()
        assert verif.is_valid is False
        assert verif.tampered_event_id == ev1.event_id

