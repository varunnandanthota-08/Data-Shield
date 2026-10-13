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
