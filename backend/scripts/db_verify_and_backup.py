#!/usr/bin/env python3
"""DataShield AI — Database Backup, Integrity, and Audit Chain Verification CLI.

Provides zero-downtime online SQLite backups using SQLite's native backup API
(safe with active WAL writes), PRAGMA integrity verification, schema validation,
and cryptographic SHA-256 audit-chain validation.
"""

import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from typing import Any, Dict

# Ensure backend root is on sys.path
backend_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_root not in sys.path:
    sys.path.insert(0, backend_root)

from app.audit.service import AuditService
from app.core.config import settings
from app.db.connection import get_connection, get_db_path


def verify_sqlite_integrity(db_path: str) -> Dict[str, Any]:
    """Runs PRAGMA integrity_check and quick_check on SQLite database."""
    if not os.path.exists(db_path):
        return {
            "exists": False,
            "status": "error",
            "message": f"Database file not found at: {db_path}",
        }

    try:
        conn = get_connection(db_path)
        cursor = conn.cursor()

        cursor.execute("PRAGMA quick_check")
        quick_check_res = [row[0] for row in cursor.fetchall()]

        cursor.execute("PRAGMA integrity_check")
        integrity_check_res = [row[0] for row in cursor.fetchall()]

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]

        counts: Dict[str, int] = {}
        for tbl in ["users", "policies", "scan_records", "audit_events", "revoked_tokens"]:
            if tbl in tables:
                cursor.execute(f"SELECT COUNT(*) AS c FROM {tbl}")  # nosec
                counts[tbl] = cursor.fetchone()[0]

        conn.close()

        is_healthy = quick_check_res == ["ok"] and integrity_check_res == ["ok"]
        return {
            "exists": True,
            "status": "healthy" if is_healthy else "corrupted",
            "db_path": db_path,
            "file_size_bytes": os.path.getsize(db_path),
            "quick_check": quick_check_res,
            "integrity_check": integrity_check_res,
            "tables": tables,
            "record_counts": counts,
        }
    except Exception as exc:
        return {
            "exists": True,
            "status": "error",
            "message": str(exc),
        }


def perform_online_backup(src_db_path: str, dest_backup_path: str) -> Dict[str, Any]:
    """Executes a safe online SQLite backup using sqlite3.Connection.backup.
    Handles concurrent WAL mode writes safely with transactional consistency.
    """
    if not os.path.exists(src_db_path):
        return {
            "success": False,
            "error": f"Source database not found: {src_db_path}",
        }

    dest_dir = os.path.dirname(dest_backup_path)
    if dest_dir:
        os.makedirs(dest_dir, exist_ok=True)

    start_time = datetime.now(timezone.utc)
    try:
        src_conn = get_connection(src_db_path)
        dest_conn = sqlite3.connect(dest_backup_path)

        # Use SQLite online backup API
        with dest_conn:
            src_conn.backup(dest_conn, pages=100)

        dest_conn.close()
        src_conn.close()

        duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        backup_size = os.path.getsize(dest_backup_path)

        return {
            "success": True,
            "source_path": src_db_path,
            "destination_path": dest_backup_path,
            "duration_seconds": round(duration, 3),
            "backup_size_bytes": backup_size,
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as exc:
        return {
            "success": False,
            "source_path": src_db_path,
            "destination_path": dest_backup_path,
            "error": str(exc),
        }


def verify_audit_chain(db_path: str, org_id: str = "default") -> Dict[str, Any]:
    """Verifies cryptographic SHA-256 hash-chain integrity of audit records."""
    if not os.path.exists(db_path):
        return {"valid": False, "error": f"Database file not found: {db_path}"}

    audit_svc = AuditService(db_path=db_path)
    try:
        result = audit_svc.verify_chain(org_id=org_id)
        return {
            "org_id": org_id,
            "is_valid": result.is_valid,
            "total_events": result.total_events,
            "verified_events": result.verified_events,
            "errors": result.errors,
            "tampered_event_id": result.tampered_event_id,
            "chain_head_hash": result.chain_head_hash,
            "details": result.details,
        }
    except Exception as exc:
        return {
            "org_id": org_id,
            "is_valid": False,
            "total_events": 0,
            "verified_events": 0,
            "errors": [str(exc)],
            "tampered_event_id": None,
            "chain_head_hash": None,
            "details": f"Audit verification failed: {exc}",
        }


def perform_safe_restore(
    backup_path: str,
    dest_restore_path: str,
    active_db_path: str,
) -> Dict[str, Any]:
    """Safely restores a SQLite backup to a dedicated isolated target database.
    CRITICAL SAFETY ENFORCEMENT:
    Refuses to restore directly over the active database to prevent accidental data loss.
    Verifies PRAGMA integrity and audit-chain integrity on the restored file.
    """
    norm_backup = os.path.normpath(os.path.abspath(backup_path))
    norm_dest = os.path.normpath(os.path.abspath(dest_restore_path))
    norm_active = os.path.normpath(os.path.abspath(active_db_path))

    if not os.path.exists(norm_backup):
        return {
            "success": False,
            "error": f"Backup source file not found at: {norm_backup}",
        }

    # Invariant: Never allow overwriting the active running database!
    if norm_dest == norm_active:
        return {
            "success": False,
            "error": (
                f"SAFETY VIOLATION PREVENTED: Cannot restore directly over the active database ({norm_active}). "
                "Specify a separate, dedicated staging or test restore target."
            ),
        }

    dest_dir = os.path.dirname(norm_dest)
    if dest_dir:
        os.makedirs(dest_dir, exist_ok=True)

    start_time = datetime.now(timezone.utc)
    try:
        # Use SQLite online backup API to write into destination
        src_conn = sqlite3.connect(norm_backup)
        dest_conn = sqlite3.connect(norm_dest)
        with dest_conn:
            src_conn.backup(dest_conn, pages=100)
        dest_conn.close()
        src_conn.close()

        duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        restore_size = os.path.getsize(norm_dest)

        # Immediate post-restore verification
        integrity = verify_sqlite_integrity(norm_dest)
        audit_check = verify_audit_chain(norm_dest)

        is_valid = integrity.get("status") == "healthy" and audit_check.get("is_valid", False)

        return {
            "success": is_valid,
            "source_backup_path": norm_backup,
            "restored_path": norm_dest,
            "duration_seconds": round(duration, 3),
            "restored_size_bytes": restore_size,
            "integrity_status": integrity.get("status"),
            "audit_chain_valid": audit_check.get("is_valid"),
            "audit_events_verified": audit_check.get("verified_events"),
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as exc:
        return {
            "success": False,
            "source_backup_path": norm_backup,
            "restored_path": norm_dest,
            "error": str(exc),
        }


def main():
    parser = argparse.ArgumentParser(
        description="DataShield AI — Database Backup, Integrity, and Audit Chain Verification"
    )
    parser.add_argument(
        "--db",
        dest="db_path",
        default=None,
        help="Path to SQLite database (default: configured SQLITE_DB_PATH)",
    )
    parser.add_argument(
        "--backup-to",
        dest="backup_path",
        default=None,
        help="Perform online transactional backup to specified destination path",
    )
    parser.add_argument(
        "--restore-from",
        dest="restore_from_path",
        default=None,
        help="Source backup file path to safely restore from",
    )
    parser.add_argument(
        "--restore-to",
        dest="restore_to_path",
        default=None,
        help="Isolated target destination path for restored database (never matches active DB)",
    )
    parser.add_argument(
        "--verify-audit",
        action="store_true",
        dest="verify_audit",
        help="Verify cryptographic SHA-256 hash-chain integrity",
    )
    parser.add_argument(
        "--org-id",
        dest="org_id",
        default="default",
        help="Target tenant org_id for audit chain verification (default: 'default')",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Format output as JSON",
    )
    args = parser.parse_args()

    db_path = get_db_path(args.db_path)

    report: Dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "database_path": db_path,
    }

    # 1. Integrity check
    integrity = verify_sqlite_integrity(db_path)
    report["integrity_check"] = integrity

    # 2. Audit chain check if requested
    if args.verify_audit:
        audit_check = verify_audit_chain(db_path, org_id=args.org_id)
        report["audit_chain_verification"] = audit_check

    # 3. Perform backup if requested
    if args.backup_path:
        backup_result = perform_online_backup(db_path, args.backup_path)
        report["backup"] = backup_result

    # 4. Perform safe restore if requested
    if args.restore_from_path and args.restore_to_path:
        restore_result = perform_safe_restore(
            backup_path=args.restore_from_path,
            dest_restore_path=args.restore_to_path,
            active_db_path=db_path,
        )
        report["restore"] = restore_result

    if args.json_output:
        print(json.dumps(report, indent=2))
    else:
        print("=" * 60)
        print("DataShield AI — Database Integrity & Lifecycle Report")
        print("=" * 60)
        print(f"Database File: {db_path}")
        print(f"Integrity Status: {integrity.get('status', 'unknown').upper()}")
        if integrity.get("exists"):
            print(f"Size: {integrity.get('file_size_bytes', 0):,} bytes")
            print(f"Tables: {', '.join(integrity.get('tables', []))}")
            for tbl, cnt in integrity.get("record_counts", {}).items():
                print(f"  • {tbl}: {cnt:,} records")

        if args.verify_audit and "audit_chain_verification" in report:
            audit = report["audit_chain_verification"]
            valid_str = "VALID (Untampered)" if audit.get("is_valid") else "COMPROMISED"
            print(f"\nAudit Chain Integrity ({audit.get('org_id')}): {valid_str}")
            print(f"Events Verified: {audit.get('verified_events', 0)} of {audit.get('total_events', 0)}")
            if not audit.get("is_valid"):
                print(f"Tampered Event ID: {audit.get('tampered_event_id')}")
                print(f"Errors: {audit.get('errors')}")

        if args.backup_path and "backup" in report:
            b = report["backup"]
            if b.get("success"):
                print(f"\nBackup Succeeded: {b.get('destination_path')}")
                print(f"Backup Size: {b.get('backup_size_bytes', 0):,} bytes in {b.get('duration_seconds')}s")
            else:
                print(f"\nBackup Failed: {b.get('error')}")

        if args.restore_from_path and args.restore_to_path and "restore" in report:
            r = report["restore"]
            if r.get("success"):
                print(f"\nSafe Restore Succeeded: {r.get('restored_path')}")
                print(f"Restored Size: {r.get('restored_size_bytes', 0):,} bytes")
                print(f"Restored Integrity: {r.get('integrity_status')}")
                print(f"Restored Audit Chain: {'VALID' if r.get('audit_chain_valid') else 'INVALID'}")
            else:
                print(f"\nRestore Failed: {r.get('error')}")

        print("=" * 60)

    # Determine exit code: 0 if healthy, 1 if unhealthy or error
    if integrity.get("status") != "healthy":
        sys.exit(1)
    if args.verify_audit and not report.get("audit_chain_verification", {}).get("is_valid", False):
        sys.exit(1)
    if args.backup_path and not report.get("backup", {}).get("success", False):
        sys.exit(1)
    if args.restore_from_path and args.restore_to_path and not report.get("restore", {}).get("success", False):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
