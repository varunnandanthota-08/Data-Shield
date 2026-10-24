import os
import sqlite3
import pytest
from app.db.connection import (
    BACKEND_DIR,
    OBSOLETE_ROOT_DB,
    PROJECT_ROOT,
    get_db_path,
    resolve_db_path,
)
from scripts.db_verify_and_backup import perform_safe_restore


class TestDatabasePathResolution:
    """Verifies deterministic path resolution and prevention of obsolete root db selection."""

    def test_default_datashield_db_resolves_to_backend(self):
        """Relative 'datashield.db' must always anchor to backend/datashield.db."""
        resolved = resolve_db_path("datashield.db")
        expected = os.path.normpath(os.path.join(BACKEND_DIR, "datashield.db"))
        assert resolved == expected

    def test_staging_database_resolves_to_backend_directory(self):
        """Relative 'datashield_staging.db' must anchor to backend/datashield_staging.db."""
        resolved = resolve_db_path("datashield_staging.db")
        expected = os.path.normpath(os.path.join(BACKEND_DIR, "datashield_staging.db"))
        assert resolved == expected

    def test_prevents_accidental_selection_of_obsolete_root_db(self, monkeypatch):
        """When current working directory is project root, 'datashield.db' must NOT resolve to root db."""
        monkeypatch.chdir(PROJECT_ROOT)
        # Verify CWD is indeed project root
        assert os.path.normpath(os.getcwd()) == PROJECT_ROOT

        # Resolving "datashield.db" while in project root must route to backend/datashield.db
        resolved = resolve_db_path("datashield.db")
        assert resolved != OBSOLETE_ROOT_DB
        expected = os.path.normpath(os.path.join(BACKEND_DIR, "datashield.db"))
        assert resolved == expected

    def test_backend_relative_path_from_project_root(self, monkeypatch):
        """When in project root, 'backend/datashield.db' resolves to backend/datashield.db."""
        monkeypatch.chdir(PROJECT_ROOT)
        resolved = resolve_db_path("backend/datashield.db")
        expected = os.path.normpath(os.path.join(BACKEND_DIR, "datashield.db"))
        assert resolved == expected

    def test_memory_database_preserved(self):
        """:memory: must remain :memory:."""
        assert resolve_db_path(":memory:") == ":memory:"

    def test_absolute_path_preserved(self, tmp_path):
        """Explicit absolute paths must be preserved exactly."""
        custom_db = str(tmp_path / "custom_audit.db")
        resolved = resolve_db_path(custom_db)
        assert resolved == os.path.normpath(custom_db)

    def test_get_db_path_override(self, tmp_path):
        """get_db_path with override_path must resolve through resolve_db_path."""
        override = str(tmp_path / "override.db")
        assert get_db_path(override) == os.path.normpath(override)


class TestBackupAndSafeRestoreProtection:
    """Verifies that backup restore operations cannot overwrite active databases."""

    def test_safe_restore_refuses_to_overwrite_active_db(self, tmp_path):
        """Restoring to the active database path must be blocked immediately."""
        active_db = str(tmp_path / "active.db")
        backup_db = str(tmp_path / "backup.db")

        # Create dummy backup db
        conn = sqlite3.connect(backup_db)
        conn.execute("CREATE TABLE t (id INT)")
        conn.commit()
        conn.close()

        # Attempt restore where dest == active
        result = perform_safe_restore(
            backup_path=backup_db,
            dest_restore_path=active_db,
            active_db_path=active_db,
        )
        assert result["success"] is False
        assert "SAFETY VIOLATION PREVENTED" in result["error"]
