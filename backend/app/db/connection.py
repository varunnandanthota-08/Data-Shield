import os
import sqlite3
from contextlib import contextmanager
from typing import Generator, Optional
from app.core.config import settings


BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
PROJECT_ROOT = os.path.abspath(os.path.join(BACKEND_DIR, ".."))
OBSOLETE_ROOT_DB = os.path.normpath(os.path.join(PROJECT_ROOT, "datashield.db"))


def resolve_db_path(raw_path: str) -> str:
    """Safely and deterministically resolves an SQLite database path.

    Guarantees:
    1. Preserves ':memory:' for in-memory databases.
    2. Preserves explicitly supplied absolute paths.
    3. Prevents accidental selection of the obsolete project-root 'datashield.db':
       if a relative path resolves to the obsolete root file, it is automatically
       rerouted to the canonical backend database.
    4. For relative paths (e.g. 'datashield.db', 'datashield_staging.db'),
       anchors resolution deterministically to BACKEND_DIR so behavior is identical
       regardless of the process's current working directory.
    """
    if raw_path == ":memory:":
        return ":memory:"

    if os.path.isabs(raw_path):
        resolved = os.path.normpath(raw_path)
    else:
        candidate_cwd = os.path.normpath(os.path.abspath(raw_path))
        if candidate_cwd == OBSOLETE_ROOT_DB:
            # Guard against accidental selection of obsolete root datashield.db
            resolved = os.path.normpath(os.path.join(BACKEND_DIR, "datashield.db"))
        elif os.path.exists(candidate_cwd) and os.path.commonpath([candidate_cwd, BACKEND_DIR]) == BACKEND_DIR:
            resolved = candidate_cwd
        else:
            resolved = os.path.normpath(os.path.join(BACKEND_DIR, raw_path))

    parent_dir = os.path.dirname(resolved)
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)
    return resolved


def get_db_path(override_path: Optional[str] = None) -> str:
    """Resolves database file path."""
    target = override_path if override_path is not None else settings.SQLITE_DB_PATH
    return resolve_db_path(target)


def get_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Creates a configured SQLite connection with row factories."""
    path = get_db_path(db_path)
    conn = sqlite3.connect(path, timeout=10.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Enable WAL mode for high concurrency and write safety when using file db
    if path != ":memory:":
        conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


@contextmanager
def get_db_cursor(db_path: Optional[str] = None) -> Generator[sqlite3.Cursor, None, None]:
    """Context manager providing an auto-committing / auto-rollback database cursor."""
    conn = get_connection(db_path)
    cursor = conn.cursor()
    try:
        yield cursor
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
