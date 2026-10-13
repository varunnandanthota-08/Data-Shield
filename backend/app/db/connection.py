import os
import sqlite3
from contextlib import contextmanager
from typing import Generator, Optional
from app.core.config import settings


def get_db_path(override_path: Optional[str] = None) -> str:
    """Resolves database file path."""
    if override_path:
        return override_path
    db_path = settings.SQLITE_DB_PATH
    # In testing or relative path, ensure parent directory exists if needed
    if db_path != ":memory:" and os.path.dirname(db_path):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
    return db_path


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
