import os
import threading
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import Dict, List, Optional, Tuple
from fastapi import Request
from app.core.config import settings
from app.db.connection import get_db_cursor


def get_client_ip(request: Request) -> str:
    """Safely extracts client IP address, preventing spoofed forwarded headers.
    Arbitrary client-supplied X-Forwarded-For or X-Real-IP headers are ignored
    unless TRUST_FORWARDED_FOR is enabled AND the direct connection originates
    from an explicitly verified TRUSTED_PROXIES address.
    """
    direct_host = request.client.host if request.client else "127.0.0.1"

    if not settings.TRUST_FORWARDED_FOR:
        return direct_host

    # Only trust forwarded headers if direct connection is from a known trusted proxy
    if direct_host not in settings.TRUSTED_PROXIES:
        return direct_host

    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # First entry in X-Forwarded-For is the originating client IP
        return forwarded.split(",")[0].strip()

    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()

    return direct_host


class RateLimiterStorage(ABC):
    """Abstract storage interface for rate limiting and lockout state."""

    @abstractmethod
    def is_locked(self, key: str) -> Tuple[bool, int]:
        """Checks if a key is currently locked out. Returns (is_locked, remaining_seconds)."""
        pass

    @abstractmethod
    def record_failure(
        self,
        key: str,
        window_seconds: int,
        max_attempts: int,
        lockout_seconds: int,
    ) -> bool:
        """Records a failed attempt; triggers lockout if threshold is exceeded. Returns True if newly locked."""
        pass

    @abstractmethod
    def record_success(self, key: str) -> None:
        """Clears failure counter and active lockout on success."""
        pass

    @abstractmethod
    def check_rate_limit(
        self,
        key: str,
        max_requests: int,
        window_seconds: int,
    ) -> Tuple[bool, int]:
        """Generic sliding window rate limiter. Returns (is_limited, retry_after_seconds)."""
        pass

    @abstractmethod
    def reset_all(self) -> None:
        """Clears all records (used in test fixtures)."""
        pass


class InMemoryRateLimiterStorage(RateLimiterStorage):
    """Thread-safe in-memory sliding-window rate limiter storage.

    IMPORTANT ARCHITECTURAL NOTE:
    In-memory storage maintains state strictly within a single Python process.
    It is NOT shared across multiple Uvicorn worker processes or distributed
    container instances. For multi-worker or clustered deployments, use
    SqliteRateLimiterStorage (or an external shared Redis store).
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._failures: Dict[str, List[float]] = defaultdict(list)
        self._lockouts: Dict[str, float] = {}
        self._endpoint_hits: Dict[str, List[float]] = defaultdict(list)

    def is_locked(self, key: str) -> Tuple[bool, int]:
        now = time.time()
        with self._lock:
            lockout_until = self._lockouts.get(key, 0.0)
            if lockout_until > now:
                remaining = int(lockout_until - now) + 1
                return True, remaining
            if key in self._lockouts:
                del self._lockouts[key]
                self._failures.pop(key, None)
            return False, 0

    def record_failure(
        self,
        key: str,
        window_seconds: int,
        max_attempts: int,
        lockout_seconds: int,
    ) -> bool:
        now = time.time()
        window_start = now - window_seconds
        with self._lock:
            history = [ts for ts in self._failures[key] if ts > window_start]
            history.append(now)
            self._failures[key] = history

            if len(history) >= max_attempts:
                self._lockouts[key] = now + lockout_seconds
                return True
            return False

    def record_success(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)
            self._lockouts.pop(key, None)

    def check_rate_limit(
        self,
        key: str,
        max_requests: int,
        window_seconds: int,
    ) -> Tuple[bool, int]:
        now = time.time()
        window_start = now - window_seconds
        with self._lock:
            history = [ts for ts in self._endpoint_hits[key] if ts > window_start]
            if len(history) >= max_requests:
                oldest_in_window = history[0]
                retry_after = max(1, int((oldest_in_window + window_seconds) - now))
                return True, retry_after

            history.append(now)
            self._endpoint_hits[key] = history
            return False, 0

    def reset_all(self) -> None:
        with self._lock:
            self._failures.clear()
            self._lockouts.clear()
            self._endpoint_hits.clear()


class SqliteRateLimiterStorage(RateLimiterStorage):
    """Persistent, multi-worker shared rate limiter storage using SQLite.

    Maintains rate limiting, lockout, and endpoint throttling records inside
    the shared auth_rate_limits table. Enables multiple Uvicorn worker
    processes accessing the same SQLite database to share unified rate
    limits and lockouts with immediate ACID transactional consistency.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or settings.SQLITE_DB_PATH

    def is_locked(self, key: str) -> Tuple[bool, int]:
        now = time.time()
        with get_db_cursor(self.db_path) as cursor:
            cursor.execute(
                "SELECT locked_until FROM auth_rate_limits WHERE rate_key = ?",
                (key,),
            )
            row = cursor.fetchone()
            if row:
                locked_until = row["locked_until"]
                if locked_until > now:
                    remaining = int(locked_until - now) + 1
                    return True, remaining
                if locked_until > 0.0:
                    cursor.execute(
                        "UPDATE auth_rate_limits SET locked_until = 0.0, attempts = 0 WHERE rate_key = ?",
                        (key,),
                    )
            return False, 0

    def record_failure(
        self,
        key: str,
        window_seconds: int,
        max_attempts: int,
        lockout_seconds: int,
    ) -> bool:
        now = time.time()
        with get_db_cursor(self.db_path) as cursor:
            cursor.execute(
                "SELECT attempts, window_start, locked_until FROM auth_rate_limits WHERE rate_key = ?",
                (key,),
            )
            row = cursor.fetchone()

            if row:
                window_start = row["window_start"]
                if (now - window_start) > window_seconds:
                    attempts = 1
                    window_start = now
                else:
                    attempts = row["attempts"] + 1

                if attempts >= max_attempts:
                    locked_until = now + lockout_seconds
                    cursor.execute(
                        """
                        UPDATE auth_rate_limits
                        SET attempts = ?, window_start = ?, locked_until = ?, updated_at = ?
                        WHERE rate_key = ?
                        """,
                        (attempts, window_start, locked_until, now, key),
                    )
                    return True
                else:
                    cursor.execute(
                        """
                        UPDATE auth_rate_limits
                        SET attempts = ?, window_start = ?, updated_at = ?
                        WHERE rate_key = ?
                        """,
                        (attempts, window_start, now, key),
                    )
                    return False
            else:
                cursor.execute(
                    """
                    INSERT INTO auth_rate_limits (rate_key, attempts, window_start, locked_until, updated_at)
                    VALUES (?, 1, ?, 0.0, ?)
                    """,
                    (key, now, now),
                )
                return False

    def record_success(self, key: str) -> None:
        with get_db_cursor(self.db_path) as cursor:
            cursor.execute("DELETE FROM auth_rate_limits WHERE rate_key = ?", (key,))

    def check_rate_limit(
        self,
        key: str,
        max_requests: int,
        window_seconds: int,
    ) -> Tuple[bool, int]:
        now = time.time()
        with get_db_cursor(self.db_path) as cursor:
            cursor.execute(
                "SELECT attempts, window_start FROM auth_rate_limits WHERE rate_key = ?",
                (key,),
            )
            row = cursor.fetchone()

            if row:
                window_start = row["window_start"]
                if (now - window_start) > window_seconds:
                    cursor.execute(
                        "UPDATE auth_rate_limits SET attempts = 1, window_start = ?, updated_at = ? WHERE rate_key = ?",
                        (now, now, key),
                    )
                    return False, 0
                else:
                    attempts = row["attempts"]
                    if attempts >= max_requests:
                        retry_after = max(1, int((window_start + window_seconds) - now))
                        return True, retry_after
                    cursor.execute(
                        "UPDATE auth_rate_limits SET attempts = attempts + 1, updated_at = ? WHERE rate_key = ?",
                        (now, key),
                    )
                    return False, 0
            else:
                cursor.execute(
                    """
                    INSERT INTO auth_rate_limits (rate_key, attempts, window_start, locked_until, updated_at)
                    VALUES (?, 1, ?, 0.0, ?)
                    """,
                    (key, now, now),
                )
                return False, 0

    def reset_all(self) -> None:
        with get_db_cursor(self.db_path) as cursor:
            cursor.execute("DELETE FROM auth_rate_limits")


def create_rate_limiter_storage(
    backend: Optional[str] = None,
    db_path: Optional[str] = None,
) -> RateLimiterStorage:
    """Factory creating rate limiter storage based on configuration."""
    selected = (backend or settings.RATE_LIMIT_STORAGE_BACKEND).lower()
    if selected == "memory":
        return InMemoryRateLimiterStorage()
    return SqliteRateLimiterStorage(db_path=db_path)


class AuthRateLimiter:
    """Authentication rate limiter and account lockout coordinator."""

    def __init__(self, storage: Optional[RateLimiterStorage] = None):
        self._storage = storage or create_rate_limiter_storage()

    def set_storage(self, storage: RateLimiterStorage) -> None:
        self._storage = storage

    def is_locked(self, key: str) -> Tuple[bool, int]:
        return self._storage.is_locked(key)

    def record_failure(self, key: str) -> bool:
        return self._storage.record_failure(
            key=key,
            window_seconds=settings.AUTH_RATE_LIMIT_WINDOW_SECONDS,
            max_attempts=settings.AUTH_RATE_LIMIT_MAX_ATTEMPTS,
            lockout_seconds=settings.AUTH_RATE_LIMIT_LOCKOUT_SECONDS,
        )

    def record_success(self, key: str) -> None:
        self._storage.record_success(key)

    def reset_all(self) -> None:
        self._storage.reset_all()


class EndpointRateLimiter:
    """Endpoint abuse prevention limiter for compute-intensive endpoints (e.g. scan)."""

    def __init__(self, storage: Optional[RateLimiterStorage] = None):
        self._storage = storage or create_rate_limiter_storage()

    def set_storage(self, storage: RateLimiterStorage) -> None:
        self._storage = storage

    def check_rate_limit(
        self,
        key: str,
        max_requests: Optional[int] = None,
        window_seconds: int = 60,
    ) -> Tuple[bool, int]:
        limit = max_requests or settings.SCAN_RATE_LIMIT_PER_MINUTE
        return self._storage.check_rate_limit(
            key=key,
            max_requests=limit,
            window_seconds=window_seconds,
        )

    def reset_all(self) -> None:
        self._storage.reset_all()


# Global rate limiter instances
auth_rate_limiter = AuthRateLimiter()
scan_rate_limiter = EndpointRateLimiter()
