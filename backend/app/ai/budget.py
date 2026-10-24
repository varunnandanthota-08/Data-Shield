import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.core.config import settings
from app.db.connection import get_connection, get_db_path

logger = logging.getLogger(__name__)


@dataclass
class BudgetCheckResult:
    allowed: bool
    reason: Optional[str] = None
    exhausted_scope: Optional[str] = None  # "user", "tenant", "tenant_hard_ceiling"
    reservation_id: Optional[str] = None
    user_usage: int = 0
    user_limit: int = 0
    tenant_usage: int = 0
    tenant_limit: int = 0
    tenant_hard_ceiling: int = 0


class AIBudgetService:
    """Thread-safe and process-safe persistent accounting service for rolling 24-hour
    Gemini advisory AI usage budgets.

    Architectural Invariants:
    1. Zero Secrets / Zero Payload Storage: Only metadata (user_id, org_id, timestamp,
       created_at, scan_id, status) is recorded. Never raw scanned text, prompts, or API keys.
    2. Atomic Check-and-Reserve: Executes atomic SQLite transactions with write-locking
       (and process-level mutex) to prevent concurrent requests from bypassing configured limits.
    3. Multi-Worker & Restart Persistence: State is written directly to SQLite WAL,
       surviving application restarts and sharing consistent limits across worker processes.
    4. Deterministic Precedence: When budget is exhausted, Gemini call is skipped while
       deterministic detection, risk scoring, and policy enforcement continue unaffected.
    """

    def __init__(self, db_path: Optional[str] = None):
        self._db_path = db_path
        self._lock = threading.Lock()

    @property
    def db_path(self) -> str:
        return get_db_path(self._db_path)

    def check_and_reserve(
        self,
        user_id: str,
        org_id: str,
        scan_id: Optional[str] = None,
        now: Optional[float] = None,
    ) -> BudgetCheckResult:
        """Atomically evaluates rolling 24-hour limits for the user and tenant,
        and if permitted, inserts a reservation record within the same transaction.
        """
        user_limit = settings.AI_BUDGET_USER_DAILY_LIMIT
        tenant_limit = settings.AI_BUDGET_TENANT_DAILY_LIMIT
        hard_ceiling = settings.AI_BUDGET_TENANT_HARD_CEILING
        window_seconds = settings.AI_BUDGET_WINDOW_SECONDS

        if not settings.AI_BUDGET_ENABLED:
            return BudgetCheckResult(
                allowed=True,
                reason="AI usage budget is disabled in configuration",
                user_usage=0,
                user_limit=user_limit,
                tenant_usage=0,
                tenant_limit=tenant_limit,
                tenant_hard_ceiling=hard_ceiling,
            )

        current_ts = now if now is not None else time.time()
        cutoff_ts = current_ts - window_seconds
        now_iso = datetime.fromtimestamp(current_ts, tz=timezone.utc).isoformat()

        # Mutual exclusion inside Python process + SQLite write transaction lock
        with self._lock:
            conn = get_connection(self.db_path)
            try:
                # Use immediate transaction so write lock is acquired before reading counts
                conn.execute("BEGIN IMMEDIATE")
                cursor = conn.cursor()

                # 1. Query user usage within the rolling window
                cursor.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM ai_budget_usage
                    WHERE user_id = ? AND timestamp > ?
                    """,
                    (user_id, cutoff_ts),
                )
                user_usage = cursor.fetchone()["cnt"]

                # 2. Query tenant aggregate usage within the rolling window
                cursor.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM ai_budget_usage
                    WHERE org_id = ? AND timestamp > ?
                    """,
                    (org_id, cutoff_ts),
                )
                tenant_usage = cursor.fetchone()["cnt"]

                # 3. Check tenant hard ceiling (absolute upper safety bound)
                if tenant_usage >= hard_ceiling:
                    conn.rollback()
                    logger.warning(
                        "AI budget exhausted: Tenant hard ceiling reached (%d/%d) for org '%s'",
                        tenant_usage,
                        hard_ceiling,
                        org_id,
                    )
                    return BudgetCheckResult(
                        allowed=False,
                        reason=(
                            f"Tenant hard ceiling exhausted: {tenant_usage}/{hard_ceiling} "
                            f"AI scans used in rolling {window_seconds // 3600} hours"
                        ),
                        exhausted_scope="tenant_hard_ceiling",
                        user_usage=user_usage,
                        user_limit=user_limit,
                        tenant_usage=tenant_usage,
                        tenant_limit=tenant_limit,
                        tenant_hard_ceiling=hard_ceiling,
                    )

                # 4. Check tenant daily operational limit
                if tenant_usage >= tenant_limit:
                    conn.rollback()
                    logger.warning(
                        "AI budget exhausted: Tenant operational limit reached (%d/%d) for org '%s'",
                        tenant_usage,
                        tenant_limit,
                        org_id,
                    )
                    return BudgetCheckResult(
                        allowed=False,
                        reason=(
                            f"Tenant AI daily usage budget exhausted: {tenant_usage}/{tenant_limit} "
                            f"AI scans used in rolling {window_seconds // 3600} hours"
                        ),
                        exhausted_scope="tenant",
                        user_usage=user_usage,
                        user_limit=user_limit,
                        tenant_usage=tenant_usage,
                        tenant_limit=tenant_limit,
                        tenant_hard_ceiling=hard_ceiling,
                    )

                # 5. Check user daily limit
                if user_usage >= user_limit:
                    conn.rollback()
                    logger.warning(
                        "AI budget exhausted: User limit reached (%d/%d) for user '%s' in org '%s'",
                        user_usage,
                        user_limit,
                        user_id,
                        org_id,
                    )
                    return BudgetCheckResult(
                        allowed=False,
                        reason=(
                            f"User AI daily usage budget exhausted: {user_usage}/{user_limit} "
                            f"AI scans used in rolling {window_seconds // 3600} hours"
                        ),
                        exhausted_scope="user",
                        user_usage=user_usage,
                        user_limit=user_limit,
                        tenant_usage=tenant_usage,
                        tenant_limit=tenant_limit,
                        tenant_hard_ceiling=hard_ceiling,
                    )

                # 6. Both limits satisfied: Atomically reserve usage record
                reservation_id = f"aibudget_{uuid.uuid4().hex[:16]}"
                cursor.execute(
                    """
                    INSERT INTO ai_budget_usage (id, user_id, org_id, timestamp, created_at, scan_id, status)
                    VALUES (?, ?, ?, ?, ?, ?, 'RESERVED')
                    """,
                    (reservation_id, user_id, org_id, current_ts, now_iso, scan_id),
                )
                conn.commit()

                return BudgetCheckResult(
                    allowed=True,
                    reservation_id=reservation_id,
                    user_usage=user_usage + 1,
                    user_limit=user_limit,
                    tenant_usage=tenant_usage + 1,
                    tenant_limit=tenant_limit,
                    tenant_hard_ceiling=hard_ceiling,
                )
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    def get_usage_summary(
        self,
        user_id: Optional[str] = None,
        org_id: str = "default",
        now: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Queries current non-mutating rolling-window usage statistics for a user and tenant."""
        current_ts = now if now is not None else time.time()
        window_seconds = settings.AI_BUDGET_WINDOW_SECONDS
        cutoff_ts = current_ts - window_seconds

        user_limit = settings.AI_BUDGET_USER_DAILY_LIMIT
        tenant_limit = settings.AI_BUDGET_TENANT_DAILY_LIMIT
        hard_ceiling = settings.AI_BUDGET_TENANT_HARD_CEILING

        conn = get_connection(self.db_path)
        try:
            cursor = conn.cursor()

            # Tenant aggregate usage
            cursor.execute(
                """
                SELECT COUNT(*) AS cnt, MIN(timestamp) AS oldest_ts
                FROM ai_budget_usage
                WHERE org_id = ? AND timestamp > ?
                """,
                (org_id, cutoff_ts),
            )
            tenant_row = cursor.fetchone()
            tenant_used = tenant_row["cnt"] if tenant_row else 0
            tenant_oldest = tenant_row["oldest_ts"] if tenant_row else None

            # User usage if user_id is provided
            user_used = 0
            user_oldest = None
            if user_id:
                cursor.execute(
                    """
                    SELECT COUNT(*) AS cnt, MIN(timestamp) AS oldest_ts
                    FROM ai_budget_usage
                    WHERE user_id = ? AND org_id = ? AND timestamp > ?
                    """,
                    (user_id, org_id, cutoff_ts),
                )
                user_row = cursor.fetchone()
                user_used = user_row["cnt"] if user_row else 0
                user_oldest = user_row["oldest_ts"] if user_row else None

            # Calculate earliest reset (time until oldest reservation expires out of window)
            earliest_reset_seconds: Optional[int] = None
            relevant_oldest = user_oldest or tenant_oldest
            if relevant_oldest:
                seconds_remaining = int((relevant_oldest + window_seconds) - current_ts)
                earliest_reset_seconds = max(0, seconds_remaining)

            user_remaining = max(0, user_limit - user_used)
            tenant_remaining = max(0, tenant_limit - tenant_used)
            ceiling_remaining = max(0, hard_ceiling - tenant_used)

            summary = {
                "enabled": settings.AI_BUDGET_ENABLED,
                "window_seconds": window_seconds,
                "user_budget": {
                    "user_id": user_id,
                    "used": user_used,
                    "limit": user_limit,
                    "remaining": user_remaining,
                    "is_exhausted": user_used >= user_limit,
                },
                "tenant_budget": {
                    "org_id": org_id,
                    "used": tenant_used,
                    "limit": tenant_limit,
                    "hard_ceiling": hard_ceiling,
                    "remaining": tenant_remaining,
                    "hard_ceiling_remaining": ceiling_remaining,
                    "is_exhausted": tenant_used >= tenant_limit,
                    "is_hard_ceiling_exhausted": tenant_used >= hard_ceiling,
                },
                "earliest_reset_seconds": earliest_reset_seconds,
            }
            return summary
        finally:
            conn.close()

    def get_tenant_user_breakdown(
        self,
        org_id: str,
        now: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """Returns per-user usage breakdown within a single tenant for tenant administrators."""
        current_ts = now if now is not None else time.time()
        window_seconds = settings.AI_BUDGET_WINDOW_SECONDS
        cutoff_ts = current_ts - window_seconds

        conn = get_connection(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT user_id, COUNT(*) AS scan_count, MAX(timestamp) AS last_scan_ts
                FROM ai_budget_usage
                WHERE org_id = ? AND timestamp > ?
                GROUP BY user_id
                ORDER BY scan_count DESC
                """,
                (org_id, cutoff_ts),
            )
            rows = cursor.fetchall()
            return [
                {
                    "user_id": r["user_id"],
                    "scan_count": r["scan_count"],
                    "last_scan_at": (
                        datetime.fromtimestamp(r["last_scan_ts"], tz=timezone.utc).isoformat()
                        if r["last_scan_ts"]
                        else None
                    ),
                }
                for r in rows
            ]
        finally:
            conn.close()


ai_budget_service = AIBudgetService()
