from datetime import datetime, timezone
from typing import Any, Dict
from fastapi import APIRouter
from app.core.config import settings

router = APIRouter(prefix="/health", tags=["Health"])


@router.get("", summary="System Health Check")
async def get_health() -> Dict[str, Any]:
    """Returns the operational status of DataShield AI backend service."""
    return {
        "status": "healthy",
        "service": "datashield-ai-backend",
        "version": settings.VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "mode": settings.ENVIRONMENT,
            "llm_configured": settings.is_llm_configured,
        },
    }


@router.get("/ready", summary="System Readiness Check")
async def get_readiness() -> Dict[str, Any]:
    """Readiness probe checking database responsiveness and reporting resolved path without secrets."""
    import os
    from fastapi import HTTPException, status
    from app.db.connection import get_db_cursor, get_db_path

    resolved_path = os.path.abspath(get_db_path())
    try:
        with get_db_cursor() as cursor:
            cursor.execute("SELECT 1")
            cursor.fetchone()
        db_connected = True
    except Exception:
        db_connected = False

    if not db_connected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database connectivity probe failed",
        )

    return {
        "status": "ready",
        "database": "connected",
        "resolved_db_path": resolved_path,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

