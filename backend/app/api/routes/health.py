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
