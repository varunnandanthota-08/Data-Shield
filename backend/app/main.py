import logging
import uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.api.routes import audit, auth, health, policies, scan, users
from app.core.config import settings
from app.db.connection import get_db_path
from app.db.repository import policy_repo
from app.db.schema import init_db
from app.policy.engine import policy_engine

logger = logging.getLogger("datashield.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Safe diagnostic reporting the resolved database path without exposing secrets
    import os
    resolved_db = os.path.abspath(get_db_path())
    logger.info("DataShield AI database resolved at startup: %s", resolved_db)
    # Initialize SQLite database and seed default policies
    init_db()
    # Synchronize policy engine with stored policies
    db_policies = policy_repo.list_policies()
    if db_policies:
        policy_engine.set_rules(db_policies)
    yield


# Ensure tables exist on initial import as well
init_db()
db_policies = policy_repo.list_policies()
if db_policies:
    policy_engine.set_rules(db_policies)

# Disable interactive docs in production unless explicitly permitted
is_prod = settings.ENVIRONMENT.lower() == "production"
docs_url = None if (is_prod and not settings.ENABLE_PROD_DOCS) else "/docs"
redoc_url = None if (is_prod and not settings.ENABLE_PROD_DOCS) else "/redoc"

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="DataShield AI — GenAI Data Loss Prevention & Sensitive Data Exposure Gateway",
    docs_url=docs_url,
    redoc_url=redoc_url,
    lifespan=lifespan,
)

# Setup CORS with explicit origin validation (disallow '*' with credentials)
raw_origins = settings.CORS_ORIGINS if isinstance(settings.CORS_ORIGINS, list) else [settings.CORS_ORIGINS]
cors_origins = [o for o in raw_origins if o != "*"] if is_prod else raw_origins
if not cors_origins:
    cors_origins = ["http://localhost:5173", "http://127.0.0.1:5173"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["*"],
)


# Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response


# Global sanitized error handler to prevent internal information leakage
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    error_id = f"err_{uuid.uuid4().hex[:10]}"
    logger.error("Unhandled server exception [%s]: %s", error_id, str(exc), exc_info=settings.DEBUG)

    if settings.DEBUG:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "detail": "Internal server error occurred.",
                "error_id": error_id,
                "debug_message": str(exc),
            },
        )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "An internal server error occurred. Please contact the security operations team.",
            "error_id": error_id,
        },
    )


# Include API Routers
app.include_router(health.router, prefix="/api")
app.include_router(auth.router, prefix="/api")
app.include_router(users.router, prefix="/api")
app.include_router(scan.router, prefix="/api")
app.include_router(policies.router, prefix="/api")
app.include_router(audit.router, prefix="/api")


@app.get("/")
async def root():
    return {
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "health": "/api/health",
        "policies": "/api/v1/policies",
        "audit": "/api/v1/audit/events",
    }
