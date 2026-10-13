from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import audit, health, policies, scan
from app.core.config import settings
from app.db.repository import policy_repo
from app.db.schema import init_db
from app.policy.engine import policy_engine


@asynccontextmanager
async def lifespan(app: FastAPI):
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


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="DataShield AI — GenAI Data Loss Prevention & Sensitive Data Exposure Gateway",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Setup CORS
origins = settings.CORS_ORIGINS if isinstance(settings.CORS_ORIGINS, list) else ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API Routers
app.include_router(health.router, prefix="/api")
app.include_router(scan.router, prefix="/api")
app.include_router(policies.router, prefix="/api")
app.include_router(audit.router, prefix="/api")


@app.get("/")
async def root():
    return {
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "docs": "/docs",
        "health": "/api/health",
        "policies": "/api/v1/policies",
        "audit": "/api/v1/audit/events",
    }
