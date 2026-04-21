import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.db.postgres import create_tables, AsyncSessionLocal
from app.db.opensearch import ensure_indices
from app.db.seed import seed_default_admin

settings = get_settings()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logging.info("SOCINT API starting up...")
    await create_tables()
    await ensure_indices()
    async with AsyncSessionLocal() as db:
        await seed_default_admin(db)
    logging.info("Database ready")
    yield
    # Shutdown
    logging.info("SOCINT API shutting down")


app = FastAPI(
    title="SOCINT",
    description="Unified Cyber Threat Intelligence Platform",
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Register routers ─────────────────────────────────────────────
from app.api.rest.routers.auth import router as auth_router
from app.api.rest.routers.intel import router as intel_router
from app.api.rest.routers.cases import router as cases_router, alert_router
from app.api.rest.routers.darkweb import router as darkweb_router
from app.api.rest.routers.enrichment import router as enrichment_router
from app.api.rest.routers.connectors import router as connectors_router
from app.api.rest.routers.rules import router as rules_router
from app.api.rest.routers.sightings import router as sightings_router
from app.api.rest.routers.alert_rules import router as alert_rules_router
from app.api.rest.routers.export import router as export_router
from app.stream.sse import router as stream_router
from app.api.rest.routers.compliance import router as compliance_router
from app.api.rest.routers.hunting import router as hunting_router
from app.api.rest.routers.docs import router as docs_router

for router in [
    auth_router,
    intel_router,
    cases_router,
    alert_router,
    darkweb_router,
    enrichment_router,
    connectors_router,
    rules_router,
    sightings_router,
    alert_rules_router,
    export_router,
    stream_router,
    compliance_router,
    hunting_router,
    docs_router,
]:
    app.include_router(router, prefix="/api")


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}


@app.get("/")
async def root():
    return {"name": "SOCINT", "docs": "/api/docs"}
