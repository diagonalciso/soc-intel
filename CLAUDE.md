# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

SOCint is a unified threat intelligence platform (TIP) built around STIX 2.1, with 26 built-in data connectors, on-demand enrichment, dark web monitoring, incident case management, and a MITRE ATT&CK heatmap. It runs as a multi-service Docker Compose stack.

## Commands

### Full Stack (recommended)
```bash
cp .env.example .env   # configure secrets first
docker compose up -d --build
```

### Backend (standalone)
```bash
cd backend
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
python -m app.workers.main   # connector scheduler + decay jobs
```

### Frontend (standalone)
```bash
cd frontend
npm run dev       # Vite dev server on port 3000, proxies /api → api:8000
npm run build
npm run preview
```

### Testing
```bash
cd backend
pytest
pytest tests/path/to/test_file.py::test_name   # single test
python validate_connectors.py   # test connectors without full stack
```

### Database migrations
Alembic migrations run automatically at startup via FastAPI lifespan. To run manually:
```bash
cd backend
alembic upgrade head
```

## Architecture

### Services (docker-compose.yml)
| Service | Port | Purpose |
|---------|------|---------|
| `api` | 8000 | FastAPI REST + GraphQL + SSE |
| `worker` | — | APScheduler connector jobs, alert matching, decay |
| `frontend` | 3000 | React 18 + Vite (nginx in prod) |
| `postgres` | 5432 | SQLAlchemy ORM (cases, users, rules, compliance) |
| `opensearch` | 9200 | STIX 2.1 object store (all threat intel) |
| `redis` | 6379 | Cache, pub/sub for real-time alerts |
| `rabbitmq` | 5672 | Bulk indexing queue (sightings, decay) |
| `minio` | 9000 | S3-compatible file storage |
| `tor` | 9050 | SOCKS5 proxy for dark web connectors |

### Data Flow
1. **Connectors** (scheduled via APScheduler in `worker`) fetch external feeds and call `push_to_platform()` which upserts STIX objects into OpenSearch with deterministic UUID5 IDs (`type:value`).
2. **Enrichment pipeline** (`app/enrichment/pipeline.py`) runs on-demand against OpenSearch objects, merging results from GreyNoise, OTX, VirusTotal, AbuseIPDB.
3. **Alert matcher** (`app/workers/alert_matcher.py`) evaluates detection rules against new indicators and publishes hits to Redis pub/sub → SSE stream.
4. **Indicator decay** runs daily (03:00 UTC), reducing confidence on aged IoCs; revokes at 90 days unless a sighting exempts them.

### Key Design Decisions
- **STIX 2.1 is the canonical format** — everything in OpenSearch is STIX JSON with socint extensions (`tlp`, `source`, `confidence`, `decay_score`, `sightings`)
- **Deterministic IDs** — `uuid5(type + ":" + value)` means the same IoC from multiple sources converges to one document (upsert, not duplicate)
- **TLP everywhere** — every STIX object carries a canonical `tlp` field (CLEAR/GREEN/AMBER/AMBER+STRICT/RED)
- **Source reliability weight** — per-connector `source_reliability` (0–100) multiplies into indicator confidence at ingest
- **Fully async** — FastAPI + asyncpg + aio-pika + aiohttp throughout; no sync DB calls in request handlers

### Backend Layout (`backend/app/`)
```
main.py                  # FastAPI app, router registration, lifespan (DB init + seed)
config.py                # Settings (pydantic-settings, reads .env)
core/
  stix_engine.py         # STIX CRUD, TLP normalization, deterministic ID generation
  warning_lists.py       # MISP warning list FP suppression
api/rest/routers/        # One file per domain (intel, cases, rules, enrichment, …)
api/stream/              # SSE endpoints (real-time alerts)
api/graphql/             # Strawberry GraphQL (ready to use)
connectors/
  sdk/base.py            # BaseConnector + ConnectorConfig + IngestResult
  builtin/               # 26 built-in connectors
workers/
  main.py                # Entry point, signal handling
  scheduler.py           # APScheduler registration of all 26 connectors
  alert_matcher.py       # Detection rule evaluation
enrichment/
  pipeline.py            # Parallel enrichment engine
models/                  # SQLAlchemy ORM models (postgres only)
auth/
  security.py            # JWT generation/verification (python-jose + bcrypt)
  dependencies.py        # FastAPI deps: get_current_user, require_analyst, require_admin
db/
  postgres.py            # AsyncSession factory, declarative Base
  opensearch.py          # Client, index setup, STIX + darkweb storage helpers
  redis.py               # Cache + pub/sub helpers
  seed.py                # First-run admin account seeding
```

### Frontend Layout (`frontend/src/`)
```
App.tsx                  # React Router routes, global layout
pages/                   # One file per route (Dashboard, Intel, Cases, DarkWeb, Rules, Attack, Connectors, CompliancePage)
components/              # Reusable UI components
store/                   # Zustand global state
api/                     # axios clients and React Query hooks
types/                   # TypeScript interfaces matching backend models
```

## Adding a Connector

1. Create `backend/app/connectors/builtin/my_source.py` extending `BaseConnector`:
```python
from app.connectors.sdk.base import BaseConnector, ConnectorConfig

class MySourceConnector(BaseConnector):
    def __init__(self):
        super().__init__(ConnectorConfig(
            name="my-source",
            display_name="My Source",
            connector_type="import_external",   # or "import_internal"
            schedule="0 */6 * * *",             # cron expression
            source_reliability=75,              # 0–100
            default_tlp="TLP:CLEAR",
        ))

    async def run(self):
        # fetch data, build STIX objects, then:
        await self.push_to_platform(stix_objects)
```

2. Register in `backend/app/workers/scheduler.py` alongside the other connectors.
3. Test without a full stack: `python validate_connectors.py`.

## Environment Variables

Key variables from `.env` (see `.env.example` for full list):
- `SECRET_KEY` — JWT signing key (64-char hex)
- `CONNECTOR_API_KEY` — Internal connector auth, separate from SECRET_KEY
- `SEED_ADMIN_PASSWORD` — Used only on first startup to create the admin account
- `OTX_API_KEY`, `NVD_API_KEY`, `VIRUSTOTAL_API_KEY` — Optional; connectors degrade gracefully without them
- `TOR_PROXY=socks5://tor:9050` — Used by dark web connectors

## API

- REST docs: `http://localhost:8000/api/docs`
- All REST endpoints are under `/api`
- GraphQL: `/graphql` (Strawberry)
- SSE stream: `/stream`
- Auth: JWT bearer token, obtained via `POST /api/auth/login`
