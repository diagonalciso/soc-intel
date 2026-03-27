# CLAWINT — Installation Guide

CLAWINT is a unified, self-hosted Cyber Threat Intelligence platform. It combines indicator management, case management, dark web tracking, enrichment, detection rules, and a connector framework into a single Docker Compose deployment.

---

## Table of Contents

1. [Requirements](#1-requirements)
2. [Quick Start](#2-quick-start)
3. [Configuration](#3-configuration)
4. [First Login](#4-first-login)
5. [Connectors](#5-connectors)
6. [API Keys](#6-api-keys)
7. [Production Deployment](#7-production-deployment)
8. [Port Reference](#8-port-reference)
9. [Architecture](#9-architecture)
10. [Upgrading](#10-upgrading)
11. [Troubleshooting](#11-troubleshooting)

---

## 1. Requirements

### Minimum (free sources only)
| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 4 cores | 8 cores |
| RAM | 8 GB | 16 GB |
| Disk | 50 GB | 200 GB |
| OS | Linux (Ubuntu 22.04+ / Debian 12+) | Ubuntu 22.04 LTS |

> **OpenSearch requires at least 4 GB RAM allocated to its JVM.** The default config sets `-Xms2g -Xmx2g`. On systems with less than 8 GB total RAM, reduce this in `docker-compose.yml`.

### Software
- **Docker** 24.0+ with the Compose plugin (`docker compose`, not `docker-compose`)
- **Git**

Check versions:
```bash
docker --version
docker compose version
```

### OS tuning (required for OpenSearch)

OpenSearch requires a higher virtual memory limit. Set this permanently:

```bash
# Apply immediately
sudo sysctl -w vm.max_map_count=262144

# Make permanent across reboots
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

---

## 2. Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/diagonalciso/Clawint.git
cd Clawint

# 2. Create your .env file
cp .env.example .env

# 3. Generate and set a secure secret key
SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
CONNECTOR_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
sed -i "s/change-me-to-a-long-random-string/$SECRET/" .env
sed -i "s/change-me-connector-key/$CONNECTOR_KEY/" .env

# 4. Set a strong admin password
sed -i "s/changeme123!/YourStrongPasswordHere!/" .env

# 5. Start the stack
docker compose up -d --build

# 6. Watch startup logs (takes 2–3 minutes on first run)
docker compose logs -f api
```

Once you see `CLAWINT API starting up... Database ready`, the platform is ready.

Open **http://localhost:3000** in your browser.

---

## 3. Configuration

All configuration is done via the `.env` file. Never commit this file to version control — it is listed in `.gitignore`.

### Core settings

```env
APP_ENV=development          # Set to "production" for production deployments
SECRET_KEY=<random-hex-64>   # JWT signing key — keep secret, never share
CONNECTOR_API_KEY=<random>   # Internal connector auth key — different from SECRET_KEY
ALLOWED_ORIGINS=http://localhost:3000  # CORS origins — set to your domain in production
```

### Admin account (first-run seed)

These values are only used on the very first startup, when no users exist in the database. After the first user is created, these are ignored.

```env
SEED_ORG=MyOrg
SEED_EMAIL=admin@myorg.com
SEED_USERNAME=admin
SEED_PASSWORD=YourStrongPassword!
```

> Change the password immediately after first login via the UI or API.

### Database passwords

For production, change all default passwords:

```env
POSTGRES_PASSWORD=<strong-password>
REDIS_PASSWORD=<strong-password>
RABBITMQ_PASS=<strong-password>
MINIO_ROOT_PASSWORD=<strong-password>
```

### OpenSearch memory

Edit `docker-compose.yml` to adjust OpenSearch JVM heap. Default is 2 GB each:

```yaml
environment:
  - OPENSEARCH_JAVA_OPTS=-Xms2g -Xmx2g  # Adjust to ~50% of available RAM
```

---

## 4. First Login

1. Navigate to **http://localhost:3000**
2. Log in with the credentials you set in `SEED_EMAIL` / `SEED_PASSWORD`
3. Go to **Settings → Security** and change your password
4. Navigate to **Connectors** to see all available data sources
5. Trigger the **Sigma Rules** connector to populate the detection rules library (or wait for the weekly run)

### API access

Interactive API documentation is available at **http://localhost:8000/api/docs**

Obtain a JWT token:
```bash
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@myorg.com","password":"YourPassword"}'
```

Use the returned `access_token` as a Bearer token for all subsequent API calls:
```bash
curl http://localhost:8000/api/connectors \
  -H "Authorization: Bearer <token>"
```

---

## 5. Connectors

CLAWINT ships with 22 built-in connectors (18 import + 4 enrichment) that run automatically on schedule. All free connectors work out of the box with no API key required.

### Import connectors

| Connector | Type | Schedule | Reliability | Notes |
|-----------|------|----------|-------------|-------|
| AlienVault OTX | Import | Every 2h | 65 | Free API key required |
| MISP Public Feeds | Import | Every 4h | 72 | No key needed |
| TAXII 2.1 (Anomali Limo) | Import | Every 6h | 70 | No key needed |
| Ransomwatch | Import | Every 2h | 78 | No key needed |
| Ransomware.live (v2) | Import | Every 2h | 80 | Victims + group profiles |
| RansomLook | Import | Every 3h | 80 | CC BY 4.0 |
| DeepDarkCTI (Ransomware Groups) | Import | Daily 06:00 | 80 | 200+ groups + onion URLs |
| Ransomware Leak Sites (Tor) | Import | Every 3h | 80 | Tor proxy required |
| URLhaus (abuse.ch) | Import | Every 30min | 75 | No key needed |
| ThreatFox (abuse.ch) | Import | Every 4h | 75 | No key needed |
| Feodo Tracker (abuse.ch) | Import | Every 6h | 80 | No key needed |
| Spamhaus DROP/EDROP | Import | Every 12h | 85 | No key needed |
| OpenPhish | Import | Every 12h | 68 | No key needed |
| SANS ISC DShield | Import | Every 12h | 75 | No key needed |
| CISA KEV | Import | Every 12h | 95 | Official government source |
| NVD + EPSS | Import | Daily 04:00 | 95 | Optional NVD_API_KEY boosts rate limit |
| MITRE ATT&CK | Import | Weekly Sun | 95 | Official MITRE source |
| Sigma Rules (SigmaHQ) | Import | Weekly Mon | — | Writes to PostgreSQL; Windows/Linux/network/cloud |

The **Reliability** column (0–100) is applied as a multiplier to indicator confidence at ingest time. A score of 95 means the source is authoritative; 65 means open community quality. Sigma rules bypass this (no confidence field; stored directly as detection rules).

### Scheduled maintenance jobs

In addition to data connectors, the worker runs:

| Job | Schedule | Description |
|-----|----------|-------------|
| Indicator decay | Daily 03:00 | Reduces confidence on old indicators (−10/30d); revokes at age 90d. Indicators sighted within the last 30 days are exempt. |
| Warning list refresh | Every 24h | Refreshes MISP FP suppression lists (top-1000 domains, CDN ranges, cloud IPs) |

### Enrichment connectors (on-demand)

Triggered when you look up an observable in the UI or via `/api/enrich`:

| Connector | Enriches | API Key Required |
|-----------|----------|-----------------|
| AlienVault OTX | IP, domain, URL, hash | Yes (free) |
| GreyNoise | IP | Optional (free community tier) |
| AbuseIPDB | IP | Yes (free tier) |
| VirusTotal | IP, domain, URL, hash | Yes (paid) |

### Triggering connectors manually

Via the UI: **Connectors → [connector name] → Run Now**

Via the API:
```bash
curl -X POST http://localhost:8000/api/connectors/sigma-rules/trigger \
  -H "Authorization: Bearer <token>"
```

### Adding extra TAXII servers

Add to your `.env`:
```env
TAXII_EXTRA_SERVERS=MyServer|https://taxii.example.com/taxii2/|username|password
```

Multiple servers (comma-separated):
```env
TAXII_EXTRA_SERVERS=Server1|https://taxii1.example.com/|user1|pass1,Server2|https://taxii2.example.com/|user2|pass2
```

---

## 6. API Keys

API keys are set in `.env`. The platform works fully with free sources only — paid keys unlock additional enrichment connectors.

### Free (recommended to set up)

**AlienVault OTX** — [otx.alienvault.com](https://otx.alienvault.com)
- Create a free account and copy your API key from your profile
- Provides access to 8,000+ community threat pulses with IOCs
```env
OTX_API_KEY=your-key-here
```

**NVD API Key** — [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key)
- Free to request, takes ~1 hour to activate
- Without key: 5 requests / 30 seconds. With key: 50 requests / 30 seconds
- Significantly speeds up the initial NVD import (120-day backfill)
```env
NVD_API_KEY=your-key-here
```

**GreyNoise Community** — [greynoise.io](https://greynoise.io)
- Free community tier available after registration
- Classifies IPs as internet background noise vs. targeted threats
```env
GREYNOISE_API_KEY=your-key-here
```

**AbuseIPDB** — [abuseipdb.com](https://www.abuseipdb.com)
- Free tier: 1,000 checks/day
- Community IP abuse reports and confidence scores
```env
ABUSEIPDB_API_KEY=your-key-here
```

### Paid (optional)

| Key | Service | Notes |
|-----|---------|-------|
| `VIRUSTOTAL_API_KEY` | VirusTotal | Enriches IPs, domains, URLs, hashes |
| `SHODAN_API_KEY` | Shodan | Internet-wide scanning data |
| `CENSYS_API_ID` + `CENSYS_API_SECRET` | Censys | Internet asset enumeration |
| `ABUSEIPDB_API_KEY` | AbuseIPDB | Higher limits on paid tier |
| `HIBP_API_KEY` | Have I Been Pwned | Credential exposure checks |
| `HUDSONROCK_API_KEY` | Hudson Rock | Stealer log / credential intel |
| `CRIMINAL_IP_API_KEY` | Criminal IP | IP threat scoring |
| `PULSEDIVE_API_KEY` | Pulsedive | Threat intelligence enrichment |
| `FLARE_API_KEY` | Flare | Dark web monitoring |
| `DARKOWL_API_KEY` | DarkOwl | Dark web dataset |
| `RECORDED_FUTURE_API_KEY` | Recorded Future | Premium threat intelligence |
| `INTEL471_USERNAME` + `INTEL471_API_KEY` | Intel471 | Underground forum intel |

---

## 7. Production Deployment

### Systemd service (auto-start on boot)

Run the included installer script as root:

```bash
sudo bash scripts/install-service.sh
```

This will:
- Install Docker if not present
- Add your user to the `docker` group
- Create `.env` if it doesn't exist
- Install and enable a systemd service that starts CLAWINT on boot

Managing the service:
```bash
sudo systemctl start clawint
sudo systemctl stop clawint
sudo systemctl restart clawint
sudo systemctl status clawint
journalctl -u clawint -f       # Follow logs
```

### Reverse proxy (HTTPS)

For production, put CLAWINT behind nginx or Caddy with TLS. Example Caddy config:

```
clawint.yourdomain.com {
    reverse_proxy /api/* localhost:8000
    reverse_proxy /* localhost:3000
}
```

Update `.env`:
```env
APP_ENV=production
ALLOWED_ORIGINS=https://clawint.yourdomain.com
```

### Firewall

In production, block direct access to infrastructure ports. Only expose what you need:

```bash
# Allow only the frontend and API (if not behind a reverse proxy)
ufw allow 3000/tcp
ufw allow 8000/tcp

# Block direct infrastructure access from the internet
ufw deny 5432/tcp   # PostgreSQL
ufw deny 6379/tcp   # Redis
ufw deny 5672/tcp   # RabbitMQ
ufw deny 9200/tcp   # OpenSearch
ufw deny 9000/tcp   # MinIO
```

If using a reverse proxy, only expose 80/443 externally.

### Data persistence

All data is stored in named Docker volumes:

| Volume | Contents |
|--------|----------|
| `clawint_opensearch_data` | All STIX objects, indicators, dark web records, sightings |
| `clawint_postgres_data` | Cases, users, tasks, RBAC, detection rules |
| `clawint_redis_data` | Session cache |
| `clawint_rabbitmq_data` | Message queue state |
| `clawint_minio_data` | Uploaded files, reports |

Back up these volumes regularly. Example backup:
```bash
# Stop the stack first for a consistent snapshot
docker compose stop

# Export each volume
for vol in opensearch_data postgres_data redis_data rabbitmq_data minio_data; do
  docker run --rm \
    -v clawint_${vol}:/data \
    -v $(pwd)/backups:/backup \
    alpine tar czf /backup/${vol}-$(date +%Y%m%d).tar.gz -C /data .
done

docker compose start
```

---

## 8. Port Reference

| Port | Service | Notes |
|------|---------|-------|
| **3000** | Frontend (React) | Main UI |
| **8000** | Backend API (FastAPI) | REST. Docs at `/api/docs` |
| **9200** | OpenSearch | STIX object store. Not for public access |
| **5601** | OpenSearch Dashboards | Optional raw data explorer |
| **5432** | PostgreSQL | Cases, users, detection rules. Not for public access |
| **6379** | Redis | Cache. Not for public access |
| **5672** | RabbitMQ | Message bus. Not for public access |
| **15672** | RabbitMQ Management | Web UI for queue inspection |
| **9000** | MinIO S3 API | File storage API. Not for public access |
| **9001** | MinIO Console | Web UI for file browser |
| **9050** | Tor SOCKS proxy | Used by leak site scraper connector |
| **8118** | Tor HTTP proxy | Privoxy HTTP proxy over Tor |

---

## 9. Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Frontend  (React/TypeScript)                  │
│  :3000 — Dashboard │ Intel │ ATT&CK │ Rules │ Cases │ Dark Web  │
└─────────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│                        API  (FastAPI)                            │
│   :8000 — REST /api/* │ SSE stream /stream                      │
│   intel │ sightings │ rules │ cases │ alerts │ darkweb          │
└─────────────────────────────────────────────────────────────────┘
         │              │               │               │
         ▼              ▼               ▼               ▼
   ┌──────────┐  ┌──────────┐  ┌──────────────┐  ┌──────────┐
   │OpenSearch│  │PostgreSQL│  │    Redis     │  │  MinIO   │
   │  :9200   │  │  :5432   │  │    :6379     │  │  :9000   │
   │STIX/Dark │  │Cases/Users│  │Cache/Sessions│  │  Files   │
   │web index │  │Rules/RBAC│  │              │  │          │
   └──────────┘  └──────────┘  └──────────────┘  └──────────┘
                                      │
                               ┌──────────┐
                               │ RabbitMQ │
                               │  :5672   │
                               └──────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────┐
│               Worker  (Connector scheduler + enrichment)         │
│   18 import connectors on cron │ daily decay │ warning lists    │
└─────────────────────────────────────────────────────────────────┘
         │              │               │               │
    ┌─────────┐  ┌────────────┐  ┌──────────┐  ┌──────────────┐
    │External │  │ MISP feeds │  │  TAXII   │  │  Tor proxy   │
    │  APIs   │  │  (public)  │  │ servers  │  │  :9050       │
    │OTX/VT/  │  │Botvrij.eu  │  │Anomali   │  │Leak site     │
    │abuse.ch │  │abuse.ch    │  │Limo+more │  │scraping      │
    └─────────┘  └────────────┘  └──────────┘  └──────────────┘
```

### Data flow

1. **Import connectors** fetch from external sources → convert to STIX 2.1 → TLP normalized + source reliability applied → POST to `/api/intel/bulk` → stored in OpenSearch with deterministic dedup
2. **Sigma connector** fetches from SigmaHQ GitHub → parses YAML → writes directly to PostgreSQL `detection_rules` table
3. **Dark web connectors** (ransomwatch, ransomware.live, leaksites) write directly to the `clawint-darkweb` OpenSearch index
4. **Enrichment connectors** are called on-demand when an analyst queries an observable
5. **Sightings** are stored as STIX `sighting` objects in OpenSearch; sighted indicators are flagged as decay-exempt
6. **Frontend** reads all data via the REST API

---

## 10. Upgrading

```bash
git pull origin main

# Rebuild images with new code
docker compose up -d --build

# Check logs for migration errors
docker compose logs -f api
```

Database migrations run automatically on startup via SQLAlchemy.

> After upgrading, trigger the Sigma Rules connector manually if you want the latest rules immediately rather than waiting for the weekly schedule.

---

## 11. Troubleshooting

### OpenSearch won't start

**Symptom:** `opensearch` container exits immediately or stays unhealthy.

**Fix:** Set the kernel memory map limit:
```bash
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

### API won't start / "Cannot connect to postgres"

**Symptom:** API container crashes with database connection errors.

**Cause:** PostgreSQL healthcheck hasn't passed yet.

**Fix:** Wait 30–60 seconds and try again. The `depends_on` with `condition: service_healthy` should handle this automatically. If it persists:
```bash
docker compose logs postgres
docker compose restart api
```

### Connectors not ingesting data

**Check 1:** Is the worker running?
```bash
docker compose ps worker
docker compose logs worker --tail 50
```

**Check 2:** Trigger a connector manually and check its output:
```bash
curl -X POST http://localhost:8000/api/connectors/urlhaus/trigger \
  -H "Authorization: Bearer <token>"

# Then watch worker logs
docker compose logs -f worker
```

**Check 3:** Verify OpenSearch is healthy:
```bash
curl http://localhost:9200/_cluster/health
```

### Rules page is empty

The Sigma rules connector runs weekly (Monday 05:00). Trigger it manually to populate immediately:
```bash
curl -X POST http://localhost:8000/api/connectors/sigma-rules/trigger \
  -H "Authorization: Bearer <token>"
```

Watch progress in worker logs — 500+ rules import in ~2 minutes.

### Tor-based connectors failing

The leak site scraper connects via Tor. The `tor` container needs a few minutes on first start to establish a circuit.

```bash
docker compose logs tor
```

If it shows repeated failures, the Tor network may be blocked from your network. Disable the leaksites connector in `scheduler.py` or use a different Tor exit configuration.

### TLP filter returning 0 results

New TLP fields are applied to indicators ingested after the feature was enabled. Re-trigger any import connectors to backfill TLP on recent data:
```bash
curl -X POST http://localhost:8000/api/connectors/urlhaus/trigger \
  -H "Authorization: Bearer <token>"
```

### Out of disk space

OpenSearch data grows continuously. Monitor usage:
```bash
docker system df
df -h /var/lib/docker
```

Add index lifecycle management or periodically prune old indicators by modifying the OpenSearch index settings.

### Resetting to a clean state

> **Warning:** This deletes all ingested data.

```bash
docker compose down -v   # Removes all volumes
docker compose up -d --build
```

---

## Connector SDK

To build a custom connector, see the base class at `backend/app/connectors/sdk/base.py`.

Minimal example:

```python
from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult

class MyConnector(BaseConnector):
    def __init__(self):
        super().__init__(ConnectorConfig(
            name="my-connector",
            display_name="My Connector",
            connector_type="import_external",
            description="Fetches IOCs from my source.",
            schedule="0 */6 * * *",
            source_reliability=75,   # 0-100, applied to indicator confidence
            default_tlp="TLP:CLEAR", # default TLP for objects from this connector
        ))

    async def run(self) -> IngestResult:
        result = IngestResult()
        resp = await self.http.get("https://my-source.example.com/feed.json")
        objects = self._parse(resp.json())
        r = await self.push_to_platform(objects)
        result.objects_created += r.objects_created
        return result
```

Register it in `backend/app/workers/scheduler.py` by adding it to the `CONNECTORS` list.

---

## Security Notes

- Change all default passwords in `.env` before deploying
- `SECRET_KEY` and `CONNECTOR_API_KEY` must be strong random strings — generate with `python3 -c "import secrets; print(secrets.token_hex(32))"`
- In production, place the platform behind a reverse proxy with TLS
- Block direct access to infrastructure ports (PostgreSQL, Redis, OpenSearch, RabbitMQ, MinIO) from the internet
- The `.env` file contains secrets — never commit it to version control
- OpenSearch security plugin is disabled by default for ease of deployment — enable it for production multi-tenant environments
