# SOCINT

**Unified, self-hosted Cyber Threat Intelligence platform.**

SOCINT combines indicator management, dark web tracking, case management, enrichment, detection rule management, and a connector framework into a single Docker Compose deployment — replacing OpenCTI + MISP + TheHive + Cortex.

---

## Features

- **STIX 2.1 native** — all threat objects stored and exchanged as STIX 2.1
- **22 built-in connectors** — abuse.ch, OTX, MISP feeds, TAXII, CISA KEV, NVD, MITRE ATT&CK, Sigma rules, ransomware trackers, and more
- **Dark web as first-class** — Tor-based ransomware leak site scraping, victim tracking, IAB listings, credential exposures, stealer logs
- **IOC deduplication** — deterministic indicator IDs (UUID5 of type:value) prevent duplicates across all import sources
- **FP suppression** — MISP warning lists filter top-1000 domains, CDN ranges, cloud IPs before storage
- **TLP marking** — every STIX object carries a canonical TLP field (CLEAR/GREEN/AMBER/AMBER+STRICT/RED); filterable in the Intel browser
- **Source trust scoring** — per-connector reliability weight (0–100) applied to indicator confidence at ingest; CISA KEV = 95, OTX community = 65
- **Indicator decay** — confidence auto-reduces over time; revokes aged IoCs after 90 days; sighted indicators are exempt from decay
- **Sightings** — record when an indicator is observed in your environment; updates decay exemption and running sighting count
- **Enrichment engine** — parallel on-demand enrichment for IPs, domains, URLs, and file hashes with risk scoring
- **Detection rules** — 500+ Sigma rules imported automatically; YARA, Snort, Suricata, and STIX Pattern storage with MITRE technique linkage
- **MITRE ATT&CK heatmap** — interactive matrix showing coverage against your knowledge base
- **Knowledge graph** — Cytoscape.js relationship graph on every STIX object
- **Case management** — TheHive-inspired case/task/observable/alert workflow
- **NVD + EPSS** — full CVE database with CVSS v3 scores and exploitation probability
- **API-first** — every feature accessible via REST (GraphQL schema ready)
- **Self-hostable** — single `docker compose up` to run the full stack

---

## Built-in Connectors

### Import (automated, scheduled)

| Connector | Source | Schedule | Notes |
|-----------|--------|----------|-------|
| AlienVault OTX | otx.alienvault.com | Every 2h | Requires free API key |
| MISP Public Feeds | Botvrij.eu + abuse.ch | Every 4h | Free |
| TAXII 2.1 | Anomali Limo (free) | Every 6h | Free, guest/guest |
| Ransomwatch | joshhighet/ransomwatch | Every 2h | Free, archived feed |
| Ransomware.live | api.ransomware.live/v2 | Every 2h | Free, victims + group profiles |
| RansomLook | ransomlook.io | Every 3h | Free CC BY 4.0 |
| DeepDarkCTI | fastfire/deepdarkCTI | Daily 06:00 | 200+ groups + onion URLs |
| Ransomware Leak Sites | Tor scraper | Every 3h | Requires Tor proxy |
| URLhaus | abuse.ch | Every 30min | Free |
| ThreatFox | abuse.ch | Every 4h | Free |
| Feodo Tracker | abuse.ch | Every 6h | Free |
| Spamhaus DROP/EDROP | spamhaus.org | Every 12h | Free |
| OpenPhish | openphish.com | Every 12h | Free |
| SANS ISC DShield | isc.sans.edu | Every 12h | Free |
| CISA KEV | cisa.gov | Every 12h | Free, official |
| NVD + EPSS | nvd.nist.gov + first.org | Daily 04:00 | Free; optional NVD_API_KEY |
| MITRE ATT&CK | github.com/mitre/cti | Weekly Sun | Free, official |
| Sigma Rules | SigmaHQ/sigma on GitHub | Weekly Mon | Free; Windows/Linux/network/cloud |

### Enrichment (on-demand)

| Connector | Enriches | Key Required |
|-----------|----------|--------------|
| AlienVault OTX | IP, domain, URL, hash | Free |
| GreyNoise | IP | Free community tier |
| AbuseIPDB | IP | Free tier |
| VirusTotal | IP, domain, URL, hash | Paid |

---

## Quick Start

```bash
git clone https://github.com/diagonalciso/SOCint.git
cd SOCint

cp .env.example .env

# Generate secret keys
SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
CONNECTOR_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
sed -i "s/change-me-to-a-long-random-string/$SECRET/" .env
sed -i "s/change-me-connector-key/$CONNECTOR_KEY/" .env

# Set your admin password
sed -i "s/changeme123!/YourStrongPassword!/" .env

docker compose up -d --build
```

Open **http://localhost:3000**

> First startup takes 2–3 minutes while OpenSearch and PostgreSQL initialize.

### OS requirement (OpenSearch)

```bash
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

---

## Requirements

| | Minimum | Recommended |
|-|---------|-------------|
| CPU | 4 cores | 8 cores |
| RAM | 8 GB | 16 GB |
| Disk | 50 GB | 200 GB |
| Docker | 24.0+ | latest |

---

## Stack

| Layer | Technology |
|-------|-----------|
| Backend API | Python / FastAPI |
| Frontend | React 18 + TypeScript |
| STIX object store | OpenSearch 2.x |
| Relational DB | PostgreSQL 16 |
| Cache / pub-sub | Redis 7 |
| Message bus | RabbitMQ 3.13 |
| File storage | MinIO (S3-compatible) |
| Graph visualization | Cytoscape.js 3.x |
| Dark web access | Tor proxy |
| Scheduler | APScheduler (cron) |

---

## Pages

| URL | Description |
|-----|-------------|
| `/dashboard` | KPI cards, top ransomware groups, intel by source, recent alerts |
| `/intel` | STIX object browser — full-text search, TLP filter, type filter |
| `/intel/:id` | Object detail — core fields, TLP badge, sighting count, Report Sighting button, relationship graph |
| `/attack` | MITRE ATT&CK matrix heatmap with technique coverage |
| `/rules` | Detection rule management — 500+ Sigma rules auto-imported; YARA / Snort / Suricata / STIX Pattern |
| `/cases` | Incident response case management with tasks and observables |
| `/darkweb` | Ransomware victims, credentials, IAB listings, stealer logs |
| `/connectors` | Connector status, reliability scores, and manual trigger |

---

## Ports

| Port | Service |
|------|---------|
| 3000 | Frontend |
| 8000 | API (docs at `/api/docs`) |
| 9200 | OpenSearch |
| 5601 | OpenSearch Dashboards |
| 15672 | RabbitMQ management |
| 9001 | MinIO console |

---

## API Keys

All sources work without API keys. Optional keys unlock additional coverage or higher rate limits:

| Key | Source | Benefit |
|-----|--------|---------|
| `OTX_API_KEY` | [otx.alienvault.com](https://otx.alienvault.com) | Required for OTX import |
| `NVD_API_KEY` | [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key) | Boosts NVD rate limit 10× |
| `GREYNOISE_API_KEY` | [greynoise.io](https://greynoise.io) | Higher enrichment quota |
| `ABUSEIPDB_API_KEY` | [abuseipdb.com](https://www.abuseipdb.com) | IP reputation enrichment |
| `VIRUSTOTAL_API_KEY` | [virustotal.com](https://www.virustotal.com) | Multi-AV enrichment |

Set in `.env` — see `.env.example` for all options.

---

## Scheduled Jobs

In addition to connectors, the worker runs:

| Job | Schedule | Description |
|-----|----------|-------------|
| Indicator decay | Daily 03:00 | Reduces confidence on old IoCs, revokes at age 90d; indicators sighted within 30 days are exempt |
| Warning list refresh | Every 24h | Refreshes FP suppression lists from MISP warninglists |

---

## Sightings

Record when an indicator is observed in your environment from the indicator detail page (`/intel/:id`) or via the API:

```bash
curl -X POST http://localhost:8000/api/sightings \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "sighting_of_ref": "indicator--...",
    "count": 1,
    "source": "siem",
    "note": "Seen in firewall logs"
  }'
```

Sighted indicators are stored as STIX `sighting` objects and exempt from confidence decay for 30 days.

---

## TLP Filtering

Every STIX object has a canonical `tlp` field set at ingest. Filter by TLP in the Intel browser dropdown or via the API:

```bash
# All TLP:AMBER indicators
curl "http://localhost:8000/api/intel/objects?type=indicator&tlp=TLP:AMBER"

# Filter by source
curl "http://localhost:8000/api/intel/objects?source=cisa-kev"
```

---

## Source Trust Scoring

Each connector has a reliability score (0–100) applied to indicator confidence at ingest:

| Score | Connectors |
|-------|-----------|
| 95 | CISA KEV, NVD, MITRE ATT&CK |
| 85 | Spamhaus |
| 80 | Feodo Tracker, Ransomware.live, RansomLook |
| 75 | URLhaus, ThreatFox, DShield |
| 70–72 | MISP Feeds, TAXII |
| 65–68 | AlienVault OTX, OpenPhish |

An OTX indicator with raw confidence 60 from a connector with reliability 65 is stored with confidence `60 × 65/100 = 39`.

---

## Custom Connectors

```python
from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult

class MyConnector(BaseConnector):
    def __init__(self):
        super().__init__(ConnectorConfig(
            name="my-connector",
            display_name="My Source",
            connector_type="import_external",
            schedule="0 */6 * * *",
            source_reliability=75,   # 0-100, applied to indicator confidence
            default_tlp="TLP:CLEAR", # default TLP for all objects from this connector
        ))

    async def run(self) -> IngestResult:
        result = IngestResult()
        resp = await self.http.get("https://my-source.example.com/feed.json")
        r = await self.push_to_platform(self._parse(resp.json()))
        result.objects_created += r.objects_created
        return result
```

Register it in `backend/app/workers/scheduler.py`.

---

## Validate Connectors

Test all connectors against live sources without needing the full stack:

```bash
cd /path/to/socint
pip install -r backend/requirements.txt
python validate_connectors.py
```

> The Sigma rules connector requires a live PostgreSQL connection and is tested via `docker compose` only.

---

## Production

For production deployment with systemd auto-start:

```bash
sudo bash scripts/install-service.sh
```

See [INSTALL.md](INSTALL.md) for reverse proxy setup, firewall config, and volume backups.

---

## License

MIT
