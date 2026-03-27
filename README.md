# CLAWINT

**Unified, self-hosted Cyber Threat Intelligence platform.**

CLAWINT combines indicator management, dark web tracking, case management, enrichment, detection rule management, and a connector framework into a single Docker Compose deployment — replacing OpenCTI + MISP + TheHive + Cortex.

---

## Features

- **STIX 2.1 native** — all threat objects stored and exchanged as STIX 2.1
- **20 built-in connectors** — abuse.ch, OTX, MISP feeds, TAXII, CISA KEV, NVD, MITRE ATT&CK, ransomware trackers, and more
- **Dark web as first-class** — Tor-based ransomware leak site scraping, victim tracking, IAB listings, credential exposures, stealer logs
- **IOC deduplication** — deterministic indicator IDs (UUID5 of type:value) prevent duplicates across 20 sources
- **FP suppression** — MISP warning lists filter top-1000 domains, CDN ranges, cloud IPs before storage
- **Indicator decay** — confidence auto-reduces over time; revokes aged IoCs after 90 days
- **Enrichment engine** — parallel on-demand enrichment for IPs, domains, URLs, and file hashes with risk scoring
- **Detection rules** — YARA, Sigma, Snort, Suricata, and STIX Pattern storage with MITRE technique linkage
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
| MITRE ATT&CK | github.com/mitre/cti | Weekly | Free, official |

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
git clone https://github.com/diagonalciso/Clawint.git
cd Clawint

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
| `/intel` | STIX object browser — all types, full-text search |
| `/intel/:id` | Object detail — core fields, extended attrs, relationships table + graph |
| `/attack` | MITRE ATT&CK matrix heatmap with technique coverage |
| `/rules` | Detection rule management (YARA / Sigma / Snort / Suricata / STIX Pattern) |
| `/cases` | Incident response case management with tasks and observables |
| `/darkweb` | Ransomware victims, credentials, IAB listings, stealer logs |
| `/connectors` | Connector status and manual trigger |

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
| Indicator decay | Daily 03:00 | Reduces confidence on old IoCs, revokes at age 90d |
| Warning list refresh | Every 24h | Refreshes FP suppression lists from MISP warninglists |

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
cd /path/to/clawint
pip install -r backend/requirements.txt
python validate_connectors.py
```

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
