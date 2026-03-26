# CLAWINT

**Unified, self-hosted Cyber Threat Intelligence platform.**

CLAWINT combines indicator management, dark web tracking, case management, enrichment, and a connector framework into a single Docker Compose deployment — replacing the need to run OpenCTI + MISP + TheHive + Cortex separately.

---

## Features

- **STIX 2.1 native** — all threat objects stored and exchanged as STIX 2.1
- **14 built-in connectors** — ingests from abuse.ch, OTX, MISP feeds, TAXII, CISA, MITRE ATT&CK, ransomware trackers, and more
- **Dark web as a first-class citizen** — ransomware leak site scraping via Tor, victim tracking, ransomware group intelligence
- **Enrichment engine** — on-demand enrichment for IPs, domains, URLs, and file hashes
- **Case management** — TheHive-inspired case/task/observable workflow
- **Knowledge graph** — relationship visualization with Cytoscape.js
- **API-first** — every feature accessible via REST and GraphQL
- **Self-hostable** — single `docker compose up` to run the full stack

---

## Built-in Connectors

### Import (automated, scheduled)

| Connector | Source | Schedule |
|-----------|--------|----------|
| AlienVault OTX | otx.alienvault.com | Every 2h |
| MISP Public Feeds | Botvrij.eu + abuse.ch | Every 4h |
| TAXII 2.1 | Anomali Limo (free) | Every 6h |
| Ransomwatch | joshhighet/ransomwatch | Every 2h |
| Ransomware.live | ransomware.live API | Every 2h |
| Ransomware Leak Sites | Tor scraper (11 groups) | Every 3h |
| URLhaus | abuse.ch | Every 30min |
| ThreatFox | abuse.ch | Every 4h |
| Feodo Tracker | abuse.ch | Every 6h |
| Spamhaus DROP/EDROP | spamhaus.org | Every 12h |
| OpenPhish | openphish.com | Every 12h |
| SANS ISC DShield | isc.sans.edu | Every 12h |
| CISA KEV | cisa.gov | Every 12h |
| MITRE ATT&CK | Enterprise + ICS | Weekly |

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
| GraphQL | Strawberry |
| Frontend | React + TypeScript |
| STIX object store | OpenSearch |
| Relational DB | PostgreSQL |
| Cache | Redis |
| Message bus | RabbitMQ |
| File storage | MinIO (S3-compatible) |
| Graph visualization | Cytoscape.js |
| Dark web access | Tor proxy |

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

The platform works fully with free sources. Optional keys unlock additional enrichment:

- **AlienVault OTX** — free at [otx.alienvault.com](https://otx.alienvault.com)
- **GreyNoise** — free community tier at [greynoise.io](https://greynoise.io)
- **AbuseIPDB** — free tier at [abuseipdb.com](https://www.abuseipdb.com)
- **VirusTotal**, **Shodan**, **Censys**, and more — see [INSTALL.md](INSTALL.md)

Set keys in `.env` — see `.env.example` for all available options.

---

## Custom Connectors

Extend CLAWINT with your own data sources by subclassing `BaseConnector`:

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

## Production

For production deployment with systemd auto-start:

```bash
sudo bash scripts/install-service.sh
```

See [INSTALL.md](INSTALL.md) for full instructions including reverse proxy setup, firewall configuration, and volume backups.

---

## License

MIT
