# SOCint Administration Manual

**This manual teaches administrators how to deploy, run, and maintain SOCint.**

SOCint is a **threat intelligence platform**. Think of it as a smart filing cabinet that collects security threat data from the internet (hacker forums, vulnerability databases, ransomware gang websites, leaked credentials, etc.) and makes it searchable and actionable for your security team.

Unlike Wazuh (which watches YOUR network), SOCint watches the EXTERNAL threat landscape.

**Before you start:** You need Docker, Docker Compose, and about 16 GB of RAM (minimum 8 GB). SOCint is not lightweight — it runs a full search engine (OpenSearch) and database (PostgreSQL) alongside the application.

---

## What You're About to Do

By the end, you will have:
1. ✅ Docker and all prerequisites installed
2. ✅ SOCint running in Docker Compose
3. ✅ 22 threat feeds automatically importing data
4. ✅ Web interface available at `http://localhost:3000`
5. ✅ Database backups configured
6. ✅ Troubleshooting knowledge for common problems

**Time required:** 45 minutes for initial deployment. Another 30 minutes for backups and tuning.

**Hardware required:**
- **CPU:** 4 cores minimum (8 recommended)
- **RAM:** 8 GB minimum (16 GB recommended) — OpenSearch is memory-hungry
- **Disk:** 50 GB minimum (100 GB recommended) — threat data accumulates quickly
- **Network:** Internet connection (feeds are pulled from external sources)

---

## Part 1: Prerequisites

### Check Your Docker Installation

```bash
docker --version          # Should be 20.10+
docker compose version    # Should be 2.0+
```

If you don't have Docker:

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install docker.io docker-compose
sudo usermod -aG docker $USER
newgrp docker             # Apply group without relogin
```

**RHEL/CentOS:**
```bash
sudo yum install docker docker-compose
sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker $USER
newgrp docker
```

### Set OpenSearch Memory Limit

OpenSearch (the search engine) needs extra system memory allocation:

```bash
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

This is only needed once per system. If you skip it, Docker Compose will fail with cryptic OpenSearch errors.

### Check Available Resources

```bash
free -h                    # Shows RAM available
df -h /                    # Shows disk space
nproc                      # Shows CPU cores
```

**Minimum to proceed:**
- RAM: at least 8 GB free
- Disk: at least 50 GB free
- CPU: at least 4 cores

If you have less, SOCint will run but very slowly.

---

## Part 2: Installation

### Step 1: Get SOCint Code

Clone the repository:

```bash
cd ~/claude
git clone https://github.com/diagonalciso/SOCint.git socint
cd socint
```

Or if already cloned:
```bash
cd ~/claude/socint
```

### Step 2: Create Configuration

SOCint needs a `.env` file with secrets and settings:

```bash
cp .env.example .env
chmod 600 .env
nano .env                 # Edit it
```

**Essential variables to set:**

```env
# This is the admin password for the web UI
SEED_ADMIN_PASSWORD=YourVeryStrongPassword123!

# Generate random secrets (copy output into these two)
SECRET_KEY=<generate with: python3 -c "import secrets; print(secrets.token_hex(32))">
CONNECTOR_API_KEY=<generate with: python3 -c "import secrets; print(secrets.token_hex(32))">

# These are optional but recommended
OTX_API_KEY=               # Free from otx.alienvault.com
NVD_API_KEY=               # Free from nvd.nist.gov
VIRUSTOTAL_API_KEY=        # Paid from virustotal.com (optional)
```

**Generate the secrets:**

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

This gives you a random string. Copy it and paste into `.env` for `SECRET_KEY` and `CONNECTOR_API_KEY`.

### Step 3: Start SOCint

```bash
docker compose up -d --build
```

**What this does:**
- `-d` = run in background
- `--build` = build Docker images (only needed first time)

**First startup takes 3-5 minutes.** The system is initializing:
- PostgreSQL database
- OpenSearch search engine
- Python application

### Step 4: Verify It's Running

```bash
docker compose logs -f app
```

Wait for lines like:
```
app_1 | [INFO] SOCint running on http://0.0.0.0:8000
app_1 | [INFO] Connectors scheduler started
```

Press `Ctrl+C` to exit logs.

### Step 5: Access the Web UI

Open your browser:
```
http://localhost:3000
```

**Login with:**
- Username: `admin`
- Password: whatever you put in `SEED_ADMIN_PASSWORD`

If you see the threat intelligence dashboard, you're done with installation! 🎉

---

## Part 3: Understanding What's Running

### The Services

SOCint runs 4 Docker containers:

| Container | What It Does | Purpose |
|-----------|------------|---------|
| **app** | Python FastAPI server | Handles web requests, API, UI |
| **postgres** | SQL database | Stores case data, user info, rule metadata |
| **opensearch** | Search engine | Stores all threat indicators (IPs, domains, hashes, etc.) |
| **redis** | Cache server | Speeds up repeated queries |

**Each runs in its own isolated container.** If one crashes, Docker automatically restarts it.

### The 22 Threat Feeds

SOCint automatically pulls threat data from 22 sources on a schedule:

| Feed | What It Is | Updates Every | Cost |
|------|-----------|---|------|
| AlienVault OTX | Crowdsourced threat data | 2 hours | Free |
| MISP Public | Community threat data | 4 hours | Free |
| CISA KEV | US govt vulnerability data | 12 hours | Free |
| NVD | National Vulnerability Database | Daily | Free |
| URLhaus | Malicious URLs | 30 min | Free |
| Ransomware.live | Ransomware gang activity | 2 hours | Free |
| Tor scraper | Dark web ransomware sites | 3 hours | Free |
| And 15 more... | | | All free |

**You don't have to do anything.** The connectors run automatically on a schedule, fetching fresh threat data every 2-12 hours.

---

## Part 4: Configuration & Tuning

### Basic Settings (.env)

```env
# Web interface port
SOCINT_PORT=3000

# How often to run connector schedules
CONNECTOR_POLL_INTERVAL=300           # seconds (5 minutes)

# How far back to fetch on first run
INITIAL_WINDOW=now-30d                # Try: now-1y for full history

# Optional API keys (leave empty if not available)
OTX_API_KEY=abc123def456
NVD_API_KEY=xyz789
VIRUSTOTAL_API_KEY=
```

### Connector Configuration

Advanced: in `backend/app/config.py`, you can tune individual connectors:

```python
# Example: disable a slow connector
CONNECTORS_DISABLED = ["ransomware_tracker", "darkweb_scraper"]

# Example: change fetch schedule
CONNECTOR_SCHEDULES = {
    "otx": "0 */2 * * *",              # Every 2 hours
    "nvd": "0 4 * * *",                # Daily at 4 AM
}
```

**Most users don't need to edit this.** Defaults are well-tuned.

### Database Tuning

To improve query performance, tune PostgreSQL:

```bash
# Edit docker-compose.yml
# In the postgres service, add environment variables:
environment:
  POSTGRES_INITDB_ARGS: "-c shared_buffers=2GB -c effective_cache_size=4GB"
```

Then rebuild:
```bash
docker compose down
docker compose up -d --build
```

---

## Part 5: Monitoring

### Check Service Health

```bash
# All containers running?
docker compose ps

# Expected output: 4 containers, all "Up"
```

### View Logs

```bash
# App logs (most useful)
docker compose logs -f app

# Database logs (if debugging SQL)
docker compose logs -f postgres

# Search engine logs (if debugging queries)
docker compose logs -f opensearch

# All logs together
docker compose logs -f
```

Press `Ctrl+C` to stop viewing.

### Monitor Disk Usage

```bash
# How much data has SOCint stored?
du -sh <docker-volume-path>

# Typical growth:
# After 1 week:   2-5 GB
# After 1 month:  8-15 GB
# After 1 year:   60-100 GB
```

The search engine stores all threat indicators. Data grows as feeds import new threats.

### Check Connector Status

**In the web UI:**
1. Go to **Settings** → **Connectors**
2. See each connector's last run time and status
3. If a connector says "ERROR", check the logs

---

## Part 6: Backups

### What to Backup

Two things matter:
1. **PostgreSQL database** — case data, user accounts, rules
2. **OpenSearch indices** — all threat indicators

Everything else can be regenerated.

### Backup Strategy

**Daily PostgreSQL backup:**

```bash
# Create backup directory
mkdir -p ~/backups

# Backup command
docker compose exec -T postgres pg_dump -U postgres socint > ~/backups/socint-$(date +%Y%m%d).sql

# Restore (if database is corrupted)
docker compose exec -T postgres psql -U postgres -d socint < ~/backups/socint-20260419.sql
```

**Automated backup (cron):**

```bash
crontab -e

# Add this line:
# 2 * * * * docker compose -f ~/claude/socint/docker-compose.yml exec -T postgres pg_dump -U postgres socint > ~/backups/socint-$(date +\%Y\%m\%d).sql
```

### Backup OpenSearch Indices

```bash
# List all indices
curl -s http://localhost:9200/_cat/indices

# Backup all indices
curl -X PUT http://localhost:9200/_snapshot/backup -H 'Content-Type: application/json' -d '{"type": "fs", "settings": {"location": "/backups/opensearch"}}'

# Create snapshot
curl -X PUT "http://localhost:9200/_snapshot/backup/backup-$(date +%Y%m%d)?wait_for_completion=true"
```

---

## Part 7: Managing Threat Data

### Data Retention

By default, SOCint keeps all indicators forever. To manage size, set retention:

**In backend/app/config.py:**

```python
# Delete indicators not sighted in 180 days
INDICATOR_RETENTION_DAYS = 180

# Delete cases closed > 90 days ago
CASE_RETENTION_DAYS = 90
```

Then restart:
```bash
docker compose restart app
```

### Indicator Decay

SOCint automatically reduces confidence on old indicators. An indicator seen 6 months ago gets lower priority than one seen yesterday.

This happens automatically — no configuration needed.

### Disable Noisy Feeds

Some feeds produce false positives. Disable them in the web UI:

**In UI: Settings → Connectors → [Connector Name] → Disable**

Or in `.env`:
```env
DISABLED_CONNECTORS=["misp", "urlhaus"]
```

---

## Part 8: Troubleshooting

### Docker Won't Start

**Error:** `"permission denied"`

**Fix:**
```bash
sudo usermod -aG docker $USER
newgrp docker
docker ps            # Should work now
```

### OpenSearch Won't Start

**Error:** `"vm.max_map_count must be 262144"`

**Fix:**
```bash
sudo sysctl -w vm.max_map_count=262144
docker compose restart opensearch
```

### Out of Memory

**Symptom:** App crashes, containers restart frequently

**Fix:**
- Close other applications
- Reduce Docker memory limits in `docker-compose.yml`
- Or increase server RAM

**Check memory:**
```bash
docker stats                # Shows memory per container
free -h                     # Shows system memory
```

### Connector Failures

**In web UI, connector shows "ERROR"**

**Common causes:**
1. Internet connection down
2. Feed server is down (wait, usually resolves in hours)
3. Rate limit exceeded (daily quota hit, resets tomorrow)
4. Invalid API key (check `.env`)

**To retry:**
- Check logs: `docker compose logs -f app | grep connector`
- Wait 1 hour (scheduler will retry)
- Or manually restart: `docker compose restart app`

### Database Connection Failed

**Error:** `"psycopg2.OperationalError: could not connect to server"`

**Cause:** PostgreSQL not ready yet (usually on first startup)

**Fix:**
```bash
docker compose logs postgres    # Wait for "ready to accept connections"
docker compose restart app
```

### Search Engine Not Responding

**Error:** `"Elasticsearch server is unreachable"`

**Cause:** OpenSearch not initialized (takes 2-3 min on startup)

**Fix:**
```bash
docker compose logs opensearch  # Wait for startup to finish
docker compose restart opensearch
```

---

## Part 9: Security

### Limit Web Access

By default, port 3000 is open to anyone on your network.

**Option 1: Firewall**
```bash
sudo ufw allow from 10.0.0.0/24 to any port 3000
sudo ufw deny 3000
```

**Option 2: Reverse Proxy (nginx)**

```bash
sudo apt install nginx
sudo nano /etc/nginx/sites-enabled/socint
```

Paste:
```nginx
upstream socint {
    server 127.0.0.1:3000;
}

server {
    listen 443 ssl http2;
    server_name your.domain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    auth_basic "SOCint";
    auth_basic_user_file /etc/nginx/.htpasswd;
    
    location / {
        proxy_pass http://socint;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

Then:
```bash
sudo systemctl restart nginx
```

### Change Admin Password

**In web UI:**
1. Log in as admin
2. Settings → Profile → Change Password

**Or via PostgreSQL:**
```bash
docker compose exec postgres psql -U postgres -d socint -c "UPDATE users SET password_hash='...' WHERE username='admin';"
```

### Protect Secrets

```bash
# .env file should be readable only by you
chmod 600 .env

# Don't commit to git
echo ".env" >> .gitignore
echo "*.sql" >> .gitignore
echo "docker-compose.override.yml" >> .gitignore
```

---

## Part 10: Upgrades

### Check for Updates

```bash
cd ~/claude/socint
git status                 # Shows if repo has changes
git log --oneline -5       # Shows recent commits
```

### Update to Latest Version

```bash
docker compose down

# Backup first!
docker compose exec postgres pg_dump -U postgres socint > backup-pre-upgrade.sql

# Pull new code
git pull origin main

# Update environment if needed
diff .env.example .env    # Check for new variables

# Rebuild and restart
docker compose up -d --build
```

---

## Part 11: Maintenance Schedule

### Daily
- Monitor logs: `docker compose logs app | grep error`
- Check connector status in web UI

### Weekly
- Disk usage: `du -sh <volume-path>`
- Any unresolved errors in logs?

### Monthly
- Review data retention settings
- Check if any feeds are consistently failing (disable them)
- Clean old cases (Settings → Cleanup)

### Quarterly
- Full backup verification (test restore)
- Update Docker images: `docker compose pull && docker compose up -d`

### Annually
- Rotate API keys (OTX, NVD, VirusTotal)
- Review access logs for unauthorized attempts

---

## Part 12: Common Tasks

### Add a Custom Feed

**TAXII 2.1 feed:**

In `backend/app/connectors/custom.py`:
```python
class CustomTAXIIConnector(BaseConnector):
    def __init__(self):
        super().__init__(ConnectorConfig(
            name="custom-taxii",
            display_name="My TAXII Feed",
            schedule="0 */6 * * *",  # Every 6 hours
        ))
    
    async def run(self):
        # Fetch from TAXII server
        # Parse STIX 2.1 objects
        # Call self.push_to_platform(stix_objects)
```

### Import Local Data

Upload a STIX 2.1 JSON file:

**In web UI: Intel → Import → Choose file**

Or via API:
```bash
curl -X POST "http://localhost:8000/api/intel/import" \
  -H "Authorization: Bearer $(cat .env | grep API_KEY)" \
  -F "file=@threat_data.json"
```

### Export Indicators for SIEM

**In UI: Intel → Export → Choose format**

Options: STIX 2.1, CSV, JSON, YARA rules, Snort/Suricata rules

---

**You're now an SOCint administrator.** The system is designed to run itself — feeds import automatically, old data decays automatically, and backups just need a cron job.

Questions? Check the logs first: `docker compose logs -f app`. They usually tell you exactly what's wrong.
