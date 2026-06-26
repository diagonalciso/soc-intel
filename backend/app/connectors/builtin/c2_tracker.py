"""
C2 Tracker connector — import.
Ingests live botnet C2 infrastructure from abuse.ch SSLBL feeds:
  - SSL Certificate Blacklist (SHA1 + malware family attribution)
  - Botnet C2 IP Blacklist (aggressive, IPs + ports)

Original source (montysecurity/C2-Tracker) dropped static data files in 2025.
SSLBL is the authoritative replacement — same threat class, better family coverage.
Free, no API key required.
https://sslbl.abuse.ch/
"""
import re
from datetime import datetime, timezone

from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult

_CERT_URL = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"
_IP_URL   = "https://sslbl.abuse.ch/blacklist/sslipblacklist_aggressive.csv"


class C2TrackerConnector(BaseConnector):
    def __init__(self):
        super().__init__(ConnectorConfig(
            name="c2-tracker",
            display_name="C2 Tracker (abuse.ch SSLBL)",
            connector_type="import_external",
            description=(
                "Botnet C2 SSL certificates and IP addresses from abuse.ch SSLBL. "
                "Covers Cobalt Strike, Metasploit, Vidar, RedLine, and 100+ C2 families."
            ),
            schedule="0 */3 * * *",
            source_reliability=85,
        ))

    async def run(self) -> IngestResult:
        self.logger.info("C2 Tracker: fetching SSLBL C2 feeds...")
        result = IngestResult()
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        cert_result = await self._ingest_certs(now)
        ip_result   = await self._ingest_ips(now)

        result.objects_created = cert_result.objects_created + ip_result.objects_created
        result.errors = cert_result.errors + ip_result.errors
        self.logger.info(f"C2 Tracker: ingested {result.objects_created} C2 indicators total")
        return result

    async def _ingest_certs(self, now: str) -> IngestResult:
        result = IngestResult()
        try:
            resp = await self.http.get(_CERT_URL, headers={"User-Agent": "SOCINT/1.0 CTI Platform (research)"})
            resp.raise_for_status()
        except Exception as e:
            self.logger.warning(f"C2 Tracker: cert feed fetch failed: {e}")
            result.errors += 1
            return result

        stix_objects = []
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",", 2)
            if len(parts) < 3:
                continue
            _, sha1, reason = parts
            sha1 = sha1.strip()
            family = reason.strip().replace(" C&C", "").replace(" C2", "").strip()
            if not sha1 or len(sha1) != 40:
                continue

            indicator = {
                "type": "indicator",
                "name": f"C2 SSL: {sha1[:16]}... ({family})",
                "description": f"SSLBL — {family} C2 SSL certificate",
                "pattern": f"[x509-certificate:hashes.'SHA-1' = '{sha1}']",
                "pattern_type": "stix",
                "indicator_types": ["malicious-activity", "compromised"],
                "valid_from": now,
                "labels": [_slugify(family), "c2", "ssl-certificate", "sslbl"],
                "x_clawint_source": "c2-tracker",
                "x_clawint_family": family,
                "external_references": [{"source_name": "SSLBL", "url": "https://sslbl.abuse.ch/"}],
            }
            stix_objects.append(indicator)

            if len(stix_objects) >= 500:
                r = await self.push_to_platform(stix_objects)
                result.objects_created += r.objects_created
                result.errors += r.errors
                stix_objects = []

        if stix_objects:
            r = await self.push_to_platform(stix_objects)
            result.objects_created += r.objects_created
            result.errors += r.errors

        return result

    async def _ingest_ips(self, now: str) -> IngestResult:
        result = IngestResult()
        try:
            resp = await self.http.get(_IP_URL, headers={"User-Agent": "SOCINT/1.0 CTI Platform (research)"})
            resp.raise_for_status()
        except Exception as e:
            self.logger.warning(f"C2 Tracker: IP feed fetch failed: {e}")
            result.errors += 1
            return result

        stix_objects = []
        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) < 2:
                continue
            ip = parts[1].strip()
            if not ip or not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                continue

            indicator = {
                "type": "indicator",
                "name": f"Botnet C2: {ip}",
                "description": "SSLBL — confirmed botnet C2 server",
                "pattern": f"[ipv4-addr:value = '{ip}']",
                "pattern_type": "stix",
                "indicator_types": ["malicious-activity", "compromised"],
                "valid_from": now,
                "labels": ["c2", "botnet", "sslbl"],
                "x_clawint_source": "c2-tracker",
                "external_references": [{"source_name": "SSLBL", "url": "https://sslbl.abuse.ch/"}],
            }
            stix_objects.append(indicator)

            if len(stix_objects) >= 500:
                r = await self.push_to_platform(stix_objects)
                result.objects_created += r.objects_created
                result.errors += r.errors
                stix_objects = []

        if stix_objects:
            r = await self.push_to_platform(stix_objects)
            result.objects_created += r.objects_created
            result.errors += r.errors

        return result


def _slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower().strip()).strip("-")
