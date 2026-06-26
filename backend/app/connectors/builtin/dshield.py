"""
SANS ISC DShield connector — import.
Ingests top attack source IP ranges from the SANS Internet Storm Center.
Free, no API key required.
"""
import re
from datetime import datetime, timezone

from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult


class DShieldConnector(BaseConnector):
    # block.txt: top 20 most active /24 networks attacking DShield sensors
    FEED_URL = "https://feeds.dshield.org/block.txt"

    def __init__(self):
        super().__init__(ConnectorConfig(
            name="dshield",
            display_name="SANS ISC DShield",
            connector_type="import_external",
            description="Top attack source IP ranges from the SANS Internet Storm Center DShield honeypot network.",
            schedule="0 */12 * * *",  # every 12 hours
        ))

    async def run(self) -> IngestResult:
        self.logger.info("DShield: fetching top attack source ranges...")
        result = IngestResult()

        try:
            resp = await self.http.get(self.FEED_URL)
            resp.raise_for_status()
        except Exception as e:
            self.logger.error(f"DShield: fetch failed: {e}")
            result.errors += 1
            return result

        stix_objects = []
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        for line in resp.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("Start"):
                continue

            parts = re.split(r"\s+", line)
            if len(parts) < 3:
                continue

            start_ip = parts[0]
            end_ip = parts[1]
            cidr = parts[2]

            # Build a /24 CIDR if not provided
            if not re.match(r"\d+\.\d+\.\d+\.\d+/\d+", cidr):
                cidr = f"{start_ip}/24"

            # Validate it looks like an IP
            if not re.match(r"\d+\.\d+\.\d+\.\d+", start_ip):
                continue

            company = " ".join(parts[3:6]).strip() if len(parts) > 3 else ""

            pattern = f"[ipv4-addr:value = '{start_ip}/24']"
            name = f"DShield attack source: {cidr}"

            indicator = {
                "type": "indicator",
                "name": name,
                "description": f"SANS ISC DShield — top attack source range. AS/Org: {company}",
                "pattern": pattern,
                "pattern_type": "stix",
                "indicator_types": ["malicious-activity", "anomalous-activity"],
                "valid_from": now,
                "confidence": 60,
                "labels": ["attack-source", "scanning", "dshield", "sans-isc"],
                "x_clawint_source": "dshield",
                "x_clawint_cidr": cidr,
                "x_clawint_org": company,
                "external_references": [
                    {"source_name": "SANS ISC DShield", "url": "https://www.dshield.org/"},
                ],
            }
            stix_objects.append(indicator)

        if stix_objects:
            r = await self.push_to_platform(stix_objects)
            result.objects_created += r.objects_created
            result.errors += r.errors

        self.logger.info(f"DShield: ingested {result.objects_created} attack-source ranges")
        return result
