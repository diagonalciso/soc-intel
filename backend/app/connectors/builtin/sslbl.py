"""
Spamhaus DROP (Don't Route Or Peer) connector — import.
Ingests IP ranges used by professional spam/malware/botnet operations.
Free, no API key required.
"""
import re
from datetime import datetime, timezone

from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult


class SpamhausDropConnector(BaseConnector):
    DROP_URL = "https://www.spamhaus.org/drop/drop.txt"
    EDROP_URL = "https://www.spamhaus.org/drop/edrop.txt"

    def __init__(self):
        super().__init__(ConnectorConfig(
            name="spamhaus-drop",
            display_name="Spamhaus DROP / EDROP",
            connector_type="import_external",
            description="IP ranges controlled by spammers, botnet operators and malware distributors (Spamhaus DROP + EDROP).",
            schedule="0 */12 * * *",  # every 12 hours
        ))

    async def run(self) -> IngestResult:
        self.logger.info("Spamhaus DROP: fetching blocklists...")
        result = IngestResult()
        stix_objects = []
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        for url, list_name in [(self.DROP_URL, "DROP"), (self.EDROP_URL, "EDROP")]:
            try:
                resp = await self.http.get(url)
                resp.raise_for_status()
            except Exception as e:
                self.logger.warning(f"Spamhaus {list_name}: fetch failed: {e}")
                result.errors += 1
                continue

            for line in resp.text.splitlines():
                line = line.strip()
                if not line or line.startswith(";"):
                    continue
                # Lines: x.x.x.x/yy ; SBLxxx
                parts = line.split(";")
                cidr = parts[0].strip()
                sbl_ref = parts[1].strip() if len(parts) > 1 else ""

                if not re.match(r"\d+\.\d+\.\d+\.\d+/\d+", cidr):
                    continue

                # Extract base IP for pattern
                base_ip = cidr.split("/")[0]
                pattern = f"[ipv4-addr:value = '{cidr}']"

                indicator = {
                    "type": "indicator",
                    "name": f"Spamhaus {list_name}: {cidr}",
                    "description": f"Spamhaus {list_name} — IP range used by malware/botnet operators. Ref: {sbl_ref}",
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "indicator_types": ["malicious-activity", "compromised"],
                    "valid_from": now,
                    "confidence": 90,
                    "labels": ["spamhaus", list_name.lower(), "botnet", "spam", "malware-infrastructure"],
                    "x_clawint_source": "spamhaus-drop",
                    "x_clawint_list": list_name,
                    "x_clawint_sbl_ref": sbl_ref,
                    "external_references": [
                        {"source_name": "Spamhaus", "url": "https://www.spamhaus.org/drop/"},
                    ],
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

        self.logger.info(f"Spamhaus DROP: ingested {result.objects_created} malicious IP ranges")
        return result
