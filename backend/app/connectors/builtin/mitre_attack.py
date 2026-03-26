"""
MITRE ATT&CK connector — import.
Ingests the full ATT&CK Enterprise STIX bundle.
Free, no API key required.
"""
import json

from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult


class MITREAttackConnector(BaseConnector):
    ENTERPRISE_STIX_URL = (
        "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    )
    ICS_STIX_URL = (
        "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json"
    )

    def __init__(self):
        super().__init__(ConnectorConfig(
            name="mitre-attack",
            display_name="MITRE ATT&CK",
            connector_type="import_external",
            description="Imports the full MITRE ATT&CK Enterprise + ICS knowledge base (STIX 2.1).",
            schedule="0 0 * * 0",  # weekly on Sunday
        ))

    async def run(self) -> IngestResult:
        self.logger.info("MITRE ATT&CK: fetching enterprise bundle...")
        result = IngestResult()

        for name, url in [
            ("Enterprise", self.ENTERPRISE_STIX_URL),
            ("ICS", self.ICS_STIX_URL),
        ]:
            try:
                resp = await self.http.get(url, timeout=120.0)
                resp.raise_for_status()
                bundle = resp.json()
            except Exception as e:
                self.logger.error(f"ATT&CK {name}: fetch failed: {e}")
                result.errors += 1
                continue

            objects = bundle.get("objects", [])
            # Filter to useful types
            wanted = {
                "attack-pattern", "intrusion-set", "malware", "tool",
                "campaign", "course-of-action", "identity", "relationship",
            }
            filtered = [o for o in objects if o.get("type") in wanted]

            # Batch push
            batch_size = 250
            for i in range(0, len(filtered), batch_size):
                batch = filtered[i:i + batch_size]
                r = await self.push_to_platform(batch)
                result.objects_created += r.objects_created
                result.errors += r.errors

            self.logger.info(f"ATT&CK {name}: ingested {len(filtered)} objects")

        return result
