"""
Feodo Tracker connector (abuse.ch) — import.
Ingests botnet C2 server IPs (Emotet, TrickBot, QakBot, etc.).
Free, no API key required.
"""
from datetime import datetime, timezone

from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult


class FeodoTrackerConnector(BaseConnector):
    FEED_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

    def __init__(self):
        super().__init__(ConnectorConfig(
            name="feodotracker",
            display_name="Feodo Tracker (abuse.ch)",
            connector_type="import_external",
            description="Imports botnet C2 server IPs (Emotet, TrickBot, QakBot) from abuse.ch Feodo Tracker.",
            schedule="0 */6 * * *",  # every 6 hours
        ))

    async def run(self) -> IngestResult:
        self.logger.info("FeodoTracker: fetching C2 IP blocklist...")
        result = IngestResult()

        try:
            resp = await self.http.get(self.FEED_URL)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            self.logger.error(f"FeodoTracker: fetch failed: {e}")
            result.errors += 1
            return result

        stix_objects = []
        for entry in data:
            ip = entry.get("ip_address", "").strip()
            if not ip:
                continue

            malware = entry.get("malware", "unknown")
            port = entry.get("dst_port", "")
            confidence = entry.get("confidence_level", 75)
            first_seen = _iso(entry.get("first_seen", ""))

            pattern = f"[ipv4-addr:value = '{ip}']"
            name = f"{malware} C2: {ip}"
            if port:
                name += f":{port}"

            indicator = {
                "type": "indicator",
                "name": name,
                "description": f"Feodo Tracker — {malware} botnet C2 server",
                "pattern": pattern,
                "pattern_type": "stix",
                "indicator_types": ["malicious-activity", "compromised"],
                "valid_from": first_seen,
                "confidence": confidence,
                "labels": [malware.lower().replace(" ", "-"), "c2", "botnet", "feodotracker"],
                "x_clawint_source": "feodotracker",
                "x_clawint_malware": malware,
                "x_clawint_dst_port": port,
                "external_references": [
                    {"source_name": "Feodo Tracker", "url": "https://feodotracker.abuse.ch/"},
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

        self.logger.info(f"FeodoTracker: ingested {result.objects_created} C2 indicators")
        return result


def _iso(ts: str) -> str:
    if not ts:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    try:
        dt = datetime.fromisoformat(ts.replace(" ", "T"))
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    except Exception:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
