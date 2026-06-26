"""
IPsum connector — import.
Ingests aggregated malicious IPs from stamparm/ipsum (GitHub).
Each IP is scored by how many independent blocklists contain it (1–10+).
Only imports IPs seen in 3+ lists (reduced false positives).
Free, no API key required.
"""
from datetime import datetime, timezone

from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult

FEED_URL = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
MIN_SCORE = 3  # minimum list-count to ingest (reduces FP)


class IPsumConnector(BaseConnector):
    def __init__(self):
        super().__init__(ConnectorConfig(
            name="ipsum",
            display_name="IPsum (stamparm)",
            connector_type="import_external",
            description="Aggregated malicious IPs from 30+ blocklists via stamparm/ipsum. Scored by occurrence count; only imports IPs seen in 3+ lists.",
            schedule="0 */8 * * *",
            source_reliability=76,
        ))

    async def run(self) -> IngestResult:
        self.logger.info("IPsum: fetching aggregated malicious IP list...")
        result = IngestResult()

        try:
            resp = await self.http.get(FEED_URL)
            resp.raise_for_status()
        except Exception as e:
            self.logger.error(f"IPsum: fetch failed: {e}")
            result.errors += 1
            return result

        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        stix_objects = []

        for line in resp.text.splitlines():
            if line.startswith("#") or not line.strip():
                continue

            parts = line.split("\t")
            if len(parts) < 2:
                continue

            ip = parts[0].strip()
            try:
                score = int(parts[1].strip())
            except ValueError:
                continue

            if score < MIN_SCORE:
                continue

            # Scale score to confidence: score 3=45, 5=60, 8=80, 10+=90
            confidence = min(90, 30 + score * 6)

            indicator = {
                "type": "indicator",
                "name": f"Malicious IP: {ip} (score {score})",
                "description": f"IPsum — IP found in {score} independent blocklists",
                "pattern": f"[ipv4-addr:value = '{ip}']",
                "pattern_type": "stix",
                "indicator_types": ["malicious-activity", "anomalous-activity"],
                "valid_from": now,
                "confidence": confidence,
                "labels": ["malicious-ip", "ipsum", "aggregated-blocklist"],
                "x_clawint_source": "ipsum",
                "x_clawint_ipsum_score": score,
                "external_references": [
                    {
                        "source_name": "IPsum",
                        "url": "https://github.com/stamparm/ipsum",
                    }
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

        self.logger.info(f"IPsum: ingested {result.objects_created} IP indicators")
        return result
