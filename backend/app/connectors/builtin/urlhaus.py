"""
URLhaus connector — import.
Ingests malicious URLs from abuse.ch URLhaus feed.
Free, no API key required.
"""
import csv
import io
from datetime import datetime, timezone

from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult


class URLhausConnector(BaseConnector):
    FEED_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"

    def __init__(self):
        super().__init__(ConnectorConfig(
            name="urlhaus",
            display_name="URLhaus (abuse.ch)",
            connector_type="import_external",
            description="Imports malicious URLs from abuse.ch URLhaus. Updated every 5 minutes upstream.",
            schedule="*/30 * * * *",  # every 30 minutes
        ))

    async def run(self) -> IngestResult:
        self.logger.info("URLhaus: fetching recent malicious URLs...")
        result = IngestResult()

        try:
            resp = await self.http.get(self.FEED_URL)
            resp.raise_for_status()
        except Exception as e:
            self.logger.error(f"URLhaus: fetch failed: {e}")
            result.errors += 1
            return result

        lines = [
            line for line in resp.text.splitlines()
            if not line.startswith("#") and line.strip()
        ]

        reader = csv.DictReader(lines, fieldnames=[
            "id", "dateadded", "url", "url_status", "last_online",
            "threat", "tags", "urlhaus_link", "reporter"
        ])

        stix_objects = []
        for row in reader:
            url = row.get("url", "").strip()
            if not url:
                continue

            indicator = {
                "type": "indicator",
                "name": f"Malicious URL: {url[:100]}",
                "description": f"URLhaus: {row.get('threat', 'malware')} — reported by {row.get('reporter', 'unknown')}",
                "pattern": f"[url:value = '{url}']",
                "pattern_type": "stix",
                "indicator_types": ["malicious-activity"],
                "valid_from": _iso(row.get("dateadded", "")),
                "labels": ["malicious-url", row.get("threat", "malware").lower()],
                "x_clawint_source": "urlhaus",
                "x_clawint_urlhaus_link": row.get("urlhaus_link", ""),
                "x_clawint_status": row.get("url_status", ""),
                "external_references": [
                    {"source_name": "URLhaus", "url": row.get("urlhaus_link", "")}
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

        self.logger.info(f"URLhaus: ingested {result.objects_created} indicators")
        return result


def _iso(ts: str) -> str:
    if not ts:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    try:
        dt = datetime.fromisoformat(ts)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    except Exception:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
