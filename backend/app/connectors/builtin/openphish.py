"""
OpenPhish connector — import.
Ingests active phishing URLs from the OpenPhish community feed.
Free, no API key required.
"""
from datetime import datetime, timezone
from urllib.parse import urlparse

from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult


class OpenPhishConnector(BaseConnector):
    FEED_URL = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"

    def __init__(self):
        super().__init__(ConnectorConfig(
            name="openphish",
            display_name="OpenPhish Community Feed",
            connector_type="import_external",
            description="Active phishing URLs from the OpenPhish community feed. Updated every 12 hours.",
            schedule="0 */12 * * *",  # every 12 hours
        ))

    async def run(self) -> IngestResult:
        self.logger.info("OpenPhish: fetching phishing URLs...")
        result = IngestResult()

        try:
            resp = await self.http.get(self.FEED_URL)
            resp.raise_for_status()
        except Exception as e:
            self.logger.error(f"OpenPhish: fetch failed: {e}")
            result.errors += 1
            return result

        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        stix_objects = []

        for line in resp.text.splitlines():
            url = line.strip()
            if not url or not url.startswith(("http://", "https://")):
                continue

            # Extract domain for name
            try:
                domain = urlparse(url).netloc or url[:60]
            except Exception:
                domain = url[:60]

            safe_url = url.replace("'", "%27")
            pattern = f"[url:value = '{safe_url}']"

            indicator = {
                "type": "indicator",
                "name": f"Phishing: {domain}",
                "description": f"OpenPhish community feed — active phishing URL",
                "pattern": pattern,
                "pattern_type": "stix",
                "indicator_types": ["malicious-activity"],
                "valid_from": now,
                "confidence": 80,
                "labels": ["phishing", "openphish"],
                "x_clawint_source": "openphish",
                "external_references": [
                    {"source_name": "OpenPhish", "url": "https://openphish.com/"},
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

        self.logger.info(f"OpenPhish: ingested {result.objects_created} phishing URLs")
        return result
