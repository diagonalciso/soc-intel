"""
PhishTank connector — import.
Ingests verified phishing URLs from the PhishTank community feed.
No API key required (developer key optional for higher rate limits).
"""
import gzip
import json
from datetime import datetime, timezone

from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult

FEED_URL = "https://data.phishtank.com/data/online-valid.json.gz"


class PhishTankConnector(BaseConnector):

    def __init__(self):
        super().__init__(ConnectorConfig(
            name="phishtank",
            display_name="PhishTank",
            connector_type="import_external",
            description="Imports verified phishing URLs from the PhishTank community feed.",
            schedule="0 */8 * * *",  # every 8 hours
            source_reliability=72,
        ))

    async def run(self) -> IngestResult:
        self.logger.info("PhishTank: fetching verified phishing feed...")
        result = IngestResult()

        try:
            resp = await self.http.get(
                FEED_URL,
                headers={"User-Agent": "phishtank/SOCINT"},
                timeout=60.0,
            )
            resp.raise_for_status()
            data: list[dict] = json.loads(gzip.decompress(resp.content))
        except Exception as e:
            self.logger.error(f"PhishTank: fetch failed: {e}")
            result.errors += 1
            return result

        self.logger.info(f"PhishTank: processing {len(data)} verified phish entries")
        stix_objects: list[dict] = []

        for entry in data:
            url = (entry.get("url") or "").strip()
            if not url:
                continue

            phish_id = entry.get("phish_id", "")
            target = (entry.get("target") or "Other").strip()
            verified_at = _iso(entry.get("verified_at", ""))

            safe_url = url.replace("\\", "\\\\").replace("'", "\\'")
            label_target = target.lower().replace(" ", "-").replace("/", "-")

            indicator = {
                "type": "indicator",
                "name": f"Phishing URL: {url[:80]}",
                "description": f"Verified phishing URL targeting {target} (PhishTank #{phish_id})",
                "pattern": f"[url:value = '{safe_url}']",
                "pattern_type": "stix",
                "indicator_types": ["malicious-activity"],
                "valid_from": verified_at,
                "confidence": 80,
                "labels": ["phishing", label_target] if label_target != "other" else ["phishing"],
                "x_clawint_source": "phishtank",
                "x_clawint_phish_target": target,
                "external_references": [
                    {
                        "source_name": "PhishTank",
                        "url": f"https://www.phishtank.com/phish_detail.php?phish_id={phish_id}",
                    }
                ],
            }
            stix_objects.append(indicator)

            if len(stix_objects) >= 250:
                r = await self.push_to_platform(stix_objects)
                result.objects_created += r.objects_created
                result.errors += r.errors
                stix_objects = []

        if stix_objects:
            r = await self.push_to_platform(stix_objects)
            result.objects_created += r.objects_created
            result.errors += r.errors

        self.logger.info(f"PhishTank: ingested {result.objects_created} phishing indicators")
        return result


def _iso(ts: str) -> str:
    if not ts:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    try:
        dt = datetime.fromisoformat(ts.replace(" ", "T"))
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    except Exception:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
