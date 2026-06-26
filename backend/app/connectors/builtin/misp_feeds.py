"""
MISP feeds connector — import.
Ingests threat intelligence from public MISP feeds (manifest.json format).
Pre-configured with Botvrij.eu OSINT and abuse.ch MISP feeds.
Free, no API key required.
"""
import asyncio
from datetime import datetime, timezone, timedelta

from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult

# Public MISP feeds — (display_name, base_url)
# All use the standard manifest.json + {uuid}.json pattern
PUBLIC_FEEDS = [
    ("Botvrij.eu OSINT",      "https://www.botvrij.eu/data/feed-osint/"),
    ("abuse.ch URLhaus MISP", "https://urlhaus.abuse.ch/downloads/misp/"),
]

# MISP attribute type → STIX pattern builder
_TYPE_MAP: dict = {
    "ip-dst":           lambda v: f"[ipv4-addr:value = '{v}']",
    "ip-src":           lambda v: f"[ipv4-addr:value = '{v}']",
    "ip-dst|port":      lambda v: f"[ipv4-addr:value = '{v.split('|')[0]}']",
    "ip-src|port":      lambda v: f"[ipv4-addr:value = '{v.split('|')[0]}']",
    "domain":           lambda v: f"[domain-name:value = '{v}']",
    "hostname":         lambda v: f"[domain-name:value = '{v}']",
    "domain|ip":        lambda v: f"[domain-name:value = '{v.split('|')[0]}']",
    "url":              lambda v: f"[url:value = '{v.replace(chr(39), '%27')}']",
    "md5":              lambda v: f"[file:hashes.MD5 = '{v}']",
    "sha1":             lambda v: f"[file:hashes.'SHA-1' = '{v}']",
    "sha256":           lambda v: f"[file:hashes.'SHA-256' = '{v}']",
    "filename|md5":     lambda v: f"[file:hashes.MD5 = '{v.split('|')[1]}']" if "|" in v else None,
    "filename|sha1":    lambda v: f"[file:hashes.'SHA-1' = '{v.split('|')[1]}']" if "|" in v else None,
    "filename|sha256":  lambda v: f"[file:hashes.'SHA-256' = '{v.split('|')[1]}']" if "|" in v else None,
    "email-src":        lambda v: f"[email-addr:value = '{v}']",
    "email-dst":        lambda v: f"[email-addr:value = '{v}']",
}

# Events older than this are skipped (incremental polling)
_LOOKBACK_DAYS = 7
# Max events fetched per feed per run (avoid hammering servers)
_MAX_EVENTS_PER_FEED = 100


class MISPFeedsConnector(BaseConnector):

    def __init__(self):
        super().__init__(ConnectorConfig(
            name="misp-feeds",
            display_name="MISP Public Feeds",
            connector_type="import_external",
            description=(
                "Imports threat indicators from public MISP feeds "
                "(Botvrij.eu OSINT, abuse.ch URLhaus/Feodo). "
                "Free, no API key required."
            ),
            schedule="0 */4 * * *",  # every 4 hours
        ))

    async def run(self) -> IngestResult:
        result = IngestResult()
        cutoff = datetime.now(timezone.utc) - timedelta(days=_LOOKBACK_DAYS)

        for feed_name, feed_url in PUBLIC_FEEDS:
            self.logger.info(f"MISP feeds: fetching {feed_name}...")
            try:
                r = await self._ingest_feed(feed_name, feed_url, cutoff)
                result.objects_created += r.objects_created
                result.errors += r.errors
            except Exception as e:
                self.logger.error(f"MISP feeds: {feed_name} failed: {e}")
                result.errors += 1

        self.logger.info(
            f"MISP feeds: total {result.objects_created} indicators, {result.errors} errors"
        )
        return result

    async def _ingest_feed(self, feed_name: str, feed_url: str, cutoff: datetime) -> IngestResult:
        result = IngestResult()

        # Fetch manifest
        try:
            resp = await self.http.get(f"{feed_url}manifest.json", timeout=30.0)
            resp.raise_for_status()
            manifest = resp.json()
        except Exception as e:
            self.logger.warning(f"MISP feeds: {feed_name}: manifest fetch failed: {e}")
            result.errors += 1
            return result

        # Filter to recent events and sort newest first
        recent = []
        for uuid, meta in manifest.items():
            date_str = meta.get("date", "")
            try:
                event_date = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                if event_date >= cutoff:
                    recent.append((uuid, event_date, meta))
            except Exception:
                continue

        recent.sort(key=lambda x: x[1], reverse=True)
        recent = recent[:_MAX_EVENTS_PER_FEED]

        if not recent:
            self.logger.info(f"MISP feeds: {feed_name}: no recent events")
            return result

        self.logger.info(f"MISP feeds: {feed_name}: processing {len(recent)} recent events")

        # Fetch and parse events with limited concurrency
        sem = asyncio.Semaphore(5)
        tasks = [self._fetch_event(feed_url, uuid, meta, feed_name, sem) for uuid, _, meta in recent]
        event_results = await asyncio.gather(*tasks, return_exceptions=True)

        stix_objects = []
        for er in event_results:
            if isinstance(er, Exception):
                result.errors += 1
            elif er:
                stix_objects.extend(er)

            if len(stix_objects) >= 250:
                r = await self.push_to_platform(stix_objects)
                result.objects_created += r.objects_created
                result.errors += r.errors
                stix_objects = []

        if stix_objects:
            r = await self.push_to_platform(stix_objects)
            result.objects_created += r.objects_created
            result.errors += r.errors

        return result

    async def _fetch_event(
        self, feed_url: str, uuid: str, meta: dict, feed_name: str, sem: asyncio.Semaphore
    ) -> list[dict]:
        async with sem:
            try:
                resp = await self.http.get(f"{feed_url}{uuid}.json", timeout=30.0)
                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                self.logger.debug(f"MISP feeds: event {uuid}: {e}")
                return []

        event = data.get("Event", data)  # some feeds wrap in "Event", some don't
        event_info = event.get("info", "")
        event_date = event.get("date", "")
        valid_from = _norm_date(event_date)
        tags = [t.get("name", "") for t in event.get("Tag", []) if t.get("name")]
        labels = ["misp", feed_name.lower().replace(" ", "-").replace(".", "")] + [
            t.replace(":", "-").lower() for t in tags if not t.startswith("tlp:") and len(t) < 64
        ]
        tlp = next((t for t in tags if t.lower().startswith("tlp:")), "tlp:white").upper().replace(":", ":")

        # Collect attributes from Event.Attribute and Event.Object[].Attribute
        raw_attrs = list(event.get("Attribute", []))
        for obj in event.get("Object", []):
            raw_attrs.extend(obj.get("Attribute", []))

        stix_objects = []
        for attr in raw_attrs:
            if not attr.get("to_ids", False):
                continue  # skip non-actionable attributes

            attr_type = attr.get("type", "")
            attr_value = (attr.get("value") or "").strip()
            if not attr_type or not attr_value:
                continue

            fn = _TYPE_MAP.get(attr_type)
            if fn is None:
                continue
            pattern = fn(attr_value)
            if not pattern:
                continue

            stix_objects.append({
                "type": "indicator",
                "name": f"{attr_type}: {attr_value[:100]}",
                "description": event_info or f"MISP feed: {feed_name}",
                "pattern": pattern,
                "pattern_type": "stix",
                "indicator_types": ["malicious-activity"],
                "valid_from": valid_from,
                "confidence": 60,
                "labels": list(dict.fromkeys(labels)),
                "x_clawint_source": "misp-feeds",
                "x_clawint_feed": feed_name,
                "x_clawint_tlp": tlp,
                "x_clawint_misp_uuid": uuid,
                "external_references": [
                    {"source_name": feed_name, "external_id": uuid}
                ],
            })

        return stix_objects


def _norm_date(date_str: str) -> str:
    try:
        dt = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%dT00:00:00.000Z")
    except Exception:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
