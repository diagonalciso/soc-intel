"""
Ransomware.live connector — import.
Ingests ransomware victim listings and group profiles from ransomware.live API v2.
Free, no API key required for basic use.
https://api.ransomware.live/v2 — https://www.ransomware.live/apidocs
"""
from datetime import datetime, timezone
import re

from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult
from app.db.opensearch import get_opensearch, DARKWEB_INDEX


class RansomwareLiveConnector(BaseConnector):
    BASE_URL    = "https://api.ransomware.live/v2"
    BASE_URL_V1 = "https://api.ransomware.live/v1"

    def __init__(self):
        super().__init__(ConnectorConfig(
            name="ransomware-live",
            display_name="Ransomware.live",
            connector_type="import_external",
            description="Ransomware victims and group profiles from ransomware.live (v2 API, 200+ groups).",
            schedule="0 */2 * * *",  # every 2 hours
        ))

    async def run(self) -> IngestResult:
        self.logger.info("Ransomware.live: fetching victims and groups...")
        result = IngestResult()

        victims_result = await self._ingest_victims()
        groups_result = await self._ingest_groups()

        result.objects_created = victims_result.objects_created + groups_result.objects_created
        result.errors = victims_result.errors + groups_result.errors
        self.logger.info(
            f"Ransomware.live: {result.objects_created} objects ingested, {result.errors} errors"
        )
        return result

    async def _ingest_victims(self) -> IngestResult:
        result = IngestResult()
        headers = {"User-Agent": "SOCINT/1.0 CTI Platform (research)"}
        victims = None

        # Try v2 with extended timeout first, fall back to v1
        for url in (f"{self.BASE_URL}/recentvictims", f"{self.BASE_URL_V1}/recentvictims"):
            try:
                import httpx as _httpx
                async with _httpx.AsyncClient(timeout=90.0, follow_redirects=True) as client:
                    resp = await client.get(url, headers=headers)
                resp.raise_for_status()
                victims = resp.json()
                if isinstance(victims, list):
                    self.logger.info(f"Ransomware.live: using {url} ({len(victims)} victims)")
                    break
            except Exception as e:
                self.logger.warning(f"Ransomware.live: {url} failed: {e}")

        if not victims:
            self.logger.error("Ransomware.live: both v2 and v1 victims endpoints failed")
            result.errors += 1
            return result

        if not isinstance(victims, list):
            self.logger.warning("Ransomware.live: unexpected victims response format")
            return result

        client = get_opensearch()
        bulk = []

        for v in victims:
            victim_name = (v.get("post_title") or v.get("victim") or v.get("title") or "").strip()
            if not victim_name:
                continue

            group = (v.get("group_name") or v.get("group") or v.get("gang") or "unknown").strip().lower()
            domain = (v.get("website") or v.get("url") or "").strip()
            country = (v.get("country") or "").strip()
            sector = (v.get("activity") or "").strip()
            description = (v.get("description") or "").strip()
            date_posted = _iso(v.get("discovered") or v.get("published") or "")

            doc_id = f"ransomware-leak--rwlive-{group}-{_slug(victim_name)}"
            doc = {
                "id": doc_id,
                "type": "ransomware-leak",
                "created": date_posted,
                "modified": _now(),
                "source": "ransomware-live",
                "group_name": group,
                "victim_name": victim_name,
                "victim_domain": domain,
                "country": country,
                "sector": sector,
                "date_posted": date_posted,
                "files_published": bool(v.get("post_url") or v.get("url")),
                "description": description[:500] if description else "",
            }
            bulk.append({"index": {"_index": DARKWEB_INDEX, "_id": doc_id}})
            bulk.append(doc)
            result.objects_created += 1

        if bulk:
            try:
                resp_bulk = await client.bulk(body=bulk, refresh=False)
                errors = sum(1 for item in resp_bulk["items"] if item.get("index", {}).get("error"))
                result.errors += errors
                result.objects_created -= errors
            except Exception as e:
                self.logger.error(f"Ransomware.live: OpenSearch bulk error (victims): {e}")
                result.errors += len(bulk) // 2
                result.objects_created = 0

        return result

    async def _ingest_groups(self) -> IngestResult:
        """Fetch group profiles from /v2/groups and store as ransomware-group docs."""
        result = IngestResult()
        try:
            resp = await self.http.get(
                f"{self.BASE_URL}/groups",
                headers={"User-Agent": "SOCINT/1.0 CTI Platform (research)"},
            )
            resp.raise_for_status()
            groups = resp.json()
        except Exception as e:
            self.logger.warning(f"Ransomware.live: groups fetch failed: {e}")
            return result

        if not isinstance(groups, list):
            return result

        client = get_opensearch()
        bulk = []
        now = _now()

        for g in groups:
            name = (g.get("name") or g.get("group_name") or "").strip()
            if not name:
                continue

            doc_id = f"ransomware-group--rwlive-{_slug(name)}"
            doc = {
                "id": doc_id,
                "type": "ransomware-group",
                "created": now,
                "modified": now,
                "source": "ransomware-live",
                "group_name": name.lower(),
                "group_display_name": name,
                "leak_site_url": (g.get("url") or g.get("onion") or g.get("leak_site") or "").strip(),
                "status": (g.get("status") or "").strip(),
                "description": (g.get("description") or g.get("profile") or "")[:500],
                "date_posted": now,
            }
            bulk.append({"index": {"_index": DARKWEB_INDEX, "_id": doc_id}})
            bulk.append(doc)
            result.objects_created += 1

        if bulk:
            try:
                resp_bulk = await client.bulk(body=bulk, refresh=False)
                errors = sum(1 for item in resp_bulk["items"] if item.get("index", {}).get("error"))
                result.errors += errors
                result.objects_created -= errors
            except Exception as e:
                self.logger.error(f"Ransomware.live: OpenSearch bulk error (groups): {e}")
                result.errors += len(bulk) // 2
                result.objects_created = 0

        return result


def _iso(ts: str) -> str:
    if not ts:
        return _now()
    try:
        if "T" in ts:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        else:
            dt = datetime.fromisoformat(ts)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    except Exception:
        return _now()


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower().strip())[:64]
