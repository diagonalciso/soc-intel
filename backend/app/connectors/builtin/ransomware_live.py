"""
Ransomware.live connector — import.
Ingests ransomware victim listings from ransomware.live API.
Free, no API key required for basic use.
"""
from datetime import datetime, timezone
import re

from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult
from app.db.opensearch import get_opensearch, DARKWEB_INDEX


class RansomwareLiveConnector(BaseConnector):
    API_URL = "https://api.ransomware.live/v1/recentvictims"

    def __init__(self):
        super().__init__(ConnectorConfig(
            name="ransomware-live",
            display_name="Ransomware.live",
            connector_type="import_external",
            description="Recent ransomware victims from ransomware.live community tracker.",
            schedule="0 */2 * * *",  # every 2 hours
        ))

    async def run(self) -> IngestResult:
        self.logger.info("Ransomware.live: fetching recent victims...")
        result = IngestResult()

        try:
            resp = await self.http.get(
                self.API_URL,
                headers={"User-Agent": "CLAWINT/1.0 CTI Platform (research)"},
            )
            resp.raise_for_status()
            victims = resp.json()
        except Exception as e:
            self.logger.error(f"Ransomware.live: fetch failed: {e}")
            result.errors += 1
            return result

        if not isinstance(victims, list):
            self.logger.warning(f"Ransomware.live: unexpected response format")
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
                "created": _now(),
                "modified": _now(),
                "source": "ransomware-live",
                "group_name": group,
                "victim_name": victim_name,
                "victim_domain": domain,
                "country": country,
                "sector": sector,
                "date_posted": date_posted,
                "files_published": bool(v.get("post_url") or v.get("url")),
                "data_size_gb": None,
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
                self.logger.error(f"Ransomware.live: OpenSearch bulk error: {e}")
                result.errors += len(bulk) // 2
                result.objects_created = 0

        self.logger.info(f"Ransomware.live: ingested {result.objects_created} victims")
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
