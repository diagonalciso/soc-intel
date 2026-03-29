"""
RansomLook connector — import.
Ingests ransomware victim posts from ransomlook.io open API.
Free, no auth required. Data license: CC BY 4.0.
https://www.ransomlook.io/doc/
"""
import re
from datetime import datetime, timezone

from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult
from app.db.opensearch import get_opensearch, DARKWEB_INDEX


class RansomLookConnector(BaseConnector):
    BASE_URL = "https://www.ransomlook.io"

    def __init__(self):
        super().__init__(ConnectorConfig(
            name="ransomlook",
            display_name="RansomLook",
            connector_type="import_external",
            description="Ransomware victim posts from ransomlook.io — 200+ groups including markets/forums.",
            schedule="0 */3 * * *",  # every 3 hours
        ))

    async def run(self) -> IngestResult:
        self.logger.info("RansomLook: fetching recent posts...")
        result = IngestResult()

        # Fetch last 2 days of posts
        posts = await self._fetch_posts()
        if posts is None:
            result.errors += 1
            return result

        # Fetch group metadata for enrichment
        groups_meta = await self._fetch_groups_meta()

        client = get_opensearch()
        bulk = []
        seen = set()

        for post in posts:
            victim = (
                post.get("post_title") or post.get("title") or
                post.get("name") or post.get("victim") or ""
            ).strip()
            if not victim:
                continue

            group = (
                post.get("group_name") or post.get("group") or
                post.get("gang") or "unknown"
            ).strip().lower()

            domain = (post.get("website") or post.get("url") or post.get("domain") or "").strip()
            country = (post.get("country") or "").strip()
            sector = (post.get("activity") or post.get("sector") or "").strip()
            description = (post.get("description") or post.get("summary") or "").strip()
            date_posted = _iso(post.get("discovered") or post.get("published") or post.get("date") or "")

            doc_id = f"ransomware-leak--rl-{group}-{_slug(victim)}"
            if doc_id in seen:
                continue
            seen.add(doc_id)

            doc = {
                "id": doc_id,
                "type": "ransomware-leak",
                "created": date_posted,
                "modified": date_posted,
                "source": "ransomlook",
                "group_name": group,
                "victim_name": victim,
                "victim_domain": domain,
                "country": country,
                "sector": sector,
                "date_posted": date_posted,
                "description": description[:500] if description else "",
                "files_published": True,
            }

            # Enrich with leak site URL from group metadata
            gm = groups_meta.get(group, {})
            if gm:
                locations = gm.get("locations") or gm.get("urls") or []
                if locations and isinstance(locations, list):
                    first = locations[0]
                    if isinstance(first, dict):
                        doc["leak_site_url"] = first.get("fqdn") or first.get("url") or ""
                    elif isinstance(first, str):
                        doc["leak_site_url"] = first

            bulk.append({"index": {"_index": DARKWEB_INDEX, "_id": doc_id}})
            bulk.append(doc)
            result.objects_created += 1

        if bulk:
            try:
                resp = await client.bulk(body=bulk, refresh=False)
                errors = sum(1 for item in resp["items"] if item.get("index", {}).get("error"))
                result.errors += errors
                result.objects_created -= errors
            except Exception as e:
                self.logger.error(f"RansomLook: OpenSearch bulk error: {e}")
                result.errors += len(bulk) // 2
                result.objects_created = 0

        self.logger.info(f"RansomLook: ingested {result.objects_created} victims, {result.errors} errors")
        return result

    async def _fetch_posts(self) -> list | None:
        """Fetch recent posts from /api/last/2 (last 2 days)."""
        for endpoint in ["/api/last/2", "/api/recent/200", "/api/recent"]:
            try:
                resp = await self.http.get(
                    f"{self.BASE_URL}{endpoint}",
                    headers={"User-Agent": "SOCINT/1.0 CTI Platform (research)"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if isinstance(data, list):
                        return data
                    if isinstance(data, dict):
                        return data.get("posts") or data.get("data") or data.get("results") or []
            except Exception as e:
                self.logger.warning(f"RansomLook: {endpoint} failed: {e}")
        return None

    async def _fetch_groups_meta(self) -> dict:
        """Fetch group list and build a name→metadata map."""
        try:
            resp = await self.http.get(
                f"{self.BASE_URL}/api/groups",
                headers={"User-Agent": "SOCINT/1.0 CTI Platform (research)"},
            )
            if resp.status_code != 200:
                return {}
            data = resp.json()
            if isinstance(data, dict):
                # Response may be {group_name: metadata_dict, ...}
                return {k.lower(): v for k, v in data.items() if isinstance(v, dict)}
            if isinstance(data, list):
                # May be list of strings (group names) or list of dicts
                result = {}
                for g in data:
                    if isinstance(g, dict) and g.get("name"):
                        result[g["name"].lower()] = g
                    elif isinstance(g, str) and g:
                        result[g.lower()] = {"name": g}
                return result
        except Exception as e:
            self.logger.warning(f"RansomLook: groups fetch failed: {e}")
        return {}


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
