"""
Ransomwatch connector.
Ingests ransomware leak site victim data from joshhighet/ransomwatch JSON feed.
Free, no API key required.
"""
import json
from datetime import datetime, timezone

from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult
from app.db.opensearch import get_opensearch, DARKWEB_INDEX


class RansomwatchConnector(BaseConnector):
    FEED_URL = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json"
    GROUPS_URL = "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/groups.json"

    def __init__(self):
        super().__init__(ConnectorConfig(
            name="ransomwatch",
            display_name="Ransomwatch",
            connector_type="import_external",
            description="Ingests ransomware leak site victim posts from the Ransomwatch open-source feed.",
            schedule="0 */2 * * *",  # every 2 hours
        ))

    async def run(self) -> IngestResult:
        self.logger.info("Ransomwatch: fetching victim posts...")
        result = IngestResult()

        try:
            resp = await self.http.get(self.FEED_URL)
            resp.raise_for_status()
            posts = resp.json()
        except Exception as e:
            self.logger.error(f"Ransomwatch: failed to fetch posts: {e}")
            result.errors += 1
            return result

        # Fetch group metadata
        groups_meta = {}
        try:
            resp = await self.http.get(self.GROUPS_URL)
            if resp.status_code == 200:
                for group in resp.json():
                    groups_meta[group.get("name", "").lower()] = group
        except Exception:
            pass

        client = get_opensearch()
        bulk_body = []
        seen_ids = set()

        for post in posts:
            group = post.get("group_name", "unknown")
            victim = post.get("post_title", "")
            discovered = post.get("discovered", "")
            website = post.get("website", "")

            doc_id = f"ransomware-leak--rw-{group}-{_slug(victim)}"
            if doc_id in seen_ids:
                continue
            seen_ids.add(doc_id)

            doc = {
                "id": doc_id,
                "type": "ransomware-leak",
                "created": _iso(discovered),
                "modified": _iso(discovered),
                "source": "ransomwatch",
                "group_name": group,
                "victim_name": victim,
                "victim_domain": website,
                "date_posted": _iso(discovered),
                "files_published": True,
            }

            # Enrich with group metadata
            gm = groups_meta.get(group.lower(), {})
            if gm:
                doc["leak_site_url"] = (gm.get("locations") or [{}])[0].get("fqdn", "")

            bulk_body.append({"index": {"_index": DARKWEB_INDEX, "_id": doc_id}})
            bulk_body.append(doc)
            result.objects_created += 1

        if bulk_body:
            try:
                response = await client.bulk(body=bulk_body, refresh=False)
                errors = sum(
                    1 for item in response["items"]
                    if item.get("index", {}).get("error")
                )
                result.errors += errors
                result.objects_created -= errors
            except Exception as e:
                self.logger.error(f"Ransomwatch: OpenSearch bulk error: {e}")
                result.errors += len(bulk_body) // 2
                result.objects_created = 0

        self.logger.info(f"Ransomwatch: ingested {result.objects_created} victims, {result.errors} errors")
        return result


def _iso(ts: str) -> str:
    if not ts:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    except Exception:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _slug(text: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in text.lower())[:64]
