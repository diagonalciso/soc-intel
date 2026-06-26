"""
TAXII 2.1 import connector.
Pulls STIX 2.1 objects from TAXII servers.
Pre-configured with Anomali Limo (free public feed, no registration required).
Additional servers can be added via TAXII_SERVERS config.
"""
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Iterator

from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult
from app.config import get_settings

settings = get_settings()

# Pre-configured free TAXII servers
# Each entry: (name, url, username, password)
DEFAULT_SERVERS = [
    (
        "Anomali Limo",
        "https://limo.anomali.com/api/v1/taxii2/",
        "guest",
        "guest",
    ),
]

# STIX object types we want to ingest
_WANTED_TYPES = {
    "indicator", "malware", "threat-actor", "intrusion-set",
    "attack-pattern", "campaign", "tool", "vulnerability",
    "course-of-action", "relationship", "identity",
}

_LOOKBACK_DAYS = 7


class TAXIIImportConnector(BaseConnector):

    def __init__(self):
        super().__init__(ConnectorConfig(
            name="taxii",
            display_name="TAXII 2.1 Feeds",
            connector_type="import_external",
            description=(
                "Pulls STIX 2.1 objects from TAXII 2.1 servers. "
                "Pre-configured with Anomali Limo (free public feed). "
                "No API key required for default servers."
            ),
            schedule="0 */6 * * *",  # every 6 hours
        ))

    async def run(self) -> IngestResult:
        result = IngestResult()

        servers = list(DEFAULT_SERVERS)
        # Allow additional servers via config (format: "name|url|user|pass,...")
        if settings.taxii_extra_servers:
            for entry in settings.taxii_extra_servers.split(","):
                parts = entry.strip().split("|")
                if len(parts) == 4:
                    servers.append(tuple(parts))

        for name, url, user, password in servers:
            self.logger.info(f"TAXII: connecting to {name} ({url})...")
            try:
                r = await asyncio.to_thread(
                    _pull_server, name, url, user, password, _LOOKBACK_DAYS
                )
                if r:
                    await self._push_objects(name, r, result)
            except Exception as e:
                self.logger.error(f"TAXII: {name}: {e}")
                result.errors += 1

        self.logger.info(
            f"TAXII: total {result.objects_created} objects, {result.errors} errors"
        )
        return result

    async def _push_objects(self, name: str, objects: list[dict], result: IngestResult):
        filtered = [o for o in objects if o.get("type") in _WANTED_TYPES]
        self.logger.info(f"TAXII: {name}: {len(filtered)} objects to ingest")

        batch_size = 250
        for i in range(0, len(filtered), batch_size):
            batch = filtered[i:i + batch_size]
            r = await self.push_to_platform(batch)
            result.objects_created += r.objects_created
            result.errors += r.errors


def _pull_server(name: str, url: str, user: str, password: str, lookback_days: int) -> list[dict]:
    """
    Synchronous TAXII pull — runs in a thread via asyncio.to_thread.
    Returns a flat list of STIX objects from all collections.
    """
    # Import here to keep it isolated in the thread
    from taxii2client.v21 import Server, as_pages
    from taxii2client.exceptions import TAXIIServiceException

    added_after = (
        datetime.now(timezone.utc) - timedelta(days=lookback_days)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    objects: list[dict] = []

    try:
        server = Server(url, user=user, password=password, verify=True)
        for api_root in server.api_roots:
            try:
                collections = api_root.collections
            except Exception:
                continue

            for collection in collections:
                if not collection.can_read:
                    continue
                try:
                    for bundle in as_pages(
                        collection.get_objects,
                        per_request=500,
                        added_after=added_after,
                    ):
                        objects.extend(bundle.get("objects", []))
                except TAXIIServiceException:
                    # Some collections may be empty or restricted
                    continue
                except Exception:
                    continue

    except Exception as e:
        raise RuntimeError(f"TAXII server {name}: {e}") from e

    return objects
