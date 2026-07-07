"""
MISP Galaxy connector — no-account malware & threat-actor taxonomy.

Ingests the MISP Galaxy `malpedia` and `threat-actor` clusters straight from
GitHub (CC0 public domain, no API key, no registration). Serves as the free,
no-account alternative to the key-gated Malpedia connector: family `value`s use
the same Malpedia ids (e.g. "win.emotet"), so malware objects dedup/merge with
anything the optional Malpedia connector ingests on top.

Source: https://github.com/MISP/misp-galaxy (CC0-1.0)
"""
import uuid
from datetime import datetime, timezone

from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult

# Same namespace + normalisation as the Malpedia connector so identical family
# names resolve to the same STIX id and merge across both sources.
_NAMESPACE = uuid.UUID("a3b4c5d6-e7f8-4a9b-0c1d-2e3f4a5b6c7d")

_MALPEDIA_CLUSTER = (
    "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/malpedia.json"
)
_ACTOR_CLUSTER = (
    "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"
)


class MISPGalaxyConnector(BaseConnector):
    def __init__(self):
        super().__init__(ConnectorConfig(
            name="misp-galaxy",
            display_name="MISP Galaxy (Malware & Actor Taxonomy)",
            connector_type="import_external",
            description=(
                "Imports malware-family and threat-actor taxonomy from the MISP Galaxy "
                "malpedia + threat-actor clusters on GitHub. No API key or account "
                "required (CC0). Free alternative to the key-gated Malpedia connector; "
                "family ids match Malpedia so objects merge across both."
            ),
            schedule="0 6 * * 0",  # weekly Sunday 06:00
            source_reliability=80,
        ))

    async def run(self) -> IngestResult:
        self.logger.info("MISP Galaxy: starting import...")
        result = IngestResult()

        try:
            fam = await self._import_cluster(_MALPEDIA_CLUSTER, "malware")
            result.objects_created += fam["created"]
            result.errors += fam["errors"]

            act = await self._import_cluster(_ACTOR_CLUSTER, "threat-actor")
            result.objects_created += act["created"]
            result.errors += act["errors"]
        except Exception as e:
            self.logger.error(f"MISP Galaxy: fatal error: {e}")
            result.errors += 1

        self.logger.info(
            f"MISP Galaxy: imported {result.objects_created} objects, "
            f"{result.errors} errors"
        )
        return result

    async def _import_cluster(self, url: str, stix_type: str) -> dict:
        created = 0
        errors = 0
        stix_objects: list[dict] = []

        try:
            resp = await self.http.get(url)
            if resp.status_code != 200:
                self.logger.error(f"MISP Galaxy: {url} returned {resp.status_code}")
                return {"created": 0, "errors": 1}
            values = resp.json().get("values", [])
        except Exception as e:
            self.logger.error(f"MISP Galaxy: fetch/parse {url} failed: {e}")
            return {"created": 0, "errors": 1}

        self.logger.info(f"MISP Galaxy: importing {len(values)} {stix_type} entries")
        now = datetime.now(timezone.utc).isoformat()

        for entry in values:
            try:
                name = (entry.get("value") or "").strip()
                if not name:
                    continue
                meta = entry.get("meta") or {}

                synonyms = meta.get("synonyms") or []
                if isinstance(synonyms, str):
                    synonyms = [synonyms]

                refs = meta.get("refs") or []
                if isinstance(refs, str):
                    refs = [refs]

                obj = {
                    "type": stix_type,
                    "name": name,
                    "description": (entry.get("description") or "")[:2000],
                    "aliases": synonyms[:20],
                    "labels": ["trojan"] if stix_type == "malware" else ["hacker"],
                    "created": now,
                    "modified": now,
                    "valid_from": now,
                    "x_clawint_source": "misp-galaxy",
                    "x_clawint_source_reliability": self.config.source_reliability,
                    "x_clawint_misp_galaxy_uuid": entry.get("uuid"),
                    "x_clawint_refs": refs[:10],
                }
                if stix_type == "threat-actor" and meta.get("country"):
                    obj["x_clawint_country"] = meta["country"]

                stix_objects.append(obj)

                if len(stix_objects) >= 100:
                    r = await self.push_to_platform(stix_objects)
                    created += r.objects_created
                    errors += r.errors
                    stix_objects = []
            except Exception as e:
                self.logger.debug(f"MISP Galaxy: skip {stix_type} entry: {e}")
                errors += 1

        if stix_objects:
            r = await self.push_to_platform(stix_objects)
            created += r.objects_created
            errors += r.errors

        return {"created": created, "errors": errors}

    @staticmethod
    def _deterministic_id(value: str) -> str:
        return str(uuid.uuid5(_NAMESPACE, value.strip().lower()))
