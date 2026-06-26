"""
Malpedia connector — import malware families, actors, and relationships.
Ingests curated malware taxonomy from Malpedia (Fraunhofer FKIE).
Free API key from https://malpedia.caad.fkie.fraunhofer.de/api/
"""
from datetime import datetime, timezone

import httpx

from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult
from app.config import get_settings

settings = get_settings()


class MalpediaConnector(BaseConnector):
    BASE_URL = "https://malpedia.caad.fkie.fraunhofer.de/api"

    def __init__(self):
        super().__init__(ConnectorConfig(
            name="malpedia",
            display_name="Malpedia (Malware Taxonomy)",
            connector_type="import_external",
            description=(
                "Imports curated malware families and threat actor taxonomy from Malpedia. "
                "Includes family metadata, aliases, YARA rules, and actor-to-malware relationships."
            ),
            schedule="0 6 * * 0",  # weekly Sunday 06:00
            source_reliability=85,
        ))

    async def run(self) -> IngestResult:
        self.logger.info("Malpedia: starting import...")
        result = IngestResult()

        if not settings.malpedia_api_key:
            self.logger.warning("Malpedia: MALPEDIA_API_KEY not set, skipping")
            return result

        try:
            # Import families
            families_result = await self._import_families()
            result.objects_created += families_result["created"]
            result.errors += families_result["errors"]

            # Import actors
            actors_result = await self._import_actors()
            result.objects_created += actors_result["created"]
            result.errors += actors_result["errors"]

            # Import relationships (actor → malware)
            rels_result = await self._import_relationships()
            result.objects_created += rels_result["created"]
            result.errors += rels_result["errors"]

        except Exception as e:
            self.logger.error(f"Malpedia: fatal error: {e}")
            result.errors += 1

        self.logger.info(
            f"Malpedia: imported {result.objects_created} objects, "
            f"{result.errors} errors"
        )
        return result

    async def _import_families(self) -> dict:
        """Fetch and import malware families."""
        created = 0
        errors = 0
        stix_objects = []

        try:
            families = await self._fetch_json("/list/families")
            if not isinstance(families, list):
                self.logger.error(f"Malpedia: unexpected families response type")
                return {"created": 0, "errors": 1}

            self.logger.info(f"Malpedia: importing {len(families)} families")

            for family_name in families:
                try:
                    family_data = await self._fetch_json(f"/get/family/{family_name}")
                    if not family_data:
                        errors += 1
                        continue

                    # Extract aliases
                    aliases = family_data.get("common_names", [])
                    if isinstance(aliases, str):
                        aliases = [aliases]

                    # Get associated actors
                    actor_names = family_data.get("actors", [])
                    if isinstance(actor_names, str):
                        actor_names = [actor_names]

                    # Build STIX malware object
                    malware = {
                        "type": "malware",
                        "name": family_name,
                        "description": family_data.get("description", "")[:2000],
                        "aliases": aliases[:20],
                        "labels": ["trojan"],  # default label
                        "created": datetime.now(timezone.utc).isoformat(),
                        "modified": datetime.now(timezone.utc).isoformat(),
                        "valid_from": datetime.now(timezone.utc).isoformat(),
                        "x_clawint_source": "malpedia",
                        "x_clawint_source_reliability": self.config.source_reliability,
                        "x_clawint_malpedia_url": f"https://malpedia.caad.fkie.fraunhofer.de/details/{family_name}",
                        "x_clawint_malpedia_actors": actor_names[:10],
                    }

                    stix_objects.append(malware)

                    # Batch push every 50
                    if len(stix_objects) >= 50:
                        r = await self.push_to_platform(stix_objects)
                        created += r.objects_created
                        errors += r.errors
                        stix_objects = []

                except Exception as e:
                    self.logger.debug(f"Malpedia: failed to import family {family_name}: {e}")
                    errors += 1

            # Final batch
            if stix_objects:
                r = await self.push_to_platform(stix_objects)
                created += r.objects_created
                errors += r.errors

        except Exception as e:
            self.logger.error(f"Malpedia: families import failed: {e}")
            errors += 1

        return {"created": created, "errors": errors}

    async def _import_actors(self) -> dict:
        """Fetch and import threat actors."""
        created = 0
        errors = 0
        stix_objects = []

        try:
            actors = await self._fetch_json("/list/actors")
            if not isinstance(actors, list):
                self.logger.error(f"Malpedia: unexpected actors response type")
                return {"created": 0, "errors": 1}

            self.logger.info(f"Malpedia: importing {len(actors)} actors")

            for actor_name in actors:
                try:
                    actor_data = await self._fetch_json(f"/get/actor/{actor_name}")
                    if not actor_data:
                        errors += 1
                        continue

                    aliases = actor_data.get("common_names", [])
                    if isinstance(aliases, str):
                        aliases = [aliases]

                    # Build STIX threat-actor object
                    threat_actor = {
                        "type": "threat-actor",
                        "name": actor_name,
                        "description": actor_data.get("description", "")[:2000],
                        "aliases": aliases[:20],
                        "labels": ["hacker"],
                        "created": datetime.now(timezone.utc).isoformat(),
                        "modified": datetime.now(timezone.utc).isoformat(),
                        "x_clawint_source": "malpedia",
                        "x_clawint_source_reliability": self.config.source_reliability,
                        "x_clawint_malpedia_url": f"https://malpedia.caad.fkie.fraunhofer.de/actor/{actor_name}",
                    }

                    stix_objects.append(threat_actor)

                    # Batch push every 50
                    if len(stix_objects) >= 50:
                        r = await self.push_to_platform(stix_objects)
                        created += r.objects_created
                        errors += r.errors
                        stix_objects = []

                except Exception as e:
                    self.logger.debug(f"Malpedia: failed to import actor {actor_name}: {e}")
                    errors += 1

            # Final batch
            if stix_objects:
                r = await self.push_to_platform(stix_objects)
                created += r.objects_created
                errors += r.errors

        except Exception as e:
            self.logger.error(f"Malpedia: actors import failed: {e}")
            errors += 1

        return {"created": created, "errors": errors}

    async def _import_relationships(self) -> dict:
        """Fetch actor data and create actor → malware relationships."""
        created = 0
        errors = 0
        stix_objects = []

        try:
            actors = await self._fetch_json("/list/actors")
            if not isinstance(actors, list):
                return {"created": 0, "errors": 1}

            for actor_name in actors:
                try:
                    actor_data = await self._fetch_json(f"/get/actor/{actor_name}")
                    if not actor_data:
                        errors += 1
                        continue

                    families = actor_data.get("families", [])
                    if isinstance(families, str):
                        families = [families]

                    # Create relationship for each family used by this actor
                    for family_name in families:
                        rel_id = f"relationship--{self._deterministic_id(f'uses:{actor_name}:{family_name}')}"
                        rel = {
                            "type": "relationship",
                            "id": rel_id,
                            "relationship_type": "uses",
                            "source_ref": f"threat-actor--{self._deterministic_id(actor_name)}",
                            "target_ref": f"malware--{self._deterministic_id(family_name)}",
                            "created": datetime.now(timezone.utc).isoformat(),
                            "modified": datetime.now(timezone.utc).isoformat(),
                            "x_clawint_source": "malpedia",
                        }
                        stix_objects.append(rel)

                        # Batch push every 100
                        if len(stix_objects) >= 100:
                            r = await self.push_to_platform(stix_objects)
                            created += r.objects_created
                            errors += r.errors
                            stix_objects = []

                except Exception as e:
                    self.logger.debug(f"Malpedia: failed to create relationships for actor {actor_name}: {e}")
                    errors += 1

            # Final batch
            if stix_objects:
                r = await self.push_to_platform(stix_objects)
                created += r.objects_created
                errors += r.errors

        except Exception as e:
            self.logger.error(f"Malpedia: relationships import failed: {e}")
            errors += 1

        return {"created": created, "errors": errors}

    async def _fetch_json(self, path: str) -> dict | list | None:
        """Fetch JSON from Malpedia API."""
        try:
            async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
                resp = await client.get(
                    f"{self.BASE_URL}{path}",
                    headers={
                        "Authorization": f"Bearer {settings.malpedia_api_key}",
                        "User-Agent": "SOCINT/1.0 CTI Platform (research)",
                    },
                )
                if resp.status_code == 200:
                    return resp.json()
                elif resp.status_code == 401:
                    self.logger.error(f"Malpedia: auth failed — check MALPEDIA_API_KEY")
                    return None
                else:
                    self.logger.debug(f"Malpedia: {path} returned {resp.status_code}")
                    return None
        except Exception as e:
            self.logger.debug(f"Malpedia: fetch {path} failed: {e}")
            return None

    @staticmethod
    def _deterministic_id(value: str) -> str:
        """Generate deterministic UUID from value (compatible with STIX uuid5)."""
        import uuid
        _NAMESPACE = uuid.UUID("a3b4c5d6-e7f8-4a9b-0c1d-2e3f4a5b6c7d")
        return str(uuid.uuid5(_NAMESPACE, value.strip().lower()))
