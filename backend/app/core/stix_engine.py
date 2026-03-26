"""
Core STIX 2.1 engine — CRUD for all STIX objects stored in OpenSearch.
All objects stored as-is STIX JSON with clawint extensions.
"""
import uuid
from datetime import datetime, timezone
from typing import Any

from opensearchpy import NotFoundError

from app.db.opensearch import get_opensearch, STIX_INDEX, DARKWEB_INDEX


# TLP marking definition IDs (standard)
TLP_MARKINGS = {
    "TLP:WHITE": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "TLP:CLEAR": "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "TLP:GREEN": "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
    "TLP:AMBER": "marking-definition--f88d31f6-1f95-4d47-ba2f-8b1f394b8695",
    "TLP:AMBER+STRICT": "marking-definition--939a9414-2ddd-4d32-a254-099d340a827a",
    "TLP:RED": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _stix_id(stix_type: str) -> str:
    return f"{stix_type}--{uuid.uuid4()}"


class STIXEngine:
    def __init__(self):
        self.client = get_opensearch()

    async def create(self, stix_type: str, data: dict, created_by: str | None = None) -> dict:
        """Create a new STIX object."""
        now = _now()
        obj = {
            "id": _stix_id(stix_type),
            "type": stix_type,
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            **data,
        }
        if created_by:
            obj["created_by_ref"] = created_by
        if "object_marking_refs" not in obj:
            obj["object_marking_refs"] = [TLP_MARKINGS["TLP:AMBER"]]

        await self.client.index(
            index=STIX_INDEX,
            id=obj["id"],
            body=obj,
            refresh=True,
        )
        return obj

    async def get(self, stix_id: str) -> dict | None:
        try:
            result = await self.client.get(index=STIX_INDEX, id=stix_id)
            return result["_source"]
        except NotFoundError:
            return None

    async def update(self, stix_id: str, updates: dict) -> dict | None:
        updates["modified"] = _now()
        try:
            await self.client.update(
                index=STIX_INDEX,
                id=stix_id,
                body={"doc": updates},
                refresh=True,
            )
            return await self.get(stix_id)
        except NotFoundError:
            return None

    async def delete(self, stix_id: str) -> bool:
        try:
            await self.client.delete(index=STIX_INDEX, id=stix_id, refresh=True)
            return True
        except NotFoundError:
            return False

    async def search(
        self,
        stix_type: str | None = None,
        query: str | None = None,
        filters: dict | None = None,
        from_: int = 0,
        size: int = 25,
    ) -> dict:
        must = []

        if stix_type:
            must.append({"term": {"type": stix_type}})

        if query:
            must.append({
                "multi_match": {
                    "query": query,
                    "fields": ["name^3", "description", "labels"],
                }
            })

        if filters:
            for key, value in filters.items():
                if isinstance(value, list):
                    must.append({"terms": {key: value}})
                else:
                    must.append({"term": {key: value}})

        body = {
            "query": {"bool": {"must": must}} if must else {"match_all": {}},
            "sort": [{"modified": {"order": "desc"}}],
            "from": from_,
            "size": size,
        }

        result = await self.client.search(index=STIX_INDEX, body=body)
        hits = result["hits"]
        return {
            "total": hits["total"]["value"],
            "objects": [h["_source"] for h in hits["hits"]],
        }

    async def get_relationships(self, stix_id: str) -> list[dict]:
        """Get all relationships where this object is source or target."""
        body = {
            "query": {
                "bool": {
                    "should": [
                        {"term": {"source_ref": stix_id}},
                        {"term": {"target_ref": stix_id}},
                    ],
                    "minimum_should_match": 1,
                    "must": [{"term": {"type": "relationship"}}],
                }
            },
            "size": 500,
        }
        result = await self.client.search(index=STIX_INDEX, body=body)
        return [h["_source"] for h in result["hits"]["hits"]]

    async def create_relationship(
        self,
        relationship_type: str,
        source_ref: str,
        target_ref: str,
        description: str | None = None,
        created_by: str | None = None,
        tlp: str = "TLP:AMBER",
    ) -> dict:
        data = {
            "relationship_type": relationship_type,
            "source_ref": source_ref,
            "target_ref": target_ref,
            "object_marking_refs": [TLP_MARKINGS.get(tlp, TLP_MARKINGS["TLP:AMBER"])],
        }
        if description:
            data["description"] = description
        return await self.create("relationship", data, created_by=created_by)

    async def bulk_ingest(self, objects: list[dict]) -> dict:
        """Bulk ingest STIX objects (from connectors)."""
        if not objects:
            return {"indexed": 0, "errors": 0}

        body = []
        for obj in objects:
            if "id" not in obj:
                obj["id"] = _stix_id(obj.get("type", "indicator"))
            if "spec_version" not in obj:
                obj["spec_version"] = "2.1"
            if "created" not in obj:
                obj["created"] = _now()
            if "modified" not in obj:
                obj["modified"] = _now()

            body.append({"index": {"_index": STIX_INDEX, "_id": obj["id"]}})
            body.append(obj)

        result = await self.client.bulk(body=body, refresh=True)

        indexed = sum(1 for item in result["items"] if item.get("index", {}).get("result") in ("created", "updated"))
        errors = len(result["items"]) - indexed
        return {"indexed": indexed, "errors": errors}

    # ── Dark web objects ────────────────────────────────────────

    async def create_darkweb(self, obj_type: str, data: dict) -> dict:
        now = _now()
        obj = {
            "id": f"{obj_type}--{uuid.uuid4()}",
            "type": obj_type,
            "created": now,
            "modified": now,
            **data,
        }
        await self.client.index(
            index=DARKWEB_INDEX,
            id=obj["id"],
            body=obj,
            refresh=True,
        )
        return obj

    async def search_darkweb(
        self,
        obj_type: str | None = None,
        query: str | None = None,
        filters: dict | None = None,
        from_: int = 0,
        size: int = 25,
    ) -> dict:
        must = []

        if obj_type:
            must.append({"term": {"type": obj_type}})
        if query:
            must.append({
                "multi_match": {
                    "query": query,
                    "fields": ["victim_name^3", "victim_domain^2", "group_name^2", "email", "domain"],
                }
            })
        if filters:
            for key, value in filters.items():
                if isinstance(value, list):
                    must.append({"terms": {key: value}})
                else:
                    must.append({"term": {key: value}})

        body = {
            "query": {"bool": {"must": must}} if must else {"match_all": {}},
            "sort": [{"created": {"order": "desc"}}],
            "from": from_,
            "size": size,
        }

        result = await self.client.search(index=DARKWEB_INDEX, body=body)
        hits = result["hits"]
        return {
            "total": hits["total"]["value"],
            "objects": [h["_source"] for h in hits["hits"]],
        }


# Singleton
_engine: STIXEngine | None = None


def get_stix_engine() -> STIXEngine:
    global _engine
    if _engine is None:
        _engine = STIXEngine()
    return _engine
