"""
Core STIX 2.1 engine — CRUD for all STIX objects stored in OpenSearch.
All objects stored as-is STIX JSON with socint extensions.
"""
import hashlib
import re
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

_TLP_ALIASES: dict[str, str] = {
    "white": "TLP:CLEAR", "tlp:white": "TLP:CLEAR",
    "clear": "TLP:CLEAR", "tlp:clear": "TLP:CLEAR",
    "green": "TLP:GREEN", "tlp:green": "TLP:GREEN",
    "amber": "TLP:AMBER", "tlp:amber": "TLP:AMBER",
    "amber+strict": "TLP:AMBER+STRICT", "tlp:amber+strict": "TLP:AMBER+STRICT",
    "red": "TLP:RED",   "tlp:red":   "TLP:RED",
}


def _normalize_tlp(raw: str) -> str:
    """Normalize any TLP variant to canonical form (TLP:CLEAR, TLP:GREEN, etc.)."""
    return _TLP_ALIASES.get(raw.strip().lower(), "TLP:CLEAR")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _stix_id(stix_type: str) -> str:
    return f"{stix_type}--{uuid.uuid4()}"


# ── Deterministic ID helpers ─────────────────────────────────────────────────
# For indicators, use a stable UUID5 based on type+pattern so the same IoC
# from multiple connectors always resolves to the same document (upsert).

_INDICATOR_NAMESPACE = uuid.UUID("a3b4c5d6-e7f8-4a9b-0c1d-2e3f4a5b6c7d")

_PATTERN_VALUE_RE = re.compile(r"=\s*['\"]([^'\"]+)['\"]")


def _extract_pattern_value(pattern: str) -> str | None:
    """Extract the literal value from a STIX pattern, e.g. '1.2.3.4' from
    "[ipv4-addr:value = '1.2.3.4']". Returns None if extraction fails."""
    m = _PATTERN_VALUE_RE.search(pattern or "")
    return m.group(1) if m else None


def _deterministic_indicator_id(obj: dict) -> str:
    """
    Return a deterministic STIX ID for an indicator based on its pattern value.
    If no extractable value, fall back to a hash of the full pattern.
    """
    pattern = obj.get("pattern", "")
    value = _extract_pattern_value(pattern) or pattern
    indicator_type = obj.get("indicator_types", ["unknown"])[0] if obj.get("indicator_types") else "unknown"
    seed = f"{indicator_type}:{value.strip().lower()}"
    stable_uuid = uuid.uuid5(_INDICATOR_NAMESPACE, seed)
    return f"indicator--{stable_uuid}"


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
        """
        Bulk ingest STIX objects (from connectors).
        Applies deterministic deduplication for indicators and FP flagging.
        """
        if not objects:
            return {"indexed": 0, "errors": 0}

        # Lazy import to avoid circular deps and slow startup
        try:
            from app.core.warning_lists import is_false_positive
            _wl_available = True
        except ImportError:
            _wl_available = False

        body = []
        for obj in objects:
            obj_type = obj.get("type", "indicator")

            # Deterministic ID for indicators — deduplicates across connectors
            if obj_type == "indicator" and "pattern" in obj:
                obj["id"] = _deterministic_indicator_id(obj)
            elif "id" not in obj:
                obj["id"] = _stix_id(obj_type)

            if "spec_version" not in obj:
                obj["spec_version"] = "2.1"
            if "created" not in obj:
                obj["created"] = _now()
            if "modified" not in obj:
                obj["modified"] = _now()

            # Warning list check — flag FPs instead of silently storing
            if _wl_available and obj_type == "indicator":
                pattern_val = _extract_pattern_value(obj.get("pattern", ""))
                if pattern_val:
                    indicator_types = obj.get("indicator_types", [])
                    ioc_type = indicator_types[0] if indicator_types else _infer_type(pattern_val)
                    try:
                        is_fp, reason = await is_false_positive(ioc_type, pattern_val)
                        if is_fp:
                            obj["x_clawint_fp_candidate"] = True
                            obj["x_clawint_fp_reason"] = reason
                    except Exception:
                        pass

            # Apply source reliability to indicator confidence
            if obj_type == "indicator":
                reliability = obj.get("x_clawint_source_reliability", 80)
                raw_confidence = obj.get("confidence", 60)
                obj["confidence"] = max(10, int(raw_confidence * reliability / 100))

            # Normalize TLP → set canonical `tlp` keyword field for filtering
            raw_tlp = obj.get("x_clawint_tlp") or obj.get("tlp") or "TLP:CLEAR"
            obj["tlp"] = _normalize_tlp(raw_tlp)
            # Keep object_marking_refs in sync with STIX standard
            if "object_marking_refs" not in obj:
                marking_id = TLP_MARKINGS.get(obj["tlp"])
                if marking_id:
                    obj["object_marking_refs"] = [marking_id]

            body.append({"index": {"_index": STIX_INDEX, "_id": obj["id"]}})
            body.append(obj)

        result = await self.client.bulk(body=body, refresh=True)

        indexed = sum(1 for item in result["items"] if item.get("index", {}).get("result") in ("created", "updated"))
        errors = len(result["items"]) - indexed
        return {"indexed": indexed, "errors": errors}

    async def get_graph(self, stix_id: str, depth: int = 1) -> dict:
        """
        Return graph data for Cytoscape: {nodes: [...], edges: [...]}.
        Fetches the root object, all direct relationships, and the
        objects at the other end of each relationship.
        """
        root = await self.get(stix_id)
        if not root:
            return {"nodes": [], "edges": []}

        nodes = {stix_id: root}
        edges = []

        rels = await self.get_relationships(stix_id)
        for rel in rels:
            edges.append({
                "id":    rel.get("id", ""),
                "source": rel.get("source_ref", ""),
                "target": rel.get("target_ref", ""),
                "label":  rel.get("relationship_type", ""),
            })
            for ref in (rel.get("source_ref", ""), rel.get("target_ref", "")):
                if ref and ref != stix_id and ref not in nodes:
                    obj = await self.get(ref)
                    if obj:
                        nodes[ref] = obj

        return {
            "nodes": [
                {
                    "id":    n["id"],
                    "type":  n.get("type", ""),
                    "label": n.get("name") or n.get("value") or n.get("id", "")[:32],
                    "root":  n["id"] == stix_id,
                }
                for n in nodes.values()
            ],
            "edges": edges,
        }

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


def _infer_type(value: str) -> str:
    """Guess the indicator type from a raw value string."""
    import re as _re
    if _re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value):
        return "ipv4-addr"
    if _re.match(r"^[0-9a-fA-F]{32}$", value):
        return "file:hashes.MD5"
    if _re.match(r"^[0-9a-fA-F]{40}$", value):
        return "file:hashes.SHA-1"
    if _re.match(r"^[0-9a-fA-F]{64}$", value):
        return "file:hashes.SHA-256"
    if value.startswith(("http://", "https://")):
        return "url"
    if "@" in value:
        return "email-addr"
    return "domain-name"
