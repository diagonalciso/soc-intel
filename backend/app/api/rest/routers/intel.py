"""
STIX intelligence REST endpoints.
Full CRUD for all STIX 2.1 object types.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from typing import Any

from app.core.stix_engine import get_stix_engine, STIXEngine
from app.auth.dependencies import get_current_user, require_analyst
from app.models.user import User

router = APIRouter(prefix="/intel", tags=["intelligence"])


class STIXObjectCreate(BaseModel):
    type: str
    data: dict[str, Any]


class RelationshipCreate(BaseModel):
    relationship_type: str
    source_ref: str
    target_ref: str
    description: str | None = None
    tlp: str = "TLP:AMBER"


# ── STIX Object CRUD ────────────────────────────────────────────

@router.post("/objects")
async def create_object(
    payload: STIXObjectCreate,
    engine: STIXEngine = Depends(get_stix_engine),
    user: User = Depends(require_analyst),
):
    return await engine.create(payload.type, payload.data, created_by=str(user.id))


@router.get("/objects/{stix_id}")
async def get_object(
    stix_id: str,
    engine: STIXEngine = Depends(get_stix_engine),
    user: User = Depends(get_current_user),
):
    obj = await engine.get(stix_id)
    if not obj:
        raise HTTPException(status_code=404, detail="Object not found")
    return obj


@router.patch("/objects/{stix_id}")
async def update_object(
    stix_id: str,
    updates: dict[str, Any],
    engine: STIXEngine = Depends(get_stix_engine),
    user: User = Depends(require_analyst),
):
    obj = await engine.update(stix_id, updates)
    if not obj:
        raise HTTPException(status_code=404, detail="Object not found")
    return obj


@router.delete("/objects/{stix_id}", status_code=204)
async def delete_object(
    stix_id: str,
    engine: STIXEngine = Depends(get_stix_engine),
    user: User = Depends(require_analyst),
):
    deleted = await engine.delete(stix_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Object not found")


@router.get("/objects")
async def search_objects(
    type: str | None = Query(None),
    q: str | None = Query(None),
    tlp: str | None = Query(None),
    source: str | None = Query(None),
    from_: int = Query(0, alias="from"),
    size: int = Query(25, le=500),
    engine: STIXEngine = Depends(get_stix_engine),
    user: User = Depends(get_current_user),
):
    filters: dict = {}
    if tlp:
        filters["tlp"] = tlp
    if source:
        filters["x_clawint_source"] = source
    return await engine.search(stix_type=type, query=q, filters=filters or None, from_=from_, size=size)


@router.get("/objects/{stix_id}/relationships")
async def get_relationships(
    stix_id: str,
    engine: STIXEngine = Depends(get_stix_engine),
    user: User = Depends(get_current_user),
):
    return await engine.get_relationships(stix_id)


@router.get("/objects/{stix_id}/graph")
async def get_graph(
    stix_id: str,
    engine: STIXEngine = Depends(get_stix_engine),
    user: User = Depends(get_current_user),
):
    """Return graph data (nodes + edges) for Cytoscape visualization."""
    return await engine.get_graph(stix_id)


@router.post("/relationships")
async def create_relationship(
    payload: RelationshipCreate,
    engine: STIXEngine = Depends(get_stix_engine),
    user: User = Depends(require_analyst),
):
    return await engine.create_relationship(
        relationship_type=payload.relationship_type,
        source_ref=payload.source_ref,
        target_ref=payload.target_ref,
        description=payload.description,
        created_by=str(user.id),
        tlp=payload.tlp,
    )


@router.post("/bulk")
async def bulk_ingest(
    objects: list[dict[str, Any]],
    engine: STIXEngine = Depends(get_stix_engine),
    user: User = Depends(require_analyst),
):
    """Bulk ingest STIX objects (used by connectors)."""
    return await engine.bulk_ingest(objects)


# ── Convenience endpoints by type ───────────────────────────────

STIX_TYPES = [
    "threat-actor", "intrusion-set", "campaign", "malware", "tool",
    "attack-pattern", "vulnerability", "indicator", "infrastructure",
    "identity", "report", "course-of-action",
]


@router.get("/threat-actors")
async def list_threat_actors(
    q: str | None = Query(None),
    from_: int = Query(0, alias="from"),
    size: int = Query(25, le=500),
    engine: STIXEngine = Depends(get_stix_engine),
    user: User = Depends(get_current_user),
):
    return await engine.search(stix_type="threat-actor", query=q, from_=from_, size=size)


@router.get("/indicators")
async def list_indicators(
    q: str | None = Query(None),
    from_: int = Query(0, alias="from"),
    size: int = Query(25, le=500),
    engine: STIXEngine = Depends(get_stix_engine),
    user: User = Depends(get_current_user),
):
    return await engine.search(stix_type="indicator", query=q, from_=from_, size=size)


@router.get("/malware")
async def list_malware(
    q: str | None = Query(None),
    from_: int = Query(0, alias="from"),
    size: int = Query(25, le=500),
    engine: STIXEngine = Depends(get_stix_engine),
    user: User = Depends(get_current_user),
):
    return await engine.search(stix_type="malware", query=q, from_=from_, size=size)


@router.get("/vulnerabilities")
async def list_vulnerabilities(
    q: str | None = Query(None),
    from_: int = Query(0, alias="from"),
    size: int = Query(25, le=500),
    engine: STIXEngine = Depends(get_stix_engine),
    user: User = Depends(get_current_user),
):
    return await engine.search(stix_type="vulnerability", query=q, from_=from_, size=size)


@router.get("/stats")
async def get_intel_stats(
    engine: STIXEngine = Depends(get_stix_engine),
    user: User = Depends(get_current_user),
):
    """Summary counts by type and source for dashboard use."""
    from app.db.opensearch import get_opensearch, STIX_INDEX
    client = get_opensearch()

    body = {
        "size": 0,
        "aggs": {
            "by_type": {
                "terms": {"field": "type", "size": 30}
            },
            "by_source": {
                "terms": {"field": "x_clawint_source", "size": 30}
            },
        }
    }
    try:
        resp = await client.search(index=STIX_INDEX, body=body)
        aggs = resp.get("aggregations", {})
        by_type = {b["key"]: b["doc_count"] for b in aggs.get("by_type", {}).get("buckets", [])}
        by_source = {b["key"]: b["doc_count"] for b in aggs.get("by_source", {}).get("buckets", [])}
        total = resp.get("hits", {}).get("total", {}).get("value", 0)
        return {"total": total, "by_type": by_type, "by_source": by_source}
    except Exception as e:
        return {"total": 0, "by_type": {}, "by_source": {}}
