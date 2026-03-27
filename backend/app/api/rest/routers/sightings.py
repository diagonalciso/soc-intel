"""
Sightings — record and retrieve indicator sightings.
A sighting tracks that a specific indicator was observed in an environment.
Sighted indicators are exempt from confidence decay for 30 days.
"""
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel

from app.auth.dependencies import get_current_user
from app.db.opensearch import get_opensearch, STIX_INDEX
from app.models.user import User

router = APIRouter(prefix="/sightings", tags=["sightings"])


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


class SightingCreate(BaseModel):
    sighting_of_ref: str          # STIX ID of the indicator that was seen
    count: int = 1                # Number of times seen
    first_seen: str | None = None # ISO timestamp; defaults to now
    source: str = "manual"        # e.g. "siem", "edr", "manual"
    note: str | None = None


@router.post("")
async def create_sighting(
    payload: SightingCreate,
    user: User = Depends(get_current_user),
):
    """Record a new indicator sighting and update the indicator's sighting metadata."""
    client = get_opensearch()
    now = _now()

    sighting_doc = {
        "id": f"sighting--{uuid.uuid4()}",
        "type": "sighting",
        "spec_version": "2.1",
        "created": now,
        "modified": now,
        "first_seen": payload.first_seen or now,
        "last_seen": now,
        "count": payload.count,
        "sighting_of_ref": payload.sighting_of_ref,
        "x_clawint_source": payload.source,
        "x_clawint_reported_by": user.email,
        "x_clawint_note": payload.note or "",
    }

    await client.index(
        index=STIX_INDEX,
        id=sighting_doc["id"],
        body=sighting_doc,
        refresh=True,
    )

    # Update the indicator: track last sighted timestamp and cumulative count.
    # The decay job skips indicators sighted within the last 30 days.
    try:
        await client.update(
            index=STIX_INDEX,
            id=payload.sighting_of_ref,
            body={
                "script": {
                    "source": (
                        "ctx._source.x_clawint_last_sighted = params.now; "
                        "long cur = ctx._source.containsKey('x_clawint_sighting_count') "
                        "  ? (long) ctx._source.x_clawint_sighting_count : 0L; "
                        "ctx._source.x_clawint_sighting_count = cur + params.count; "
                        "ctx._source.modified = params.now;"
                    ),
                    "params": {"now": now, "count": payload.count},
                }
            },
            refresh=True,
        )
    except Exception:
        pass  # Indicator may not exist in STIX index (e.g. dark web only)

    return sighting_doc


@router.get("")
async def list_sightings(
    indicator_id: str | None = Query(None, description="Filter by indicator STIX ID"),
    size: int = Query(50, le=500),
    user: User = Depends(get_current_user),
):
    """List sightings, optionally filtered to a specific indicator."""
    client = get_opensearch()
    must: list = [{"term": {"type": "sighting"}}]
    if indicator_id:
        must.append({"term": {"sighting_of_ref": indicator_id}})

    result = await client.search(
        index=STIX_INDEX,
        body={
            "query": {"bool": {"must": must}},
            "sort": [{"created": {"order": "desc"}}],
            "size": size,
        },
    )
    hits = result["hits"]
    return {
        "total": hits["total"]["value"],
        "sightings": [h["_source"] for h in hits["hits"]],
    }
