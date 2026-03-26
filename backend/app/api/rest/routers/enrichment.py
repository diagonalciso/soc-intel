"""
Enrichment API endpoints.
Enrich any observable on-demand.
"""
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.enrichment.pipeline import enrich_observable, compute_risk_score
from app.auth.dependencies import get_current_user
from app.models.user import User

router = APIRouter(prefix="/enrich", tags=["enrichment"])


class EnrichRequest(BaseModel):
    type: str   # ipv4-addr, domain-name, url, file:hashes.SHA-256, etc.
    value: str


@router.post("")
async def enrich(
    payload: EnrichRequest,
    user: User = Depends(get_current_user),
):
    enrichment = await enrich_observable(payload.type, payload.value)
    risk_score = compute_risk_score(enrichment)
    return {
        "type": payload.type,
        "value": payload.value,
        "risk_score": risk_score,
        "enrichment": enrichment,
    }
