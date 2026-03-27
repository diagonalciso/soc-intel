"""
Enrichment API endpoints.
Enrich any observable on-demand.
"""
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.enrichment.pipeline import enrich_observable, compute_risk_score
from app.auth.dependencies import get_current_user
from app.models.user import User
from app.connectors.builtin.shodan_internetdb import ShodanInternetDBConnector
from app.connectors.builtin.hybrid_analysis import HybridAnalysisConnector
from app.connectors.builtin.crtsh import CrtShConnector

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


@router.get("/shodan-internetdb/ip/{ip}", tags=["enrichment"])
async def enrich_ip_shodan(
    ip: str,
    user: User = Depends(get_current_user),
):
    """Enrich an IPv4 address using the Shodan InternetDB API (no auth required)."""
    connector = ShodanInternetDBConnector()
    objects = await connector.enrich_ip(ip)
    return {"ip": ip, "source": "shodan-internetdb", "objects": objects}


@router.get("/hybrid-analysis/hash/{hash}", tags=["enrichment"])
async def enrich_hash_hybrid_analysis(
    hash: str,
    user: User = Depends(get_current_user),
):
    """Enrich a file hash (MD5/SHA1/SHA256) using Hybrid Analysis sandbox results."""
    connector = HybridAnalysisConnector()
    objects = await connector.enrich_hash(hash)
    return {"hash": hash, "source": "hybrid-analysis", "objects": objects}


@router.get("/crtsh/domain/{domain}", tags=["enrichment"])
async def enrich_domain_crtsh(
    domain: str,
    user: User = Depends(get_current_user),
):
    """Enrich a domain with subdomains and SANs from crt.sh Certificate Transparency logs."""
    connector = CrtShConnector()
    objects = await connector.enrich_domain(domain)
    return {"domain": domain, "source": "crtsh", "objects": objects}
