"""
Dark web intelligence endpoints.
Ransomware victims, stealer logs, credential exposures, IAB listings.
"""
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from typing import Any

from app.core.stix_engine import get_stix_engine, STIXEngine
from app.auth.dependencies import get_current_user, require_analyst
from app.models.user import User

router = APIRouter(prefix="/darkweb", tags=["dark web"])


class RansomwareLeakCreate(BaseModel):
    group_name: str
    victim_name: str
    victim_domain: str | None = None
    country: str | None = None
    sector: str | None = None
    date_posted: str | None = None
    data_size_gb: float | None = None
    files_published: bool = False
    leak_site_url: str | None = None
    source: str = "manual"


class CredentialExposureCreate(BaseModel):
    email: str | None = None
    domain: str | None = None
    source: str
    exposure_type: str  # breach, stealer_log, combo_list
    malware_family: str | None = None
    date_discovered: str | None = None


class IABListingCreate(BaseModel):
    access_type: str  # rdp, vpn, webshell, domain_admin, local_admin
    target_sector: str | None = None
    target_country: str | None = None
    asking_price_usd: float | None = None
    forum_name: str | None = None
    source: str = "manual"


class StealerLogCreate(BaseModel):
    malware_family: str
    domains: list[str] | None = None
    credentials_count: int | None = None
    date_exfiltrated: str | None = None
    source: str


# ── Ransomware Leaks ────────────────────────────────────────────

@router.post("/ransomware", status_code=201)
async def create_ransomware_leak(
    payload: RansomwareLeakCreate,
    engine: STIXEngine = Depends(get_stix_engine),
    user: User = Depends(require_analyst),
):
    return await engine.create_darkweb("ransomware-leak", payload.model_dump())


@router.get("/ransomware")
async def list_ransomware_leaks(
    group: str | None = Query(None),
    country: str | None = Query(None),
    sector: str | None = Query(None),
    q: str | None = Query(None),
    from_: int = Query(0, alias="from"),
    size: int = Query(25, le=500),
    engine: STIXEngine = Depends(get_stix_engine),
    user: User = Depends(get_current_user),
):
    filters = {}
    if group:
        filters["group_name"] = group
    if country:
        filters["country"] = country
    if sector:
        filters["sector"] = sector
    return await engine.search_darkweb("ransomware-leak", query=q, filters=filters, from_=from_, size=size)


@router.get("/ransomware/stats")
async def ransomware_stats(
    engine: STIXEngine = Depends(get_stix_engine),
    user: User = Depends(get_current_user),
):
    from app.db.opensearch import get_opensearch, DARKWEB_INDEX
    client = get_opensearch()
    body = {
        "size": 0,
        "query": {"term": {"type": "ransomware-leak"}},
        "aggs": {
            "by_group": {"terms": {"field": "group_name", "size": 20}},
            "by_country": {"terms": {"field": "country", "size": 20}},
            "by_sector": {"terms": {"field": "sector", "size": 20}},
            "over_time": {
                "date_histogram": {
                    "field": "date_posted",
                    "calendar_interval": "month",
                }
            },
        },
    }
    result = await client.search(index=DARKWEB_INDEX, body=body)
    aggs = result.get("aggregations", {})
    return {
        "total": result["hits"]["total"]["value"],
        "by_group": {b["key"]: b["doc_count"] for b in aggs.get("by_group", {}).get("buckets", [])},
        "by_country": {b["key"]: b["doc_count"] for b in aggs.get("by_country", {}).get("buckets", [])},
        "by_sector": {b["key"]: b["doc_count"] for b in aggs.get("by_sector", {}).get("buckets", [])},
        "over_time": [
            {"date": b["key_as_string"], "count": b["doc_count"]}
            for b in aggs.get("over_time", {}).get("buckets", [])
        ],
    }


# ── Credential Exposures ────────────────────────────────────────

@router.post("/credentials", status_code=201)
async def create_credential_exposure(
    payload: CredentialExposureCreate,
    engine: STIXEngine = Depends(get_stix_engine),
    user: User = Depends(require_analyst),
):
    return await engine.create_darkweb("credential-exposure", payload.model_dump())


@router.get("/credentials")
async def list_credential_exposures(
    domain: str | None = Query(None),
    exposure_type: str | None = Query(None),
    q: str | None = Query(None),
    from_: int = Query(0, alias="from"),
    size: int = Query(25, le=500),
    engine: STIXEngine = Depends(get_stix_engine),
    user: User = Depends(get_current_user),
):
    filters = {}
    if domain:
        filters["domain"] = domain
    if exposure_type:
        filters["exposure_type"] = exposure_type
    return await engine.search_darkweb("credential-exposure", query=q, filters=filters, from_=from_, size=size)


# ── IAB Listings ────────────────────────────────────────────────

@router.post("/iab", status_code=201)
async def create_iab_listing(
    payload: IABListingCreate,
    engine: STIXEngine = Depends(get_stix_engine),
    user: User = Depends(require_analyst),
):
    return await engine.create_darkweb("iab-listing", payload.model_dump())


@router.get("/iab")
async def list_iab_listings(
    access_type: str | None = Query(None),
    country: str | None = Query(None),
    sector: str | None = Query(None),
    from_: int = Query(0, alias="from"),
    size: int = Query(25, le=500),
    engine: STIXEngine = Depends(get_stix_engine),
    user: User = Depends(get_current_user),
):
    filters = {}
    if access_type:
        filters["access_type"] = access_type
    if country:
        filters["target_country"] = country
    if sector:
        filters["target_sector"] = sector
    return await engine.search_darkweb("iab-listing", filters=filters, from_=from_, size=size)


# ── Stealer Logs ────────────────────────────────────────────────

@router.post("/stealer-logs", status_code=201)
async def create_stealer_log(
    payload: StealerLogCreate,
    engine: STIXEngine = Depends(get_stix_engine),
    user: User = Depends(require_analyst),
):
    return await engine.create_darkweb("stealer-log", payload.model_dump())


@router.get("/stealer-logs")
async def list_stealer_logs(
    malware_family: str | None = Query(None),
    domain: str | None = Query(None),
    from_: int = Query(0, alias="from"),
    size: int = Query(25, le=500),
    engine: STIXEngine = Depends(get_stix_engine),
    user: User = Depends(get_current_user),
):
    filters = {}
    if malware_family:
        filters["malware_family"] = malware_family
    return await engine.search_darkweb("stealer-log", filters=filters, from_=from_, size=size)


# ── Summary dashboard ───────────────────────────────────────────

@router.get("/summary")
async def darkweb_summary(
    engine: STIXEngine = Depends(get_stix_engine),
    user: User = Depends(get_current_user),
):
    from app.db.opensearch import get_opensearch, DARKWEB_INDEX
    client = get_opensearch()
    body = {
        "size": 0,
        "aggs": {
            "by_type": {"terms": {"field": "type", "size": 10}},
        },
    }
    result = await client.search(index=DARKWEB_INDEX, body=body)
    counts = {b["key"]: b["doc_count"] for b in result["aggregations"]["by_type"]["buckets"]}
    return {
        "ransomware_leaks": counts.get("ransomware-leak", 0),
        "credential_exposures": counts.get("credential-exposure", 0),
        "iab_listings": counts.get("iab-listing", 0),
        "stealer_logs": counts.get("stealer-log", 0),
    }
