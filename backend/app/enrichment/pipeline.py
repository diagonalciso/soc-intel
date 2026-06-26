"""
Enrichment pipeline.
Automatically enriches observables when created using available connectors.
"""
import asyncio
import logging
from typing import Any

from app.connectors.builtin.abuseipdb import AbuseIPDBConnector
from app.connectors.builtin.greynoise import GreyNoiseConnector
from app.connectors.builtin.virustotal import VirusTotalConnector
from app.connectors.builtin.otx_enrichment import OTXEnrichmentConnector

logger = logging.getLogger(__name__)

# Lazy-initialized connector instances
_abuseipdb: AbuseIPDBConnector | None = None
_greynoise: GreyNoiseConnector | None = None
_virustotal: VirusTotalConnector | None = None
_otx: OTXEnrichmentConnector | None = None


def _get_connectors():
    global _abuseipdb, _greynoise, _virustotal, _otx
    if _abuseipdb is None:
        _abuseipdb = AbuseIPDBConnector()
        _greynoise = GreyNoiseConnector()
        _virustotal = VirusTotalConnector()
        _otx = OTXEnrichmentConnector()
    return _abuseipdb, _greynoise, _virustotal, _otx


async def enrich_observable(obs_type: str, value: str) -> dict:
    """
    Enrich an observable value using all applicable connectors.
    Returns merged enrichment data from all sources.
    """
    abuseipdb, greynoise, virustotal, otx = _get_connectors()
    enrichment: dict[str, Any] = {}

    tasks = []

    if obs_type in ("ipv4-addr", "ipv6-addr"):
        tasks.append(("abuseipdb", abuseipdb.enrich_ip(value)))
        tasks.append(("greynoise", greynoise.enrich_ip(value)))
        tasks.append(("virustotal", virustotal.enrich_ip(value)))
        tasks.append(("otx", otx.enrich_ip(value)))

    elif obs_type == "domain-name":
        tasks.append(("virustotal", virustotal.enrich_domain(value)))
        tasks.append(("otx", otx.enrich_domain(value)))

    elif obs_type == "url":
        tasks.append(("virustotal", virustotal.enrich_url(value)))
        tasks.append(("otx", otx.enrich_url(value)))

    elif obs_type in ("file:hashes.MD5", "file:hashes.SHA-1", "file:hashes.SHA-256"):
        tasks.append(("virustotal", virustotal.enrich_hash(value)))
        tasks.append(("otx", otx.enrich_hash(value)))

    if not tasks:
        return enrichment

    results = await asyncio.gather(*[t[1] for t in tasks], return_exceptions=True)
    for (source, _), result in zip(tasks, results):
        if isinstance(result, Exception):
            logger.warning(f"Enrichment error from {source}: {result}")
        elif result:
            enrichment[source] = result

    return enrichment


def compute_risk_score(enrichment: dict) -> int:
    """
    Compute a 0–100 risk score from enrichment data.
    Higher = more malicious.
    """
    score = 0

    abuseipdb = enrichment.get("abuseipdb", {})
    if abuseipdb:
        score = max(score, abuseipdb.get("abuseipdb_score", 0))

    vt = enrichment.get("virustotal", {})
    if vt and vt.get("found"):
        malicious = vt.get("malicious", 0)
        suspicious = vt.get("suspicious", 0)
        total = malicious + suspicious + vt.get("harmless", 0) + vt.get("undetected", 0)
        if total > 0:
            vt_score = int(((malicious * 1.0 + suspicious * 0.5) / total) * 100)
            score = max(score, vt_score)

    gn = enrichment.get("greynoise", {})
    if gn:
        if gn.get("classification") == "malicious":
            score = max(score, 80)
        elif gn.get("noise"):
            # Background noise — reduce score (likely scanner, not targeted)
            score = min(score, 30)

    otx = enrichment.get("otx", {})
    if otx:
        pulse_count = otx.get("pulse_count", 0)
        if pulse_count >= 10:
            score = max(score, 75)
        elif pulse_count >= 3:
            score = max(score, 50)
        elif pulse_count >= 1:
            score = max(score, 30)
        if otx.get("reputation", 0) < 0:
            score = max(score, 60)

    return min(score, 100)
