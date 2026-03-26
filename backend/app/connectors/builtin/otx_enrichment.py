"""
AlienVault OTX enrichment connector.
On-demand enrichment for IPs, domains, URLs, and file hashes.
Returns pulse count, reputation, malware associations, geo, and passive DNS.
Requires OTX_API_KEY.
"""
from urllib.parse import quote

from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult
from app.config import get_settings

settings = get_settings()

OTX_BASE = "https://otx.alienvault.com/api/v1"


class OTXEnrichmentConnector(BaseConnector):

    def __init__(self):
        super().__init__(ConnectorConfig(
            name="otx-enrichment",
            display_name="AlienVault OTX (Enrichment)",
            connector_type="enrichment",
            description=(
                "Enriches IPs, domains, URLs, and file hashes using AlienVault OTX. "
                "Returns pulse count, reputation, malware associations, and passive DNS. "
                "Requires OTX_API_KEY."
            ),
        ))

    @property
    def _headers(self) -> dict:
        return {
            "X-OTX-API-KEY": settings.otx_api_key,
            "Accept": "application/json",
        }

    async def run(self) -> IngestResult:
        return IngestResult(messages=["OTX enrichment is on-demand — call enrich_*() directly"])

    async def enrich_ip(self, ip: str) -> dict | None:
        if not settings.otx_api_key:
            return None
        return await self._fetch("IPv4", ip, ["general", "reputation", "geo", "malware", "passive_dns"])

    async def enrich_domain(self, domain: str) -> dict | None:
        if not settings.otx_api_key:
            return None
        return await self._fetch("domain", domain, ["general", "malware", "url_list", "passive_dns"])

    async def enrich_url(self, url: str) -> dict | None:
        if not settings.otx_api_key:
            return None
        return await self._fetch("url", quote(url, safe=""), ["general"])

    async def enrich_hash(self, hash_value: str) -> dict | None:
        if not settings.otx_api_key:
            return None
        return await self._fetch("file", hash_value, ["general", "analysis"])

    async def _fetch(self, itype: str, value: str, sections: list[str]) -> dict | None:
        raw = {}
        for section in sections:
            try:
                resp = await self.http.get(
                    f"{OTX_BASE}/indicators/{itype}/{value}/{section}",
                    headers=self._headers,
                )
                if resp.status_code == 404:
                    continue
                resp.raise_for_status()
                raw[section] = resp.json()
            except Exception as e:
                self.logger.warning(f"OTX enrich {itype}/{value}/{section}: {e}")

        if not raw:
            return None

        return _parse(raw)


def _parse(raw: dict) -> dict:
    out: dict = {"source": "otx"}

    general = raw.get("general", {})
    if general:
        pulse_info = general.get("pulse_info", {})
        out["pulse_count"] = pulse_info.get("count", 0)
        out["pulse_names"] = [p.get("name") for p in pulse_info.get("pulses", [])[:5]]
        out["malware_families"] = [
            mf.get("display_name")
            for mf in pulse_info.get("related", {}).get("malware_families", [])
        ]
        out["asn"] = general.get("asn")
        out["country_code"] = general.get("country_code")
        out["city"] = general.get("city")
        out["reputation"] = general.get("reputation", 0)
        out["whois"] = general.get("whois")

    reputation = raw.get("reputation", {})
    if reputation:
        out["reputation"] = reputation.get("reputation", out.get("reputation", 0))
        out["activities"] = reputation.get("activities", [])

    geo = raw.get("geo", {})
    if geo:
        out["country_code"] = geo.get("country_code", out.get("country_code"))
        out["country_name"] = geo.get("country_name")
        out["city"] = geo.get("city", out.get("city"))
        out["latitude"] = geo.get("latitude")
        out["longitude"] = geo.get("longitude")

    malware = raw.get("malware", {})
    if malware:
        out["malware_samples"] = [
            {"hash": s.get("hash"), "family": s.get("detections", {}).get("avast")}
            for s in malware.get("data", [])[:10]
        ]

    passive_dns = raw.get("passive_dns", {})
    if passive_dns:
        out["passive_dns"] = [
            {
                "hostname": r.get("hostname"),
                "address": r.get("address"),
                "last": r.get("last"),
            }
            for r in passive_dns.get("passive_dns", [])[:10]
        ]

    url_list = raw.get("url_list", {})
    if url_list:
        out["url_list"] = [
            {
                "url": u.get("url"),
                "http_code": u.get("result", {}).get("urlworker", {}).get("http_code"),
            }
            for u in url_list.get("url_list", [])[:10]
        ]

    analysis = raw.get("analysis", {})
    if analysis:
        info = analysis.get("info", {}).get("results", {})
        out["file_type"] = info.get("file_type")
        out["file_size"] = info.get("filesize")

    return {k: v for k, v in out.items() if v is not None and v != [] and v != {}}
