"""
VirusTotal connector — enrichment.
Enriches files, URLs, domains, and IPs with VT reputation data.
"""
from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult
from app.config import get_settings

settings = get_settings()


class VirusTotalConnector(BaseConnector):
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self):
        super().__init__(ConnectorConfig(
            name="virustotal",
            display_name="VirusTotal",
            connector_type="enrichment",
            description="Enriches files, URLs, domains, and IPs with VirusTotal multi-AV reputation data.",
        ))

    @property
    def _headers(self) -> dict:
        return {"x-apikey": settings.virustotal_api_key, "Accept": "application/json"}

    async def run(self) -> IngestResult:
        return IngestResult(messages=["VirusTotal is an enrichment connector — call enrich_*() directly"])

    async def enrich_ip(self, ip: str) -> dict | None:
        return await self._get(f"/ip_addresses/{ip}")

    async def enrich_domain(self, domain: str) -> dict | None:
        return await self._get(f"/domains/{domain}")

    async def enrich_url(self, url: str) -> dict | None:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        return await self._get(f"/urls/{url_id}")

    async def enrich_hash(self, file_hash: str) -> dict | None:
        return await self._get(f"/files/{file_hash}")

    async def _get(self, path: str) -> dict | None:
        if not settings.virustotal_api_key:
            self.logger.warning("VirusTotal: no API key configured")
            return None
        try:
            resp = await self.http.get(f"{self.BASE_URL}{path}", headers=self._headers)
            if resp.status_code == 404:
                return {"found": False}
            resp.raise_for_status()
            data = resp.json().get("data", {})
            attrs = data.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "found": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": attrs.get("reputation"),
                "tags": attrs.get("tags", []),
                "last_analysis_date": attrs.get("last_analysis_date"),
                "link": f"https://www.virustotal.com/gui/{data.get('type', 'file')}/{data.get('id', '')}",
            }
        except Exception as e:
            self.logger.error(f"VirusTotal enrich {path}: {e}")
            return None
