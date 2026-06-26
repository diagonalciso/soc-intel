"""
AbuseIPDB connector — enrichment.
Enriches IPv4/IPv6 observables with community abuse reports.
"""
from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult
from app.config import get_settings

settings = get_settings()


class AbuseIPDBConnector(BaseConnector):
    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self):
        super().__init__(ConnectorConfig(
            name="abuseipdb",
            display_name="AbuseIPDB",
            connector_type="enrichment",
            description="Enriches IP addresses with AbuseIPDB community abuse reports and confidence scores.",
        ))

    async def run(self) -> IngestResult:
        # Enrichment connectors are called on-demand via enrich(), not scheduled
        return IngestResult(messages=["AbuseIPDB is an enrichment connector — call enrich() directly"])

    async def enrich_ip(self, ip: str) -> dict | None:
        if not settings.abuseipdb_api_key:
            self.logger.warning("AbuseIPDB: no API key configured")
            return None

        try:
            resp = await self.http.get(
                f"{self.BASE_URL}/check",
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            return {
                "abuseipdb_score": data.get("abuseConfidenceScore"),
                "total_reports": data.get("totalReports"),
                "country_code": data.get("countryCode"),
                "isp": data.get("isp"),
                "usage_type": data.get("usageType"),
                "is_tor": data.get("isTor"),
                "is_public": data.get("isPublic"),
                "last_reported": data.get("lastReportedAt"),
            }
        except Exception as e:
            self.logger.error(f"AbuseIPDB enrich {ip}: {e}")
            return None
