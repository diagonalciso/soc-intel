"""
GreyNoise connector — enrichment.
Tags IPs as internet background noise vs. targeted threats.
Free community tier or paid API.
"""
from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult
from app.config import get_settings

settings = get_settings()


class GreyNoiseConnector(BaseConnector):
    COMMUNITY_URL = "https://api.greynoise.io/v3/community"
    FULL_URL = "https://api.greynoise.io/v3/noise/context"

    def __init__(self):
        super().__init__(ConnectorConfig(
            name="greynoise",
            display_name="GreyNoise",
            connector_type="enrichment",
            description="Classifies IPs as internet background noise or targeted activity. Reduces alert fatigue.",
        ))

    async def run(self) -> IngestResult:
        return IngestResult(messages=["GreyNoise is an enrichment connector — call enrich_ip() directly"])

    async def enrich_ip(self, ip: str) -> dict | None:
        headers = {"Accept": "application/json"}
        if settings.greynoise_api_key:
            headers["key"] = settings.greynoise_api_key
            url = f"{self.FULL_URL}/{ip}"
        else:
            url = f"{self.COMMUNITY_URL}/{ip}"

        try:
            resp = await self.http.get(url, headers=headers)
            if resp.status_code == 404:
                return {"noise": False, "riot": False, "message": "IP not seen by GreyNoise"}
            resp.raise_for_status()
            data = resp.json()
            return {
                "noise": data.get("noise", False),
                "riot": data.get("riot", False),
                "classification": data.get("classification"),
                "name": data.get("name"),
                "link": data.get("link"),
                "last_seen": data.get("last_seen"),
                "tags": data.get("tags", []),
                "cve": data.get("cve", []),
            }
        except Exception as e:
            self.logger.error(f"GreyNoise enrich {ip}: {e}")
            return None
