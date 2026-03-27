"""
Criminal IP connector — enrichment.
Enriches IP addresses with Criminal IP threat intelligence
(alternative to Shodan/AbuseIPDB for IP context).
Requires CRIMINAL_IP_API_KEY.
"""
from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult
from app.config import get_settings

settings = get_settings()

BASE_URL = "https://api.criminalip.io/v1"


class CriminalIPConnector(BaseConnector):

    def __init__(self):
        super().__init__(ConnectorConfig(
            name="criminal-ip",
            display_name="Criminal IP",
            connector_type="enrichment",
            description=(
                "Enriches IP addresses with Criminal IP threat intelligence: "
                "risk score, open ports, ASN, VPN/proxy/Tor detection."
            ),
        ))

    async def run(self) -> IngestResult:
        return IngestResult(messages=["Criminal IP is an enrichment connector — call enrich_ip() directly"])

    async def enrich_ip(self, ip: str) -> dict | None:
        if not settings.criminal_ip_api_key:
            self.logger.warning("Criminal IP: no API key configured")
            return None

        try:
            resp = await self.http.get(
                f"{BASE_URL}/ip/summary",
                params={"ip": ip},
                headers={"Api-Key": settings.criminal_ip_api_key},
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            self.logger.error(f"Criminal IP enrich {ip}: {e}")
            return None

        if data.get("status") != 200:
            self.logger.warning(f"Criminal IP: API error for {ip}: {data.get('message', '')}")
            return None

        return {
            "criminal_ip_score": data.get("inbound_score") or data.get("score"),
            "criminal_ip_grade": data.get("score_grade") or _grade(data.get("inbound_score", 0)),
            "country_code": data.get("country_code"),
            "city": data.get("city"),
            "asn": data.get("as_no"),
            "as_name": data.get("as_name"),
            "is_vpn": bool(data.get("is_vpn")),
            "is_tor": bool(data.get("is_tor")),
            "is_proxy": bool(data.get("is_proxy")),
            "is_hosting": bool(data.get("is_hosting")),
            "is_scanner": bool(data.get("is_scanner")),
            "open_ports_count": data.get("open_port_count") or 0,
            "vulnerability_count": data.get("vulnerability_count") or 0,
        }

    async def enrich_domain(self, domain: str) -> dict | None:
        if not settings.criminal_ip_api_key:
            return None

        try:
            resp = await self.http.get(
                f"{BASE_URL}/domain/summary",
                params={"query": domain},
                headers={"Api-Key": settings.criminal_ip_api_key},
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            self.logger.error(f"Criminal IP enrich domain {domain}: {e}")
            return None

        return {
            "criminal_ip_score": data.get("inbound_score"),
            "criminal_ip_grade": _grade(data.get("inbound_score", 0)),
            "registrar": data.get("registrar"),
            "created_date": data.get("create_date"),
            "ip_count": data.get("ip_count") or 0,
        }


def _grade(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "dangerous"
    if score >= 40:
        return "moderate"
    if score >= 10:
        return "low"
    return "safe"
