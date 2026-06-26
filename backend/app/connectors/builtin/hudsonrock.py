"""
Hudson Rock connector — enrichment.
Enriches domains/emails with infostealer credential exposure data
via the Hudson Rock Cavalier community API.
Also supports Cavalier paid API with HUDSONROCK_API_KEY.
"""
from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult
from app.config import get_settings

settings = get_settings()

# Community (free, no key) endpoint
COMMUNITY_BASE = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"
# Paid Cavalier API endpoint
CAVALIER_BASE = "https://cavalier.hudsonrock.com/api/json/v2"


class HudsonRockConnector(BaseConnector):

    def __init__(self):
        super().__init__(ConnectorConfig(
            name="hudsonrock",
            display_name="Hudson Rock (Cavalier)",
            connector_type="enrichment",
            description=(
                "Enriches domains/emails with infostealer credential exposure data "
                "from Hudson Rock Cavalier intelligence."
            ),
        ))

    async def run(self) -> IngestResult:
        return IngestResult(messages=["Hudson Rock is an enrichment connector — call enrich() directly"])

    async def enrich_domain(self, domain: str) -> dict | None:
        """
        Look up infostealer credential exposures for a domain.
        Uses the free community endpoint if no API key is configured.
        """
        try:
            if settings.hudsonrock_api_key:
                resp = await self.http.get(
                    f"{CAVALIER_BASE}/search-by-domain",
                    params={"domain": domain},
                    headers={"Authorization": f"Bearer {settings.hudsonrock_api_key}"},
                )
            else:
                resp = await self.http.get(
                    f"{COMMUNITY_BASE}/search-by-domain",
                    params={"domain": domain},
                )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            self.logger.error(f"HudsonRock enrich domain {domain}: {e}")
            return None

        employees = data.get("employees") or []
        users = data.get("users") or []
        total_employees = data.get("total_corporate_credentials") or len(employees)
        total_users = data.get("total_user_credentials") or len(users)

        if total_employees == 0 and total_users == 0:
            return {"hudsonrock_exposed": False, "domain": domain}

        # Extract malware families from exposures
        malware_families: list[str] = []
        for emp in employees[:20]:
            mf = emp.get("malware_path") or emp.get("malware_family") or ""
            if mf and mf not in malware_families:
                malware_families.append(mf)

        return {
            "hudsonrock_exposed": True,
            "domain": domain,
            "corporate_credentials_exposed": total_employees,
            "user_credentials_exposed": total_users,
            "malware_families": malware_families[:5],
            "sample_employees": [
                {
                    "username": emp.get("username", ""),
                    "malware": emp.get("malware_path") or emp.get("malware_family") or "",
                    "date_compromised": emp.get("date_uploaded") or emp.get("date_compromised") or "",
                }
                for emp in employees[:5]
            ],
        }

    async def enrich_email(self, email: str) -> dict | None:
        """Look up infostealer credential exposures for an email address."""
        try:
            if settings.hudsonrock_api_key:
                resp = await self.http.get(
                    f"{CAVALIER_BASE}/search-by-username",
                    params={"username": email},
                    headers={"Authorization": f"Bearer {settings.hudsonrock_api_key}"},
                )
            else:
                resp = await self.http.get(
                    f"{COMMUNITY_BASE}/search-by-username",
                    params={"username": email},
                )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            self.logger.error(f"HudsonRock enrich email {email}: {e}")
            return None

        credentials = data.get("credentials") or []
        total = data.get("total") or len(credentials)

        if total == 0:
            return {"hudsonrock_exposed": False, "email": email}

        malware_families = list({
            c.get("malware_path") or c.get("malware_family") or ""
            for c in credentials if c.get("malware_path") or c.get("malware_family")
        })

        return {
            "hudsonrock_exposed": True,
            "email": email,
            "credentials_exposed": total,
            "malware_families": malware_families[:5],
            "sample_credentials": [
                {
                    "url": c.get("url", ""),
                    "username": c.get("username", ""),
                    "malware": c.get("malware_path") or c.get("malware_family") or "",
                    "date_compromised": c.get("date_uploaded") or c.get("date_compromised") or "",
                }
                for c in credentials[:5]
            ],
        }
