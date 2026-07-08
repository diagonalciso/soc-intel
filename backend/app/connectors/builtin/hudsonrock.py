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

        # Community endpoint returns `employees`/`users` as int COUNTS; the paid
        # Cavalier endpoint returns them as record LISTS. Handle both.
        employees = data.get("employees")
        users = data.get("users")
        emp_list = employees if isinstance(employees, list) else []
        usr_list = users if isinstance(users, list) else []

        total_employees = data.get("total_corporate_credentials")
        if total_employees is None:
            total_employees = employees if isinstance(employees, int) else len(emp_list)
        total_users = data.get("total_user_credentials")
        if total_users is None:
            total_users = users if isinstance(users, int) else len(usr_list)

        if not total_employees and not total_users:
            return {"hudsonrock_exposed": False, "domain": domain}

        # Extract malware families: community gives a `stealerFamilies` dict
        # (family -> count); paid gives per-record malware fields.
        malware_families: list[str] = []
        sf = data.get("stealerFamilies")
        if isinstance(sf, dict):
            malware_families = [k for k in sf.keys() if k.lower() != "total"]
        else:
            for emp in emp_list[:20]:
                mf = emp.get("malware_path") or emp.get("malware_family") or ""
                if mf and mf not in malware_families:
                    malware_families.append(mf)

        return {
            "hudsonrock_exposed": True,
            "domain": domain,
            "corporate_credentials_exposed": total_employees,
            "user_credentials_exposed": total_users,
            "third_parties_exposed": data.get("third_parties"),
            "last_employee_compromised": data.get("last_employee_compromised"),
            "last_user_compromised": data.get("last_user_compromised"),
            "malware_families": malware_families[:5],
            "sample_employees": [
                {
                    "username": emp.get("username", ""),
                    "malware": emp.get("malware_path") or emp.get("malware_family") or "",
                    "date_compromised": emp.get("date_uploaded") or emp.get("date_compromised") or "",
                }
                for emp in emp_list[:5]
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
                # Community endpoint is search-by-email (param `email`), not search-by-username.
                resp = await self.http.get(
                    f"{COMMUNITY_BASE}/search-by-email",
                    params={"email": email},
                )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            self.logger.error(f"HudsonRock enrich email {email}: {e}")
            return None

        # Community: {message, stealers:[...], total_corporate_services, total_user_services}
        # Paid:      {credentials:[...], total}
        stealers = data.get("credentials")
        if not isinstance(stealers, list):
            stealers = data.get("stealers") or []
        total = data.get("total")
        if total is None:
            total = (data.get("total_corporate_services", 0) or 0) + \
                    (data.get("total_user_services", 0) or 0)
        if not total and stealers:
            total = len(stealers)

        if not total:
            return {"hudsonrock_exposed": False, "email": email}

        malware_families = list({
            c.get("stealer_family") or c.get("malware_path") or c.get("malware_family") or ""
            for c in stealers if isinstance(c, dict) and
            (c.get("stealer_family") or c.get("malware_path") or c.get("malware_family"))
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
                    "malware": (c.get("stealer_family") or c.get("malware_path")
                                or c.get("malware_family") or ""),
                    "date_compromised": c.get("date_uploaded") or c.get("date_compromised") or "",
                }
                for c in stealers[:5] if isinstance(c, dict)
            ],
        }
