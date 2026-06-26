"""
VulnCheck KEV (Extended) connector — import.
Ingests VulnCheck's extended Known Exploited Vulnerabilities index, which is a
superset of the CISA KEV catalog with additional exploited CVEs.
Requires VULNCHECK_API_KEY.
"""
import uuid

from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult
from app.config import get_settings

settings = get_settings()

_BASE_URL = "https://api.vulncheck.com/v3/index/vulncheck-kev"

# Use the same UUID5 namespace and deterministic key format as cisa_kev.py
# so that CVEs present in both catalogs resolve to the same STIX object ID
# and OpenSearch upserts rather than creates a duplicate.
_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # uuid.NAMESPACE_URL


def _vuln_stix_id(cve_id: str) -> str:
    """Deterministic vulnerability STIX ID — matches cisa_kev.py dedup key."""
    return f"vulnerability--{uuid.uuid5(_NAMESPACE, f'osv:{cve_id}')}"


class VulnCheckKEVConnector(BaseConnector):
    def __init__(self):
        super().__init__(ConnectorConfig(
            name="vulncheck-kev",
            display_name="VulnCheck KEV (Extended)",
            connector_type="import_external",
            description=(
                "Imports VulnCheck's extended Known Exploited Vulnerabilities index — "
                "a superset of CISA KEV with additional actively exploited CVEs."
            ),
            schedule="0 */12 * * *",
            source_reliability=90,
        ))

    async def run(self) -> IngestResult:
        result = IngestResult()

        api_key = settings.vulncheck_api_key
        if not api_key:
            self.logger.warning("VulnCheck KEV: VULNCHECK_API_KEY not set — skipping run")
            result.messages.append("VulnCheck KEV skipped: no API key configured")
            return result

        self.logger.info("VulnCheck KEV: fetching extended KEV index")
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
        }

        stix_objects: list[dict] = []
        cursor: str | None = None
        pages = 0

        while True:
            params: dict = {}
            if cursor:
                params["cursor"] = cursor

            try:
                resp = await self.http.get(_BASE_URL, params=params, headers=headers)
                resp.raise_for_status()
                payload = resp.json()
            except Exception as e:
                self.logger.error(f"VulnCheck KEV: request failed (page {pages + 1}): {e}")
                result.errors += 1
                break

            data = payload.get("data", [])
            meta = payload.get("_meta", {})
            pages += 1

            for entry in data:
                cve_id = entry.get("cve", "") or entry.get("cveID", "")
                if not cve_id:
                    continue

                description = (
                    entry.get("shortDescription", "")
                    or entry.get("description", "")
                    or ""
                )

                # Determine if also on CISA KEV (cisaAdded field present and non-empty)
                is_cisa_kev = bool(entry.get("cisaAdded"))

                ext_refs = [
                    {
                        "source_name": "cve",
                        "external_id": cve_id,
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    },
                    {
                        "source_name": "vulncheck",
                        "url": f"https://vulncheck.com/browse/vulncheck-kev?cve={cve_id}",
                    },
                ]
                if is_cisa_kev:
                    ext_refs.append({
                        "source_name": "CISA KEV",
                        "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                    })

                vuln_obj: dict = {
                    "type": "vulnerability",
                    "id": _vuln_stix_id(cve_id),
                    "name": cve_id,
                    "description": description,
                    "labels": ["known-exploited", "vulncheck-kev"],
                    "external_references": ext_refs,
                    "x_clawint_source": "vulncheck-kev",
                    "x_clawint_vulncheck_kev": True,
                    "x_clawint_cisa_kev": is_cisa_kev,
                }

                # Surface additional VulnCheck fields if present
                if entry.get("dateAdded"):
                    vuln_obj["x_clawint_date_added"] = entry["dateAdded"]
                if entry.get("knownRansomwareCampaignUse"):
                    vuln_obj["x_clawint_ransomware_use"] = entry["knownRansomwareCampaignUse"]
                if entry.get("vendorProject"):
                    vuln_obj["x_clawint_vendor_project"] = entry["vendorProject"]
                if entry.get("product"):
                    vuln_obj["x_clawint_product"] = entry["product"]

                stix_objects.append(vuln_obj)

                if len(stix_objects) >= 250:
                    r = await self.push_to_platform(stix_objects)
                    result.objects_created += r.objects_created
                    result.errors += r.errors
                    stix_objects = []

            # Pagination
            next_cursor = meta.get("next_cursor")
            if not next_cursor:
                break
            cursor = next_cursor

        if stix_objects:
            r = await self.push_to_platform(stix_objects)
            result.objects_created += r.objects_created
            result.errors += r.errors

        self.logger.info(
            f"VulnCheck KEV: done — {result.objects_created} created "
            f"over {pages} page(s), {result.errors} errors"
        )
        return result
