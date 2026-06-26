"""
CISA Known Exploited Vulnerabilities (KEV) connector — import.
Ingests CISA's authoritative list of actively exploited CVEs.
Free, no API key required.
"""
from datetime import datetime

from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult


class CISAKEVConnector(BaseConnector):
    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self):
        super().__init__(ConnectorConfig(
            name="cisa-kev",
            display_name="CISA Known Exploited Vulnerabilities",
            connector_type="import_external",
            description="Imports CISA's KEV catalog — CVEs confirmed actively exploited in the wild.",
            schedule="0 */12 * * *",  # every 12 hours
        ))

    async def run(self) -> IngestResult:
        self.logger.info("CISA KEV: fetching known exploited vulnerabilities...")
        result = IngestResult()

        try:
            resp = await self.http.get(self.KEV_URL)
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            self.logger.error(f"CISA KEV: fetch failed: {e}")
            result.errors += 1
            return result

        vulns = data.get("vulnerabilities", [])
        stix_objects = []

        for v in vulns:
            cve_id = v.get("cveID", "")
            vuln = {
                "type": "vulnerability",
                "name": cve_id,
                "description": v.get("shortDescription", ""),
                "labels": ["known-exploited", "cisa-kev"],
                "external_references": [
                    {"source_name": "cve", "external_id": cve_id},
                    {"source_name": "CISA KEV", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"},
                ],
                "x_clawint_source": "cisa-kev",
                "x_clawint_vendor_project": v.get("vendorProject", ""),
                "x_clawint_product": v.get("product", ""),
                "x_clawint_cisa_due_date": v.get("dueDate", ""),
                "x_clawint_ransomware_use": v.get("knownRansomwareCampaignUse", "Unknown"),
                "x_clawint_date_added": v.get("dateAdded", ""),
            }
            stix_objects.append(vuln)

            if len(stix_objects) >= 250:
                r = await self.push_to_platform(stix_objects)
                result.objects_created += r.objects_created
                result.errors += r.errors
                stix_objects = []

        if stix_objects:
            r = await self.push_to_platform(stix_objects)
            result.objects_created += r.objects_created
            result.errors += r.errors

        self.logger.info(f"CISA KEV: ingested {result.objects_created} vulnerabilities")
        return result
