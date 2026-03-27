"""
OSV.dev Supply Chain Vulnerabilities connector — import.
Fetches per-ecosystem vulnerability feeds from OSV.dev for high-value package ecosystems.
No authentication required.
"""
import uuid
from datetime import datetime, timedelta, timezone

from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult

# Ecosystems to fetch; these map directly to GCS feed paths
_ECOSYSTEMS = [
    "PyPI",
    "npm",
    "Go",
    "Maven",
    "RubyGems",
    "crates.io",
    "NuGet",
]

_FEED_BASE = "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.json"

# Only import vulnerabilities modified within the last 30 days
_LOOKBACK_DAYS = 30

_OSV_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # uuid.NAMESPACE_URL


def _osv_stix_id(osv_id: str) -> str:
    return f"vulnerability--{uuid.uuid5(_OSV_NAMESPACE, f'osv:{osv_id}')}"


class OSVConnector(BaseConnector):
    def __init__(self):
        super().__init__(ConnectorConfig(
            name="osv-dev",
            display_name="OSV.dev Supply Chain Vulnerabilities",
            connector_type="import_external",
            description=(
                "Imports supply chain vulnerability data from OSV.dev for major package "
                "ecosystems: PyPI, npm, Go, Maven, RubyGems, crates.io, NuGet."
            ),
            schedule="0 */6 * * *",
            source_reliability=85,
        ))

    async def run(self) -> IngestResult:
        self.logger.info("OSV.dev: starting vulnerability feed fetch")
        result = IngestResult()
        cutoff = datetime.now(timezone.utc) - timedelta(days=_LOOKBACK_DAYS)

        for ecosystem in _ECOSYSTEMS:
            url = _FEED_BASE.format(ecosystem=ecosystem)
            self.logger.info(f"OSV.dev: fetching {ecosystem} feed from {url}")
            try:
                resp = await self.http.get(url)
                resp.raise_for_status()
                feed = resp.json()
            except Exception as e:
                self.logger.error(f"OSV.dev: failed to fetch {ecosystem} feed: {e}")
                result.errors += 1
                continue

            vulns = feed.get("vulns", [])
            self.logger.info(f"OSV.dev: {ecosystem} — {len(vulns)} total entries")

            batch: list[dict] = []
            for v in vulns:
                modified_str = v.get("modified", "")
                if modified_str:
                    try:
                        modified_dt = datetime.fromisoformat(
                            modified_str.replace("Z", "+00:00")
                        )
                        if modified_dt < cutoff:
                            continue
                    except ValueError:
                        pass  # if we can't parse, include it

                osv_id = v.get("id", "")
                if not osv_id:
                    continue

                summary = v.get("summary", "") or v.get("details", "")[:500] if v.get("details") else ""

                # Build external references
                ext_refs = [
                    {
                        "source_name": "osv",
                        "url": f"https://osv.dev/vulnerability/{osv_id}",
                        "external_id": osv_id,
                    }
                ]

                # Add CVE cross-references from aliases
                aliases = v.get("aliases", []) or []
                cve_aliases = [a for a in aliases if a.startswith("CVE-")]
                for cve_id in cve_aliases:
                    ext_refs.append({
                        "source_name": "cve",
                        "external_id": cve_id,
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    })

                # Extract ecosystems from affected packages
                affected = v.get("affected", []) or []
                ecosystems_list = list({
                    pkg.get("package", {}).get("ecosystem", "")
                    for pkg in affected
                    if pkg.get("package", {}).get("ecosystem")
                })

                # Severity — pick first available
                severity_str = ""
                severity_list = v.get("severity", []) or []
                if severity_list:
                    severity_str = severity_list[0].get("score", "")

                vuln_obj: dict = {
                    "type": "vulnerability",
                    "id": _osv_stix_id(osv_id),
                    "name": osv_id,
                    "description": summary,
                    "external_references": ext_refs,
                    "x_clawint_source": "osv-dev",
                    "x_clawint_ecosystems": ecosystems_list,
                }
                if severity_str:
                    vuln_obj["x_clawint_severity"] = severity_str
                if aliases:
                    vuln_obj["x_clawint_aliases"] = aliases

                batch.append(vuln_obj)

                if len(batch) >= 250:
                    r = await self.push_to_platform(batch)
                    result.objects_created += r.objects_created
                    result.errors += r.errors
                    batch = []

            if batch:
                r = await self.push_to_platform(batch)
                result.objects_created += r.objects_created
                result.errors += r.errors

        self.logger.info(
            f"OSV.dev: done — {result.objects_created} created, {result.errors} errors"
        )
        return result
