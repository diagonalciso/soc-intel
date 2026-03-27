"""
Shodan InternetDB connector — enrichment.
Enriches IPv4 addresses with open ports, CPEs, hostnames, tags, and known CVEs
from the free Shodan InternetDB API. No authentication required.
Data freshness: approximately weekly update cycle.
"""
import uuid

from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult

_BASE_URL = "https://internetdb.shodan.io"
_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # uuid.NAMESPACE_URL


def _stix_id(type_: str, key: str) -> str:
    return f"{type_}--{uuid.uuid5(_NAMESPACE, f'shodan-internetdb:{type_}:{key}')}"


class ShodanInternetDBConnector(BaseConnector):
    def __init__(self):
        super().__init__(ConnectorConfig(
            name="shodan-internetdb",
            display_name="Shodan InternetDB",
            connector_type="enrichment",
            description=(
                "Enriches IP addresses with open ports, CPEs, hostnames, tags, and "
                "known CVEs via the free Shodan InternetDB API (~weekly refresh)."
            ),
        ))

    async def run(self) -> IngestResult:
        # Enrichment connectors are called on-demand via enrich_ip()
        return IngestResult(
            messages=["Shodan InternetDB is an enrichment connector — call enrich_ip() directly"]
        )

    async def enrich_ip(self, ip: str) -> list[dict]:
        """
        Enrich an IPv4 address using Shodan InternetDB.
        Returns a list of STIX objects, or an empty list if no data is available.
        """
        try:
            resp = await self.http.get(f"{_BASE_URL}/{ip}")
        except Exception as e:
            self.logger.error(f"Shodan InternetDB enrich {ip}: request error: {e}")
            return []

        if resp.status_code == 404:
            self.logger.info(f"Shodan InternetDB: no data for {ip}")
            return []

        try:
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            self.logger.error(f"Shodan InternetDB enrich {ip}: response error: {e}")
            return []

        ports: list[int] = data.get("ports", []) or []
        cpes: list[str] = data.get("cpes", []) or []
        hostnames: list[str] = data.get("hostnames", []) or []
        tags: list[str] = data.get("tags", []) or []
        vulns: list[str] = data.get("vulns", []) or []

        stix_objects: list[dict] = []

        # IPv4-addr SCO with enrichment properties
        ip_id = _stix_id("ipv4-addr", ip)
        ip_obj: dict = {
            "type": "ipv4-addr",
            "id": ip_id,
            "value": ip,
            "x_clawint_source": "shodan-internetdb",
            "x_clawint_open_ports": ports,
            "x_clawint_tags": tags,
            "x_clawint_cpes": cpes,
        }
        stix_objects.append(ip_obj)

        # Vulnerability SDOs and relationships for each CVE
        for cve_id in vulns:
            vuln_id = _stix_id("vulnerability", cve_id)
            vuln_obj: dict = {
                "type": "vulnerability",
                "id": vuln_id,
                "name": cve_id,
                "external_references": [
                    {
                        "source_name": "cve",
                        "external_id": cve_id,
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    }
                ],
                "x_clawint_source": "shodan-internetdb",
            }
            stix_objects.append(vuln_obj)

            # ipv4-addr → related-to → vulnerability
            stix_objects.append({
                "type": "relationship",
                "id": _stix_id("relationship", f"{ip_id}-related-to-{vuln_id}"),
                "relationship_type": "related-to",
                "source_ref": ip_id,
                "target_ref": vuln_id,
                "x_clawint_source": "shodan-internetdb",
            })

        # Domain-name SCOs and relationships for each hostname
        for hostname in hostnames:
            domain_id = _stix_id("domain-name", hostname)
            domain_obj: dict = {
                "type": "domain-name",
                "id": domain_id,
                "value": hostname,
                "x_clawint_source": "shodan-internetdb",
            }
            stix_objects.append(domain_obj)

            # ipv4-addr → resolves-to → domain-name
            stix_objects.append({
                "type": "relationship",
                "id": _stix_id("relationship", f"{ip_id}-resolves-to-{domain_id}"),
                "relationship_type": "resolves-to",
                "source_ref": ip_id,
                "target_ref": domain_id,
                "x_clawint_source": "shodan-internetdb",
            })

        self.logger.info(
            f"Shodan InternetDB: enriched {ip} — "
            f"{len(ports)} ports, {len(vulns)} CVEs, {len(hostnames)} hostnames"
        )
        return stix_objects
