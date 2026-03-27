"""
crt.sh Certificate Transparency connector — enrichment.
Enriches domains with subdomains and SANs discovered via Certificate Transparency logs.
No authentication required.
"""
import uuid

import httpx

from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult

_BASE_URL = "https://crt.sh/"
_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # uuid.NAMESPACE_URL
_REQUEST_TIMEOUT = 15.0


def _stix_id(type_: str, key: str) -> str:
    return f"{type_}--{uuid.uuid5(_NAMESPACE, f'crtsh:{type_}:{key}')}"


class CrtShConnector(BaseConnector):
    def __init__(self):
        super().__init__(ConnectorConfig(
            name="crtsh",
            display_name="crt.sh Certificate Transparency",
            connector_type="enrichment",
            description=(
                "Enriches domains with subdomains and SANs discovered via "
                "crt.sh Certificate Transparency log search."
            ),
        ))

    async def run(self) -> IngestResult:
        # Enrichment connectors are called on-demand via enrich_domain()
        return IngestResult(
            messages=["crt.sh is an enrichment connector — call enrich_domain() directly"]
        )

    async def enrich_domain(self, domain: str) -> list[dict]:
        """
        Discover subdomains and SANs for the given domain via crt.sh CT logs.
        Returns a list of STIX objects (domain-name SCOs + relationships).
        """
        try:
            resp = await self.http.get(
                _BASE_URL,
                params={"q": domain, "output": "json"},
                timeout=_REQUEST_TIMEOUT,
            )
            resp.raise_for_status()

            # Guard against empty response bodies
            body = resp.text.strip()
            if not body:
                self.logger.info(f"crt.sh: empty response for domain {domain}")
                return []

            cert_records = resp.json()
        except httpx.TimeoutException:
            self.logger.warning(f"crt.sh: request timed out for domain {domain} (>{_REQUEST_TIMEOUT}s)")
            return []
        except Exception as e:
            self.logger.error(f"crt.sh enrich {domain}: {e}")
            return []

        if not cert_records:
            self.logger.info(f"crt.sh: no certificate records for domain {domain}")
            return []

        # Collect unique subdomains from name_value fields
        # name_value can contain multiple SANs separated by newlines
        seen_subdomains: set[str] = set()
        issuer_cns: set[str] = set()

        for record in cert_records:
            # Collect issuer CN for summary
            issuer_name = record.get("issuer_name", "") or ""
            # Extract CN= portion from issuer DN
            for part in issuer_name.split(","):
                part = part.strip()
                if part.upper().startswith("CN="):
                    issuer_cns.add(part[3:].strip())
                    break

            name_value = record.get("name_value", "") or ""
            for san in name_value.splitlines():
                san = san.strip().lower()
                if not san or san == domain.lower():
                    continue
                # Skip wildcard entries (they aren't valid FQDN SCO values)
                if san.startswith("*."):
                    san = san[2:]  # strip wildcard prefix, keep the base
                if san:
                    seen_subdomains.add(san)

        stix_objects: list[dict] = []

        # Queried domain object with cert summary properties
        queried_domain_id = _stix_id("domain-name", domain.lower())
        queried_domain_obj: dict = {
            "type": "domain-name",
            "id": queried_domain_id,
            "value": domain.lower(),
            "x_clawint_source": "crtsh",
            "x_clawint_cert_count": len(cert_records),
            "x_clawint_cert_issuers": sorted(issuer_cns),
        }
        stix_objects.append(queried_domain_obj)

        # Subdomain SCOs and relationships
        for subdomain in sorted(seen_subdomains):
            sub_id = _stix_id("domain-name", subdomain)
            sub_obj: dict = {
                "type": "domain-name",
                "id": sub_id,
                "value": subdomain,
                "x_clawint_source": "crtsh",
            }
            stix_objects.append(sub_obj)

            # queried domain → related-to → subdomain
            stix_objects.append({
                "type": "relationship",
                "id": _stix_id("relationship", f"{queried_domain_id}-related-to-{sub_id}"),
                "relationship_type": "related-to",
                "source_ref": queried_domain_id,
                "target_ref": sub_id,
                "x_clawint_source": "crtsh",
            })

        self.logger.info(
            f"crt.sh: domain {domain} — {len(cert_records)} certs, "
            f"{len(seen_subdomains)} unique subdomains/SANs discovered"
        )
        return stix_objects
