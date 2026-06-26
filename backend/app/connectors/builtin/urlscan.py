"""
URLScan.io URL Intelligence connector — import.
Periodically fetches confirmed malicious URLs from the URLScan.io search API.
Requires URLSCAN_API_KEY — skipped gracefully if not configured.
"""
import uuid

from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult
from app.config import get_settings

settings = get_settings()

_BASE_URL = "https://urlscan.io/api/v1/search/"
_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # uuid.NAMESPACE_URL
_MAX_PAGES = 3
_PAGE_SIZE = 100


def _stix_id(type_: str, key: str) -> str:
    return f"{type_}--{uuid.uuid5(_NAMESPACE, f'urlscan:{type_}:{key}')}"


class URLScanConnector(BaseConnector):
    def __init__(self):
        super().__init__(ConnectorConfig(
            name="urlscan-io",
            display_name="URLScan.io URL Intelligence",
            connector_type="import_external",
            description=(
                "Imports confirmed malicious URLs and associated domains/IPs "
                "from URLScan.io scan verdicts."
            ),
            schedule="0 */4 * * *",
            source_reliability=72,
        ))

    async def run(self) -> IngestResult:
        result = IngestResult()

        api_key = settings.urlscan_api_key
        if not api_key:
            self.logger.warning("URLScan.io: URLSCAN_API_KEY not set — skipping run")
            result.messages.append("URLScan.io skipped: no API key configured")
            return result

        self.logger.info("URLScan.io: fetching malicious URL verdicts")
        headers = {
            "api-key": api_key,
            "Content-Type": "application/json",
        }

        params: dict = {
            "q": "verdicts.malicious:true",
            "size": _PAGE_SIZE,
        }

        stix_objects: list[dict] = []
        pages_fetched = 0

        while pages_fetched < _MAX_PAGES:
            try:
                resp = await self.http.get(_BASE_URL, params=params, headers=headers)

                # Respect rate limit advisory header
                rate_reset = resp.headers.get("X-Rate-Limit-Reset-After", "0")
                try:
                    if int(rate_reset) > 0:
                        self.logger.warning(
                            f"URLScan.io: rate limit advisory — reset after {rate_reset}s"
                        )
                except ValueError:
                    pass

                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                self.logger.error(f"URLScan.io: request failed (page {pages_fetched + 1}): {e}")
                result.errors += 1
                break

            results = data.get("results", [])
            if not results:
                break

            for scan in results:
                page = scan.get("page", {})
                task = scan.get("task", {})
                verdicts = scan.get("verdicts", {})

                url = task.get("url", "")
                domain = page.get("domain", "")
                ip = page.get("ip", "")

                if not url:
                    continue

                # Confidence from overall verdict score (0-100 → 0-100)
                overall = verdicts.get("overall", {})
                confidence = int(overall.get("score", 50))
                # Clamp to valid STIX range
                confidence = max(0, min(100, confidence))

                # Indicator SDO for the URL
                indicator_id = _stix_id("indicator", url)
                indicator: dict = {
                    "type": "indicator",
                    "id": indicator_id,
                    "name": f"Malicious URL: {url[:120]}",
                    "pattern": f"[url:value = '{url}']",
                    "pattern_type": "stix",
                    "labels": ["malicious-activity"],
                    "confidence": confidence,
                    "x_clawint_source": "urlscan-io",
                    "x_clawint_scan_id": scan.get("_id", ""),
                }
                stix_objects.append(indicator)

                # Domain-name SCO
                if domain:
                    domain_id = _stix_id("domain-name", domain)
                    domain_obj: dict = {
                        "type": "domain-name",
                        "id": domain_id,
                        "value": domain,
                        "x_clawint_source": "urlscan-io",
                    }
                    stix_objects.append(domain_obj)

                    # indicator → indicates → domain-name
                    stix_objects.append({
                        "type": "relationship",
                        "id": _stix_id("relationship", f"{indicator_id}-indicates-{domain_id}"),
                        "relationship_type": "indicates",
                        "source_ref": indicator_id,
                        "target_ref": domain_id,
                        "x_clawint_source": "urlscan-io",
                    })

                # IPv4-addr SCO
                if ip:
                    ip_id = _stix_id("ipv4-addr", ip)
                    ip_obj: dict = {
                        "type": "ipv4-addr",
                        "id": ip_id,
                        "value": ip,
                        "x_clawint_source": "urlscan-io",
                    }
                    stix_objects.append(ip_obj)

                    # indicator → indicates → ipv4-addr
                    stix_objects.append({
                        "type": "relationship",
                        "id": _stix_id("relationship", f"{indicator_id}-indicates-{ip_id}"),
                        "relationship_type": "indicates",
                        "source_ref": indicator_id,
                        "target_ref": ip_id,
                        "x_clawint_source": "urlscan-io",
                    })

            pages_fetched += 1

            # Check for next page via sort cursor
            has_more = data.get("has_more", False)
            if not has_more or pages_fetched >= _MAX_PAGES:
                break

            # Use the sort value of the last result as cursor for next page
            last_result = results[-1]
            sort_value = last_result.get("sort")
            if sort_value:
                params["search_after"] = sort_value
            else:
                break

        if stix_objects:
            r = await self.push_to_platform(stix_objects)
            result.objects_created += r.objects_created
            result.errors += r.errors

        self.logger.info(
            f"URLScan.io: done — {result.objects_created} objects created "
            f"from {pages_fetched} page(s), {result.errors} errors"
        )
        return result
