"""
NVD + EPSS connector — import.
Ingests CVE vulnerability data from NIST NVD (API v2) enriched with
FIRST.org EPSS exploitation probability scores.

- NVD API v2: https://nvd.nist.gov/developers/vulnerabilities
- EPSS API:   https://www.first.org/epss/api

No API key required for NVD (optional key boosts rate limits).
Set NVD_API_KEY in .env for higher throughput.
"""
import asyncio
import re
from datetime import datetime, timedelta, timezone

from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult
from app.db.opensearch import get_opensearch, STIX_INDEX

NVD_URL   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL  = "https://api.first.org/data/v1/epss"

# On first run fetch last 120 days; on subsequent runs fetch last 8 days
INITIAL_LOOKBACK_DAYS = 120
DELTA_LOOKBACK_DAYS   = 8

# NVD paginates at 2000 results per page
NVD_PAGE_SIZE = 2000

# EPSS batch size (max CVEs per request)
EPSS_BATCH = 100


class NVDEPSSConnector(BaseConnector):
    def __init__(self):
        super().__init__(ConnectorConfig(
            name="nvd-epss",
            display_name="NVD + EPSS (Vulnerabilities)",
            connector_type="import_external",
            description=(
                "CVE vulnerability data from NIST NVD (CVSS v3) "
                "enriched with FIRST.org EPSS exploitation probability scores."
            ),
            schedule="0 4 * * *",  # daily at 04:00
        ))
        self._last_run: datetime | None = None

    async def run(self) -> IngestResult:
        result = IngestResult()

        lookback = DELTA_LOOKBACK_DAYS if self._last_run else INITIAL_LOOKBACK_DAYS
        end_dt   = datetime.now(timezone.utc)
        start_dt = end_dt - timedelta(days=lookback)

        self.logger.info(
            f"NVD+EPSS: fetching CVEs modified since {start_dt.strftime('%Y-%m-%d')}..."
        )

        cves = await self._fetch_nvd(start_dt, end_dt)
        if not cves:
            self.logger.info("NVD+EPSS: no CVEs returned")
            return result

        self.logger.info(f"NVD+EPSS: fetched {len(cves)} CVEs, enriching with EPSS...")
        epss_map = await self._fetch_epss([c["id"] for c in cves])

        client = get_opensearch()
        bulk   = []

        for cve in cves:
            cve_id  = cve.get("id", "")
            epss    = epss_map.get(cve_id, {})

            doc_id  = f"vulnerability--nvd-{cve_id.lower()}"
            doc     = self._build_stix(cve_id, cve, epss)

            bulk.append({"index": {"_index": STIX_INDEX, "_id": doc_id}})
            bulk.append(doc)
            result.objects_created += 1

            # Flush every 500
            if len(bulk) >= 1000:
                await self._flush(client, bulk, result)
                bulk.clear()

        if bulk:
            await self._flush(client, bulk, result)

        self._last_run = end_dt
        self.logger.info(
            f"NVD+EPSS: {result.objects_created} vulnerabilities ingested, {result.errors} errors"
        )
        return result

    # ── NVD fetching ────────────────────────────────────────────

    async def _fetch_nvd(self, start_dt: datetime, end_dt: datetime) -> list[dict]:
        """Fetch all CVEs in the date range, paginating through NVD results."""
        start_s = start_dt.strftime("%Y-%m-%dT%H:%M:%S.000")
        end_s   = end_dt.strftime("%Y-%m-%dT%H:%M:%S.000")

        params = {
            "lastModStartDate": start_s,
            "lastModEndDate":   end_s,
            "resultsPerPage":   NVD_PAGE_SIZE,
            "startIndex":       0,
        }

        headers = {"User-Agent": "SOCINT/1.0 CTI Platform (research)"}
        from app.config import get_settings
        settings = get_settings()
        if getattr(settings, "nvd_api_key", None):
            headers["apiKey"] = settings.nvd_api_key

        all_cves: list[dict] = []
        total = None

        while True:
            try:
                resp = await self.http.get(NVD_URL, params=params, headers=headers)
                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                self.logger.error(f"NVD+EPSS: NVD fetch error at index {params['startIndex']}: {e}")
                break

            if total is None:
                total = data.get("totalResults", 0)

            for vuln in data.get("vulnerabilities", []):
                cve_data = vuln.get("cve", {})
                cve_id   = cve_data.get("id", "")
                if not cve_id:
                    continue
                all_cves.append(self._parse_cve(cve_data))

            params["startIndex"] += NVD_PAGE_SIZE
            if params["startIndex"] >= total:
                break

            # NVD rate limit: 5 req/30s without key, 50/30s with key
            await asyncio.sleep(0.7 if getattr(settings, "nvd_api_key", None) else 6.5)

        return all_cves

    def _parse_cve(self, cve: dict) -> dict:
        cve_id      = cve.get("id", "")
        description = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                description = d.get("value", "")
                break

        # CVSS v3 scoring
        cvss_score      = None
        cvss_severity   = None
        cvss_vector     = None
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30"):
            entries = metrics.get(key, [])
            if entries:
                m = entries[0].get("cvssData", {})
                cvss_score    = m.get("baseScore")
                cvss_severity = m.get("baseSeverity", "").lower()
                cvss_vector   = m.get("vectorString", "")
                break

        # CWE
        cwes = []
        for w in cve.get("weaknesses", []):
            for wd in w.get("description", []):
                if wd.get("lang") == "en" and wd.get("value", "").startswith("CWE-"):
                    cwes.append(wd["value"])

        # Affected CPEs (first 10)
        cpes = []
        for cfg in (cve.get("configurations") or []):
            for node in cfg.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable") and match.get("criteria"):
                        cpes.append(match["criteria"])
                        if len(cpes) >= 10:
                            break

        published   = cve.get("published", "")
        last_mod    = cve.get("lastModified", "")
        vuln_status = cve.get("vulnStatus", "")

        return {
            "id":           cve_id,
            "description":  description,
            "cvss_score":   cvss_score,
            "cvss_severity": cvss_severity,
            "cvss_vector":  cvss_vector,
            "cwes":         cwes,
            "cpes":         cpes[:10],
            "published":    published,
            "last_modified": last_mod,
            "vuln_status":  vuln_status,
        }

    # ── EPSS fetching ────────────────────────────────────────────

    async def _fetch_epss(self, cve_ids: list[str]) -> dict[str, dict]:
        """Fetch EPSS scores for a list of CVE IDs, batched."""
        result = {}
        for i in range(0, len(cve_ids), EPSS_BATCH):
            batch = cve_ids[i:i + EPSS_BATCH]
            try:
                resp = await self.http.get(
                    EPSS_URL,
                    params={"cve": ",".join(batch)},
                    headers={"User-Agent": "SOCINT/1.0 CTI Platform (research)"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get("data", []):
                        cve = item.get("cve", "")
                        if cve:
                            result[cve] = {
                                "epss_score":       float(item.get("epss", 0)),
                                "epss_percentile":  float(item.get("percentile", 0)),
                                "epss_date":        item.get("date", ""),
                            }
            except Exception as e:
                self.logger.warning(f"NVD+EPSS: EPSS batch error: {e}")
            await asyncio.sleep(0.1)
        return result

    # ── STIX object builder ──────────────────────────────────────

    def _build_stix(self, cve_id: str, cve: dict, epss: dict) -> dict:
        now = _now()
        doc = {
            "id":           f"vulnerability--nvd-{cve_id.lower()}",
            "type":         "vulnerability",
            "spec_version": "2.1",
            "created":      _iso(cve.get("published")) or now,
            "modified":     _iso(cve.get("last_modified")) or now,
            "name":         cve_id,
            "description":  cve.get("description", ""),
            "x_clawint_source": "nvd-epss",
            "external_references": [
                {
                    "source_name": "cve",
                    "external_id": cve_id,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                }
            ],
        }

        # CVSS
        if cve.get("cvss_score") is not None:
            doc["x_cvss_score"]    = cve["cvss_score"]
            doc["x_cvss_severity"] = cve.get("cvss_severity", "")
            doc["x_cvss_vector"]   = cve.get("cvss_vector", "")

        # CWE
        if cve.get("cwes"):
            doc["x_cwes"] = cve["cwes"]

        # CPE
        if cve.get("cpes"):
            doc["x_affected_cpes"] = cve["cpes"]

        # EPSS
        if epss:
            doc["x_epss_score"]      = epss.get("epss_score", 0.0)
            doc["x_epss_percentile"] = epss.get("epss_percentile", 0.0)
            doc["x_epss_date"]       = epss.get("epss_date", "")

        # Confidence from CVSS (scaled to 0-100) + EPSS boost
        confidence = 50
        if cve.get("cvss_score"):
            confidence = int((cve["cvss_score"] / 10.0) * 100)
        if epss.get("epss_score", 0) > 0.05:
            confidence = min(100, confidence + 15)
        doc["confidence"] = confidence

        # Labels
        labels = []
        sev = cve.get("cvss_severity", "")
        if sev:
            labels.append(f"cvss:{sev}")
        if epss.get("epss_score", 0) > 0.05:
            labels.append("actively-exploited")
        if epss.get("epss_percentile", 0) > 0.9:
            labels.append("top-10pct-exploitation-risk")
        if labels:
            doc["labels"] = labels

        return doc

    async def _flush(self, client, bulk: list, result: IngestResult):
        try:
            resp = await client.bulk(body=bulk, refresh=False)
            errors = sum(
                1 for item in resp["items"] if item.get("index", {}).get("error")
            )
            result.errors         += errors
            result.objects_created -= errors
        except Exception as e:
            self.logger.error(f"NVD+EPSS: OpenSearch bulk error: {e}")
            result.errors         += len(bulk) // 2
            result.objects_created -= len(bulk) // 2


def _iso(ts: str | None) -> str | None:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    except Exception:
        return None


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
