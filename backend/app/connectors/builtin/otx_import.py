"""
AlienVault OTX (Open Threat Exchange) import connector.
Ingests subscribed pulses as STIX indicators with threat actor,
malware family, and ATT&CK metadata from pulse tags.
Requires OTX_API_KEY.
"""
from datetime import datetime, timezone, timedelta

from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult
from app.config import get_settings

settings = get_settings()

OTX_BASE = "https://otx.alienvault.com/api/v1"

_TYPE_MAP = {
    "IPv4":           lambda v: f"[ipv4-addr:value = '{v}']",
    "IPv6":           lambda v: f"[ipv6-addr:value = '{v}']",
    "domain":         lambda v: f"[domain-name:value = '{v}']",
    "hostname":       lambda v: f"[domain-name:value = '{v}']",
    "URL":            lambda v: f"[url:value = '{v.replace(chr(39), '%27')}']",
    "FileHash-MD5":   lambda v: f"[file:hashes.MD5 = '{v}']",
    "FileHash-SHA1":  lambda v: f"[file:hashes.'SHA-1' = '{v}']",
    "FileHash-SHA256":lambda v: f"[file:hashes.'SHA-256' = '{v}']",
    "CIDR":           lambda v: f"[ipv4-addr:value = '{v}']",
    "email":          lambda v: f"[email-addr:value = '{v}']",
}

_TLP_MAP = {
    "white": "TLP:WHITE",
    "green": "TLP:GREEN",
    "amber": "TLP:AMBER",
    "red":   "TLP:RED",
}


class OTXImportConnector(BaseConnector):

    def __init__(self):
        super().__init__(ConnectorConfig(
            name="otx",
            display_name="AlienVault OTX",
            connector_type="import_external",
            description=(
                "Imports subscribed pulses from AlienVault OTX (Open Threat Exchange). "
                "Ingests IOC indicators with threat actor, malware, and ATT&CK metadata. "
                "Requires OTX_API_KEY."
            ),
            schedule="0 */2 * * *",  # every 2 hours
        ))

    @property
    def _headers(self) -> dict:
        return {
            "X-OTX-API-KEY": settings.otx_api_key,
            "Accept": "application/json",
        }

    async def run(self) -> IngestResult:
        if not settings.otx_api_key:
            self.logger.warning("OTX: no API key configured (OTX_API_KEY)")
            return IngestResult(errors=1)

        self.logger.info("OTX: fetching subscribed pulses...")
        result = IngestResult()

        # Pull pulses modified in the last 7 days (safe for incremental polling;
        # OpenSearch upserts deduplicate on pulse ID so overlapping windows are fine)
        since = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S")

        page = 1
        total_pulses = 0

        while True:
            try:
                resp = await self.http.get(
                    f"{OTX_BASE}/pulses/subscribed",
                    headers=self._headers,
                    params={"modified_since": since, "limit": 50, "page": page},
                )
                resp.raise_for_status()
                data = resp.json()
            except Exception as e:
                self.logger.error(f"OTX: failed to fetch pulses (page {page}): {e}")
                result.errors += 1
                break

            pulses = data.get("results", [])
            if not pulses:
                break

            for pulse in pulses:
                r = await self._ingest_pulse(pulse)
                result.objects_created += r.objects_created
                result.errors += r.errors
                total_pulses += 1

            if not data.get("next"):
                break
            page += 1

        self.logger.info(
            f"OTX: ingested {result.objects_created} indicators from "
            f"{total_pulses} pulses, {result.errors} errors"
        )
        return result

    async def _ingest_pulse(self, pulse: dict) -> IngestResult:
        result = IngestResult()
        pulse_id = pulse.get("id", "")
        pulse_name = pulse.get("name", "unknown")
        tlp = _TLP_MAP.get(pulse.get("tlp", "white").lower(), "TLP:WHITE")
        labels = _build_labels(pulse)
        valid_from = _norm_ts(pulse.get("created") or "")
        refs = _build_refs(pulse, pulse_id)

        stix_objects = []
        for ioc in pulse.get("indicators", []):
            ioc_type = ioc.get("type", "")
            ioc_value = (ioc.get("indicator") or "").strip()
            if not ioc_value or ioc_type not in _TYPE_MAP:
                continue

            pattern = _TYPE_MAP[ioc_type](ioc_value)
            stix_objects.append({
                "type": "indicator",
                "name": f"{ioc_type}: {ioc_value[:100]}",
                "description": ioc.get("description") or pulse_name,
                "pattern": pattern,
                "pattern_type": "stix",
                "indicator_types": ["malicious-activity"],
                "valid_from": valid_from,
                "confidence": 60,
                "labels": labels,
                "x_clawint_source": "otx",
                "x_clawint_tlp": tlp,
                "x_clawint_pulse_id": pulse_id,
                "x_clawint_pulse_name": pulse_name,
                "x_clawint_malware_families": [
                    mf.get("display_name") or mf.get("id", "")
                    for mf in pulse.get("malware_families", [])
                ],
                "x_clawint_attack_ids": [
                    a.get("id", "") for a in pulse.get("attack_ids", [])
                ],
                "external_references": refs,
            })

            if len(stix_objects) >= 250:
                r = await self.push_to_platform(stix_objects)
                result.objects_created += r.objects_created
                result.errors += r.errors
                stix_objects = []

        if stix_objects:
            r = await self.push_to_platform(stix_objects)
            result.objects_created += r.objects_created
            result.errors += r.errors

        return result


def _build_labels(pulse: dict) -> list[str]:
    labels = ["otx"]
    for tag in pulse.get("tags", []):
        clean = tag.lower().replace(" ", "-")[:64]
        if clean:
            labels.append(clean)
    for mf in pulse.get("malware_families", []):
        name = (mf.get("display_name") or mf.get("id") or "").lower().replace(" ", "-")
        if name:
            labels.append(name)
    return list(dict.fromkeys(labels))  # dedupe, preserve order


def _build_refs(pulse: dict, pulse_id: str) -> list[dict]:
    refs = [{"source_name": "AlienVault OTX", "url": f"https://otx.alienvault.com/pulse/{pulse_id}"}]
    for ref in (pulse.get("references") or []):
        if ref and ref.startswith("http"):
            refs.append({"source_name": "reference", "url": ref})
    return refs


def _norm_ts(ts: str) -> str:
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    except Exception:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
