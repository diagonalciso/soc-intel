"""
ThreatFox connector (abuse.ch) — import.
Ingests IOCs (malware C2s, URLs, hashes) from ThreatFox.
Uses the free CSV export (no API key required).
"""
import csv
import io
from datetime import datetime, timezone

from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult


class ThreatFoxConnector(BaseConnector):
    CSV_URL = "https://threatfox.abuse.ch/export/csv/recent/"

    def __init__(self):
        super().__init__(ConnectorConfig(
            name="threatfox",
            display_name="ThreatFox (abuse.ch)",
            connector_type="import_external",
            description="Imports malware IOCs (C2 IPs, URLs, hashes) from abuse.ch ThreatFox.",
            schedule="0 */4 * * *",  # every 4 hours
        ))

    async def run(self) -> IngestResult:
        self.logger.info("ThreatFox: fetching recent IOCs via CSV export...")
        result = IngestResult()

        try:
            resp = await self.http.get(self.CSV_URL)
            resp.raise_for_status()
            csv_content = resp.text
        except Exception as e:
            self.logger.error(f"ThreatFox: fetch failed: {e}")
            result.errors += 1
            return result

        reader = csv.reader(io.StringIO(csv_content))
        iocs = []
        for row in reader:
            # Skip comments and header
            if not row or row[0].startswith("#"):
                continue
            if len(row) < 4:
                continue
            # Columns: first_seen_utc, ioc_id, ioc_value, ioc_type, threat_type,
            #          fk_malware, malware_alias, malware_printable, last_seen_utc,
            #          confidence_level, is_compromised, reference, tags, anonymous, reporter
            conf_raw = row[9].strip().strip('"') if len(row) > 9 else "50"
            iocs.append({
                "first_seen": row[0].strip().strip('"'),
                "id": row[1].strip().strip('"'),
                "ioc": row[2].strip().strip('"'),
                "ioc_type": row[3].strip().strip('"'),
                "malware": row[7].strip().strip('"') if len(row) > 7 else "",
                "confidence_level": int(conf_raw) if conf_raw.isdigit() else 50,
                "reporter": row[14].strip().strip('"') if len(row) > 14 else "",
            })
        stix_objects = []

        for ioc in iocs:
            ioc_type = ioc.get("ioc_type", "")
            ioc_value = ioc.get("ioc", "")
            malware = ioc.get("malware", "")
            confidence = ioc.get("confidence_level", 50)

            # Map ThreatFox types to STIX patterns
            pattern = _to_pattern(ioc_type, ioc_value)
            if not pattern:
                continue

            indicator = {
                "type": "indicator",
                "name": f"{malware}: {ioc_value[:80]}",
                "description": ioc.get("comment", f"ThreatFox IOC — {malware}"),
                "pattern": pattern,
                "pattern_type": "stix",
                "indicator_types": ["malicious-activity"],
                "valid_from": _iso(ioc.get("first_seen", "")),
                "confidence": confidence,
                "labels": [malware.lower().replace(" ", "-"), ioc_type],
                "x_clawint_source": "threatfox",
                "x_clawint_malware_malpedia": ioc.get("malware_malpedia", ""),
                "x_clawint_reporter": ioc.get("reporter", ""),
                "external_references": [
                    {"source_name": "ThreatFox", "url": f"https://threatfox.abuse.ch/ioc/{ioc.get('id', '')}"},
                ],
            }
            stix_objects.append(indicator)

            if len(stix_objects) >= 250:
                r = await self.push_to_platform(stix_objects)
                result.objects_created += r.objects_created
                result.errors += r.errors
                stix_objects = []

        if stix_objects:
            r = await self.push_to_platform(stix_objects)
            result.objects_created += r.objects_created
            result.errors += r.errors

        self.logger.info(f"ThreatFox: ingested {result.objects_created} indicators")
        return result


def _to_pattern(ioc_type: str, value: str) -> str | None:
    mapping = {
        "ip:port": lambda v: f"[ipv4-addr:value = '{v.split(':')[0]}']",
        "domain": lambda v: f"[domain-name:value = '{v}']",
        "url": lambda v: f"[url:value = '{v}']",
        "md5_hash": lambda v: f"[file:hashes.MD5 = '{v}']",
        "sha256_hash": lambda v: f"[file:hashes.'SHA-256' = '{v}']",
        "sha1_hash": lambda v: f"[file:hashes.'SHA-1' = '{v}']",
    }
    fn = mapping.get(ioc_type)
    return fn(value) if fn else None


def _iso(ts: str) -> str:
    if not ts:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    try:
        dt = datetime.fromisoformat(ts.replace(" ", "T"))
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    except Exception:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
