"""
Hybrid Analysis Sandbox connector — enrichment.
Enriches file hashes (MD5, SHA1, SHA256) with sandbox analysis results from
the Hybrid Analysis platform. Requires HYBRID_ANALYSIS_API_KEY.
Only creates STIX objects for malicious or suspicious verdicts.
"""
import uuid

from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult
from app.config import get_settings

settings = get_settings()

_BASE_URL = "https://www.hybrid-analysis.com"
_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # uuid.NAMESPACE_URL
_ACTIONABLE_VERDICTS = {"malicious", "suspicious"}


def _stix_id(type_: str, key: str) -> str:
    return f"{type_}--{uuid.uuid5(_NAMESPACE, f'hybrid-analysis:{type_}:{key}')}"


class HybridAnalysisConnector(BaseConnector):
    def __init__(self):
        super().__init__(ConnectorConfig(
            name="hybrid-analysis",
            display_name="Hybrid Analysis Sandbox",
            connector_type="enrichment",
            description=(
                "Enriches file hashes with Hybrid Analysis sandbox verdicts, "
                "malware family, and MITRE ATT&CK techniques."
            ),
        ))

    async def run(self) -> IngestResult:
        # Enrichment connectors are called on-demand via enrich_hash()
        return IngestResult(
            messages=["Hybrid Analysis is an enrichment connector — call enrich_hash() directly"]
        )

    async def enrich_hash(self, file_hash: str) -> list[dict]:
        """
        Enrich a file hash (MD5, SHA1, or SHA256) using Hybrid Analysis.
        Returns STIX objects only for malicious/suspicious verdicts.
        Returns an empty list if the hash is not found, verdict is benign,
        or no API key is configured.
        """
        api_key = settings.hybrid_analysis_api_key
        if not api_key:
            self.logger.warning("Hybrid Analysis: HYBRID_ANALYSIS_API_KEY not set — skipping")
            return []

        headers = {
            "api-key": api_key,
            "User-Agent": "Falcon Sandbox",
            "Accept": "application/json",
        }

        try:
            resp = await self.http.get(
                f"{_BASE_URL}/api/v2/search/hash",
                params={"hash": file_hash},
                headers=headers,
            )

            # Log remaining API quota if header is present
            api_limits = resp.headers.get("Api-Limits", "")
            if api_limits:
                self.logger.info(f"Hybrid Analysis: API limits — {api_limits}")

            resp.raise_for_status()
            results = resp.json()
        except Exception as e:
            self.logger.error(f"Hybrid Analysis enrich {file_hash}: {e}")
            return []

        if not results:
            self.logger.info(f"Hybrid Analysis: no results for hash {file_hash}")
            return []

        # Results is a list; pick the first entry (most complete)
        if isinstance(results, list):
            report = results[0]
        else:
            report = results

        verdict = (report.get("verdict") or "").lower()
        if verdict not in _ACTIONABLE_VERDICTS:
            self.logger.info(
                f"Hybrid Analysis: hash {file_hash} verdict='{verdict}' — not actionable"
            )
            return []

        stix_objects: list[dict] = []

        # Build hashes dict from available fields
        sha256 = report.get("sha256", "")
        sha1 = report.get("sha1", "")
        md5 = report.get("md5", "")
        submit_name = report.get("submit_name", "") or file_hash
        vx_family = report.get("vx_family", "")

        hashes: dict = {}
        if sha256:
            hashes["SHA-256"] = sha256
        if sha1:
            hashes["SHA-1"] = sha1
        if md5:
            hashes["MD5"] = md5

        # File SCO
        file_id = _stix_id("file", sha256 or file_hash)
        file_obj: dict = {
            "type": "file",
            "id": file_id,
            "name": submit_name,
            "x_clawint_source": "hybrid-analysis",
            "x_clawint_verdict": verdict,
        }
        if hashes:
            file_obj["hashes"] = hashes
        stix_objects.append(file_obj)

        # Indicator SDO
        if sha256:
            indicator_id = _stix_id("indicator", sha256)
            indicator_obj: dict = {
                "type": "indicator",
                "id": indicator_id,
                "name": f"Malicious file: {submit_name}",
                "pattern": f"[file:hashes.SHA256 = '{sha256}']",
                "pattern_type": "stix",
                "labels": ["malicious-activity"],
                "confidence": 85 if verdict == "malicious" else 60,
                "x_clawint_source": "hybrid-analysis",
            }
            stix_objects.append(indicator_obj)

            # indicator → indicates → file
            stix_objects.append({
                "type": "relationship",
                "id": _stix_id("relationship", f"{indicator_id}-indicates-{file_id}"),
                "relationship_type": "indicates",
                "source_ref": indicator_id,
                "target_ref": file_id,
                "x_clawint_source": "hybrid-analysis",
            })

        # Malware SDO
        malware_id: str | None = None
        if vx_family:
            malware_id = _stix_id("malware", vx_family.lower())
            malware_obj: dict = {
                "type": "malware",
                "id": malware_id,
                "name": vx_family,
                "is_family": True,
                "labels": ["trojan"],  # generic label; overridden by ATT&CK tags if available
                "x_clawint_source": "hybrid-analysis",
            }
            stix_objects.append(malware_obj)

            # file → related-to → malware
            stix_objects.append({
                "type": "relationship",
                "id": _stix_id("relationship", f"{file_id}-related-to-{malware_id}"),
                "relationship_type": "related-to",
                "source_ref": file_id,
                "target_ref": malware_id,
                "x_clawint_source": "hybrid-analysis",
            })

        # ATT&CK technique SDOs
        mitre_attcks = report.get("mitre_attcks", []) or []
        for technique in mitre_attcks:
            technique_id = technique.get("technique_id", "")
            technique_name = technique.get("technique", "")
            if not technique_id:
                continue

            ap_id = _stix_id("attack-pattern", technique_id)
            attack_pattern: dict = {
                "type": "attack-pattern",
                "id": ap_id,
                "name": technique_name or technique_id,
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": technique_id,
                        "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
                    }
                ],
                "x_clawint_source": "hybrid-analysis",
            }
            stix_objects.append(attack_pattern)

        self.logger.info(
            f"Hybrid Analysis: hash {file_hash} — verdict={verdict}, "
            f"family={vx_family or 'unknown'}, {len(mitre_attcks)} ATT&CK techniques"
        )
        return stix_objects
