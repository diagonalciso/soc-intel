"""
NIST SP 800-53 Rev 5 connector.
Fetches the security controls catalog from NIST OSCAL content on GitHub and stores
controls in the PostgreSQL nist_controls table. Used for compliance tagging on rules/cases.
"""
import logging
from sqlalchemy import select
from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult
from app.db.postgres import AsyncSessionLocal
from app.models.compliance import NistControl

logger = logging.getLogger(__name__)

CATALOG_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
    "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
)

_FAMILY_NAMES: dict[str, str] = {
    "ac": "Access Control",
    "at": "Awareness and Training",
    "au": "Audit and Accountability",
    "ca": "Assessment, Authorization, and Monitoring",
    "cm": "Configuration Management",
    "cp": "Contingency Planning",
    "ia": "Identification and Authentication",
    "ir": "Incident Response",
    "ma": "Maintenance",
    "mp": "Media Protection",
    "pe": "Physical and Environmental Protection",
    "pl": "Planning",
    "pm": "Program Management",
    "ps": "Personnel Security",
    "pt": "PII Processing and Transparency",
    "ra": "Risk Assessment",
    "sa": "System and Services Acquisition",
    "sc": "System and Communications Protection",
    "si": "System and Information Integrity",
    "sr": "Supply Chain Risk Management",
}


class NIST80053Connector(BaseConnector):
    def __init__(self):
        super().__init__(ConnectorConfig(
            name="nist-800-53",
            display_name="NIST SP 800-53 Rev 5",
            connector_type="import_external",
            description=(
                "Imports the NIST SP 800-53 Rev 5 security controls catalog from NIST OSCAL. "
                "Populates the compliance controls reference table for tagging detection rules and cases."
            ),
            schedule="0 3 * * 0",  # weekly Sunday 03:00
        ))

    async def run(self) -> IngestResult:
        result = IngestResult()
        try:
            resp = await self.http.get(CATALOG_URL, timeout=60)
            resp.raise_for_status()
            catalog_data = resp.json()
        except Exception as exc:
            logger.error(f"nist-800-53: failed to fetch catalog: {exc}")
            result.errors += 1
            result.messages.append(f"Fetch failed: {exc}")
            return result

        groups = catalog_data.get("catalog", {}).get("groups", [])
        if not groups:
            logger.warning("nist-800-53: no groups found in catalog — check OSCAL format")
            result.messages.append("No control groups found in catalog")
            return result

        async with AsyncSessionLocal() as db:
            for group in groups:
                family_key = group.get("id", "").lower()
                family_id = family_key.upper()
                family_name = _FAMILY_NAMES.get(family_key, group.get("title", family_id))

                for control in group.get("controls", []):
                    c, u = await self._upsert(db, control, family_id, family_name, False, None)
                    result.objects_created += c
                    result.objects_updated += u

                    for enhancement in control.get("controls", []):
                        parent_label = self._label(control)
                        c, u = await self._upsert(db, enhancement, family_id, family_name, True, parent_label)
                        result.objects_created += c
                        result.objects_updated += u

            await db.commit()

        result.messages.append(
            f"SP 800-53: {result.objects_created} controls created, {result.objects_updated} updated"
        )
        return result

    # ── helpers ───────────────────────────────────────────────────

    def _label(self, control: dict) -> str:
        for prop in control.get("props", []):
            if prop.get("name") == "label":
                return prop.get("value", "").upper()
        return control.get("id", "").upper().replace("-", "-")

    def _description(self, control: dict) -> str:
        for part in control.get("parts", []):
            if part.get("name") == "statement":
                prose = part.get("prose", "")
                if prose:
                    return prose[:4000]
                sub = [p.get("prose", "") for p in part.get("parts", []) if p.get("prose")]
                if sub:
                    return "\n".join(sub)[:4000]
        return ""

    def _baseline(self, control: dict) -> list[str]:
        seen: list[str] = []
        for prop in control.get("props", []):
            if prop.get("name") == "baseline-impact":
                val = prop.get("value", "").upper()
                if val and val not in seen:
                    seen.append(val)
        return seen

    def _related(self, control: dict) -> list[str]:
        out: list[str] = []
        for link in control.get("links", []):
            if link.get("rel") == "related":
                href = link.get("href", "").lstrip("#").upper()
                if href:
                    out.append(href)
        return out

    def _withdrawn(self, control: dict) -> bool:
        for prop in control.get("props", []):
            if prop.get("name") == "status" and prop.get("value", "").lower() == "withdrawn":
                return True
        return False

    async def _upsert(
        self,
        db,
        control: dict,
        family_id: str,
        family_name: str,
        is_enhancement: bool,
        parent_id: str | None,
    ) -> tuple[int, int]:
        label = self._label(control)
        if not label:
            return 0, 0

        existing = (await db.execute(
            select(NistControl).where(NistControl.control_id == label)
        )).scalar_one_or_none()

        kwargs = dict(
            family=family_id,
            family_name=family_name,
            title=control.get("title", ""),
            description=self._description(control),
            is_enhancement=is_enhancement,
            parent_id=parent_id,
            baseline_impact=self._baseline(control),
            related=self._related(control),
            withdrawn=self._withdrawn(control),
        )

        if existing:
            for k, v in kwargs.items():
                setattr(existing, k, v)
            return 0, 1
        else:
            db.add(NistControl(control_id=label, **kwargs))
            return 1, 0
