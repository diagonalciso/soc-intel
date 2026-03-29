"""
DeepDarkCTI connector — import.
Ingests ransomware group reference data (names, onion URLs, status) from
the fastfire/deepdarkCTI community GitHub repo.
Free, no auth required. Updates group profiles, not victim listings.
https://github.com/fastfire/deepdarkCTI
"""
import re
from datetime import datetime, timezone

from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult
from app.db.opensearch import get_opensearch, DARKWEB_INDEX

RANSOMWARE_GANG_URL = (
    "https://raw.githubusercontent.com/fastfire/deepdarkCTI/main/ransomware_gang.md"
)


class DeepDarkCTIConnector(BaseConnector):
    def __init__(self):
        super().__init__(ConnectorConfig(
            name="deepdark-cti",
            display_name="DeepDarkCTI (Ransomware Groups)",
            connector_type="import_external",
            description=(
                "Ransomware group reference data from fastfire/deepdarkCTI — "
                "200+ groups with onion URLs, status, and Telegram channels."
            ),
            schedule="0 6 * * *",  # once daily at 06:00
        ))

    async def run(self) -> IngestResult:
        self.logger.info("DeepDarkCTI: fetching ransomware group list...")
        result = IngestResult()

        try:
            resp = await self.http.get(
                RANSOMWARE_GANG_URL,
                headers={"User-Agent": "SOCINT/1.0 CTI Platform (research)"},
            )
            resp.raise_for_status()
            content = resp.text
        except Exception as e:
            self.logger.error(f"DeepDarkCTI: fetch failed: {e}")
            result.errors += 1
            return result

        groups = _parse_markdown_table(content)
        if not groups:
            self.logger.warning("DeepDarkCTI: no groups parsed from markdown")
            return result

        client = get_opensearch()
        bulk = []
        now = _now()

        for group in groups:
            name = group.get("name", "").strip()
            if not name:
                continue

            doc_id = f"ransomware-group--ddcti-{_slug(name)}"
            doc = {
                "id": doc_id,
                "type": "ransomware-group",
                "created": now,
                "modified": now,
                "source": "deepdark-cti",
                "group_name": name.lower(),
                "group_display_name": name,
                "leak_site_url": group.get("url", ""),
                "status": group.get("status", ""),
                "telegram": group.get("telegram", ""),
                "notes": group.get("notes", "")[:300],
                "date_posted": now,
            }
            bulk.append({"index": {"_index": DARKWEB_INDEX, "_id": doc_id}})
            bulk.append(doc)
            result.objects_created += 1

        if bulk:
            try:
                resp_bulk = await client.bulk(body=bulk, refresh=False)
                errors = sum(
                    1 for item in resp_bulk["items"] if item.get("index", {}).get("error")
                )
                result.errors += errors
                result.objects_created -= errors
            except Exception as e:
                self.logger.error(f"DeepDarkCTI: OpenSearch bulk error: {e}")
                result.errors += len(bulk) // 2
                result.objects_created = 0

        self.logger.info(
            f"DeepDarkCTI: ingested {result.objects_created} group profiles, {result.errors} errors"
        )
        return result


def _parse_markdown_table(content: str) -> list[dict]:
    """
    Parse the deepdarkCTI ransomware_gang.md markdown table.

    Expected columns vary but typically include:
    Group Name | URL / .onion | Status | Telegram | Notes
    """
    groups = []
    lines = content.splitlines()

    header_idx = None
    col_map = {}

    for i, line in enumerate(lines):
        line = line.strip()
        if not line.startswith("|"):
            continue

        cells = [c.strip() for c in line.strip("|").split("|")]

        # Detect header row
        if header_idx is None:
            lower_cells = [c.lower() for c in cells]
            if any(kw in " ".join(lower_cells) for kw in ["group", "name", "status", "url", "onion"]):
                header_idx = i
                for j, cell in enumerate(lower_cells):
                    if "group" in cell or "name" in cell:
                        col_map.setdefault("name", j)
                    elif "url" in cell or "onion" in cell or "site" in cell or "link" in cell:
                        col_map.setdefault("url", j)
                    elif "status" in cell or "active" in cell or "online" in cell:
                        col_map.setdefault("status", j)
                    elif "telegram" in cell or "tg" in cell:
                        col_map.setdefault("telegram", j)
                    elif "note" in cell or "comment" in cell or "info" in cell:
                        col_map.setdefault("notes", j)
            continue

        # Skip separator rows (---|---|---)
        if all(re.match(r"^[-:]+$", c) for c in cells if c):
            continue

        if header_idx is not None and cells:
            group = {}
            for field, idx in col_map.items():
                if idx < len(cells):
                    val = _strip_md(cells[idx])
                    if val:
                        group[field] = val
            if group.get("name"):
                groups.append(group)

    return groups


def _strip_md(text: str) -> str:
    """Strip markdown links and formatting from a cell value."""
    # [text](url) → url (prefer the URL for onion links)
    text = re.sub(r"\[([^\]]*)\]\(([^)]*)\)", lambda m: m.group(2) if ".onion" in m.group(2) else m.group(1), text)
    # Remove bold/italic markers
    text = re.sub(r"[*_`]", "", text)
    return text.strip()


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower().strip())[:64]
