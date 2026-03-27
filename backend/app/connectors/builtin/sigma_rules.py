"""
Sigma Rules connector — import.
Ingests curated Sigma detection rules from the SigmaHQ/sigma GitHub repo.
Imports high-signal rule categories: Windows, Linux, network, web, cloud.
Free, no auth required.
https://github.com/SigmaHQ/sigma
"""
import re
from datetime import datetime, timezone

import httpx

from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult

# Rule directories to import from the SigmaHQ repo (via GitHub raw API)
_CATEGORIES = [
    "rules/windows/process_creation",
    "rules/windows/powershell",
    "rules/windows/network_connection",
    "rules/linux/process_creation",
    "rules/network/firewall",
    "rules/web/webserver",
    "rules/cloud/aws",
    "rules/windows/registry/registry_set",
    "rules/windows/file/file_event",
]

_GITHUB_API = "https://api.github.com/repos/SigmaHQ/sigma/contents"
_RAW_BASE   = "https://raw.githubusercontent.com/SigmaHQ/sigma/master"

# Map Sigma levels to our severity enum
_LEVEL_MAP = {
    "critical": "critical",
    "high":     "high",
    "medium":   "medium",
    "low":      "low",
    "informational": "low",
}

# Sigma status values we accept
_ACCEPT_STATUS = {"stable", "test", "experimental"}


class SigmaRulesConnector(BaseConnector):

    def __init__(self):
        super().__init__(ConnectorConfig(
            name="sigma-rules",
            display_name="Sigma Rules (SigmaHQ)",
            connector_type="import_external",
            description=(
                "Imports curated Sigma detection rules from SigmaHQ/sigma on GitHub. "
                "Covers Windows, Linux, network, web, and cloud categories."
            ),
            schedule="0 5 * * 1",  # weekly Monday 05:00
        ))

    async def run(self) -> IngestResult:
        self.logger.info("Sigma: importing rules from SigmaHQ/sigma...")
        result = IngestResult()

        from app.db.postgres import AsyncSessionLocal
        from app.models.rules import DetectionRule, RuleType, RuleStatus, RuleSeverity
        from sqlalchemy import select

        async with AsyncSessionLocal() as db:
            for category in _CATEGORIES:
                try:
                    files = await self._list_yml_files(category)
                    self.logger.info(f"Sigma: {category} → {len(files)} files")
                    for file_url in files:
                        try:
                            content = await self._fetch_raw(file_url)
                            if not content:
                                continue
                            parsed = _parse_sigma_yaml(content)
                            if not parsed:
                                continue

                            # Check duplicate by name
                            existing = await db.execute(
                                select(DetectionRule).where(
                                    DetectionRule.name == parsed["name"],
                                    DetectionRule.rule_type == RuleType.sigma,
                                )
                            )
                            if existing.scalar_one_or_none():
                                continue

                            rule = DetectionRule(
                                name=parsed["name"][:255],
                                rule_type=RuleType.sigma,
                                content=content,
                                description=(parsed.get("description") or "")[:2000],
                                author=parsed.get("author", "SigmaHQ")[:255],
                                tags=parsed.get("tags", []),
                                severity=RuleSeverity(
                                    _LEVEL_MAP.get(parsed.get("level", "medium"), "medium")
                                ),
                                status=RuleStatus.active,
                                mitre_techniques=parsed.get("mitre_techniques", []),
                            )
                            db.add(rule)
                            result.objects_created += 1

                            # Commit in batches of 100
                            if result.objects_created % 100 == 0:
                                await db.commit()
                                self.logger.info(f"Sigma: committed {result.objects_created} rules so far")

                        except Exception as e:
                            self.logger.debug(f"Sigma: skipped {file_url}: {e}")
                            result.errors += 1

                except Exception as e:
                    self.logger.warning(f"Sigma: failed to list {category}: {e}")
                    result.errors += 1

            await db.commit()

        self.logger.info(f"Sigma: imported {result.objects_created} rules, {result.errors} skipped")
        return result

    async def _list_yml_files(self, path: str) -> list[str]:
        """Return list of raw file URLs for all .yml files in a repo directory."""
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
            resp = await client.get(
                f"{_GITHUB_API}/{path}",
                headers={"Accept": "application/vnd.github.v3+json",
                         "User-Agent": "CLAWINT/1.0 CTI Platform (research)"},
            )
            if resp.status_code != 200:
                return []
            entries = resp.json()
            if not isinstance(entries, list):
                return []
            return [
                f"{_RAW_BASE}/{path}/{e['name']}"
                for e in entries
                if isinstance(e, dict) and e.get("name", "").endswith(".yml")
            ]

    async def _fetch_raw(self, url: str) -> str:
        """Fetch raw file content."""
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            resp = await client.get(
                url,
                headers={"User-Agent": "CLAWINT/1.0 CTI Platform (research)"},
            )
            if resp.status_code == 200:
                return resp.text
        return ""


def _parse_sigma_yaml(content: str) -> dict | None:
    """
    Minimal YAML parser for Sigma rules — avoids pyyaml dependency.
    Extracts: title, description, author, level, status, tags, detection.
    """
    try:
        title       = _yaml_scalar(content, "title")
        status      = _yaml_scalar(content, "status") or ""
        level       = _yaml_scalar(content, "level") or "medium"
        description = _yaml_scalar(content, "description") or ""
        author      = _yaml_scalar(content, "author") or "SigmaHQ"

        if not title:
            return None
        if status.lower() not in _ACCEPT_STATUS:
            return None

        # Extract MITRE ATT&CK technique IDs from tags (e.g. attack.t1059.001)
        tags_raw = _yaml_list(content, "tags")
        mitre_techniques = []
        clean_tags = []
        for tag in tags_raw:
            m = re.match(r"attack\.(t\d{4}(?:\.\d{3})?)", tag.lower())
            if m:
                mitre_techniques.append(m.group(1).upper())
            clean_tags.append(tag)

        return {
            "name":             title,
            "description":      description,
            "author":           author,
            "level":            level.lower(),
            "status":           status.lower(),
            "tags":             clean_tags[:20],
            "mitre_techniques": list(dict.fromkeys(mitre_techniques)),
        }
    except Exception:
        return None


def _yaml_scalar(text: str, key: str) -> str:
    """Extract a single-line scalar value from YAML-like text."""
    m = re.search(rf"^{re.escape(key)}\s*:\s*(.+)$", text, re.MULTILINE)
    if not m:
        return ""
    val = m.group(1).strip()
    # Strip YAML quotes
    if (val.startswith('"') and val.endswith('"')) or \
       (val.startswith("'") and val.endswith("'")):
        val = val[1:-1]
    return val.strip()


def _yaml_list(text: str, key: str) -> list[str]:
    """Extract a YAML list (block sequence) for the given key."""
    # Match the key then capture indented list items
    m = re.search(rf"^{re.escape(key)}\s*:\s*\n((?:\s+-\s*.+\n?)+)", text, re.MULTILINE)
    if not m:
        # Inline list: key: [a, b, c]
        mi = re.search(rf"^{re.escape(key)}\s*:\s*\[(.+)\]", text, re.MULTILINE)
        if mi:
            return [i.strip().strip("'\"") for i in mi.group(1).split(",") if i.strip()]
        return []
    items = []
    for line in m.group(1).splitlines():
        stripped = re.sub(r"^\s+-\s*", "", line).strip().strip("'\"")
        if stripped:
            items.append(stripped)
    return items
