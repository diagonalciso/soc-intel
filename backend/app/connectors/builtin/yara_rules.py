"""
YARA Rules connector — import detection rules from signature-base (Neo23x0).
Fetches high-quality YARA rules from GitHub and stores in PostgreSQL.
Free, no auth required.
https://github.com/Neo23x0/signature-base
"""
import re

import httpx

from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult

_GITHUB_API = "https://api.github.com/repos/Neo23x0/signature-base/contents/yara"
_RAW_BASE = "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara"


class YaraRulesConnector(BaseConnector):

    def __init__(self):
        super().__init__(ConnectorConfig(
            name="yara-rules",
            display_name="YARA Rules (signature-base)",
            connector_type="import_external",
            description=(
                "Imports high-quality YARA detection rules from Neo23x0/signature-base on GitHub. "
                "Includes rules for malware families, APTs, and indicators of compromise."
            ),
            schedule="0 5 * * 1",  # weekly Monday 05:00
        ))

    async def run(self) -> IngestResult:
        self.logger.info("YARA: importing rules from signature-base...")
        result = IngestResult()

        from app.db.postgres import AsyncSessionLocal
        from app.models.rules import DetectionRule, RuleType, RuleStatus, RuleSeverity
        from sqlalchemy import select

        try:
            async with AsyncSessionLocal() as db:
                # Fetch list of .yar files from repo
                files = await self._list_yar_files()
                self.logger.info(f"YARA: found {len(files)} rule files")

                for file_url in files[:200]:  # limit to 200 to avoid massive imports
                    try:
                        content = await self._fetch_raw(file_url)
                        if not content:
                            continue

                        parsed = _parse_yara_rule(content)
                        if not parsed:
                            continue

                        # Check duplicate by name
                        existing = await db.execute(
                            select(DetectionRule).where(
                                DetectionRule.name == parsed["name"],
                                DetectionRule.rule_type == RuleType.yara,
                            )
                        )
                        if existing.scalar_one_or_none():
                            continue

                        # Map severity from meta field (optional)
                        severity = RuleSeverity.medium
                        if parsed.get("severity") == "high":
                            severity = RuleSeverity.high
                        elif parsed.get("severity") == "critical":
                            severity = RuleSeverity.critical

                        rule = DetectionRule(
                            name=parsed["name"][:255],
                            rule_type=RuleType.yara,
                            content=content,
                            description=(parsed.get("description") or "")[:2000],
                            author=parsed.get("author", "signature-base")[:255],
                            tags=parsed.get("tags", []),
                            severity=severity,
                            status=RuleStatus.active,
                            mitre_techniques=[],
                        )
                        db.add(rule)
                        result.objects_created += 1

                        # Commit in batches of 50
                        if result.objects_created % 50 == 0:
                            await db.commit()
                            self.logger.info(f"YARA: committed {result.objects_created} rules so far")

                    except Exception as e:
                        self.logger.debug(f"YARA: skipped {file_url}: {e}")
                        result.errors += 1

                await db.commit()

        except Exception as e:
            self.logger.error(f"YARA: import failed: {e}")
            result.errors += 1

        self.logger.info(f"YARA: imported {result.objects_created} rules, {result.errors} skipped")
        return result

    async def _list_yar_files(self) -> list[str]:
        """Return list of raw file URLs for all .yar files in the repo directory."""
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
            resp = await client.get(
                _GITHUB_API,
                headers={"Accept": "application/vnd.github.v3+json",
                         "User-Agent": "SOCINT/1.0 CTI Platform (research)"},
            )
            if resp.status_code != 200:
                self.logger.warning(f"YARA: failed to list repo: {resp.status_code}")
                return []

            try:
                entries = resp.json()
            except Exception as e:
                self.logger.warning(f"YARA: failed to parse repo listing: {e}")
                return []

            if not isinstance(entries, list):
                return []

            return [
                f"{_RAW_BASE}/{e['name']}"
                for e in entries
                if isinstance(e, dict) and e.get("name", "").endswith(".yar")
            ]

    async def _fetch_raw(self, url: str) -> str:
        """Fetch raw file content."""
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            resp = await client.get(
                url,
                headers={"User-Agent": "SOCINT/1.0 CTI Platform (research)"},
            )
            if resp.status_code == 200:
                return resp.text
        return ""


def _parse_yara_rule(content: str) -> dict | None:
    """
    Parse YARA rule metadata from content.
    Extracts: rule name, description, author, tags, severity.
    Expects format: rule <name> { ... meta: { ... } ... }
    """
    try:
        # Extract rule name
        m = re.search(r"^\s*rule\s+(\w+)\s*\{", content, re.MULTILINE)
        if not m:
            return None
        rule_name = m.group(1)

        # Extract meta section
        meta_match = re.search(
            r"^\s*meta\s*:\s*\n((?:\s+\w+\s*=\s*[^\n]+\n?)*)",
            content,
            re.MULTILINE,
        )
        meta_dict = {}
        if meta_match:
            meta_text = meta_match.group(1)
            for line in meta_text.strip().split("\n"):
                line = line.strip()
                if not line or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                meta_dict[key] = val

        # Extract strings section for description
        description = ""
        strings_match = re.search(
            r"^\s*strings\s*:\s*\n((?:\s+\$\w+\s*=\s*[^\n]+\n?)*)",
            content,
            re.MULTILINE,
        )
        if strings_match:
            description = f"Rule matches {len(strings_match.group(1).strip().split(chr(10)))} patterns"

        # Parse tags from meta fields
        tags = []
        for key in ["malware", "family", "capability", "category"]:
            if key in meta_dict:
                val = meta_dict[key]
                if val:
                    tags.append(val.lower().replace(" ", "-"))

        # Severity mapping
        severity = meta_dict.get("severity", "").lower()
        if severity not in ["critical", "high", "medium", "low"]:
            severity = "medium"

        return {
            "name": rule_name,
            "description": description or meta_dict.get("description", ""),
            "author": meta_dict.get("author", "signature-base"),
            "tags": tags[:20],
            "severity": severity,
        }

    except Exception:
        return None
