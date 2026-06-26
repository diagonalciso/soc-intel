"""
Blocklist.de connector — import.
Ingests attack-source IPs from blocklist.de (SSH, FTP, web, mail, SIP brute force).
Free, no API key required. Updated every 5 minutes upstream.
"""
from datetime import datetime, timezone

from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult

_CATEGORIES = {
    "ssh":    ("https://lists.blocklist.de/lists/ssh.txt",    "ssh-brute-force",    "SSH brute force"),
    "ftp":    ("https://lists.blocklist.de/lists/ftp.txt",    "ftp-brute-force",    "FTP brute force"),
    "apache": ("https://lists.blocklist.de/lists/apache.txt", "web-attack",         "Apache/web attack"),
    "mail":   ("https://lists.blocklist.de/lists/mail.txt",   "spam",               "mail/spam source"),
    "sip":    ("https://lists.blocklist.de/lists/sip.txt",    "sip-brute-force",    "SIP/VoIP brute force"),
}


class BlocklistDeConnector(BaseConnector):
    def __init__(self):
        super().__init__(ConnectorConfig(
            name="blocklist-de",
            display_name="Blocklist.de",
            connector_type="import_external",
            description="Attack-source IPs from blocklist.de: SSH, FTP, web, mail, SIP brute force attackers. Updated every 5 min upstream.",
            schedule="0 */4 * * *",
            source_reliability=72,
        ))

    async def run(self) -> IngestResult:
        self.logger.info("Blocklist.de: fetching attack IP lists...")
        result = IngestResult()
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        for category, (url, label, description) in _CATEGORIES.items():
            try:
                resp = await self.http.get(url)
                resp.raise_for_status()
            except Exception as e:
                self.logger.warning(f"Blocklist.de [{category}]: fetch failed: {e}")
                result.errors += 1
                continue

            stix_objects = []
            for line in resp.text.splitlines():
                ip = line.strip()
                if not ip or ip.startswith("#"):
                    continue

                indicator = {
                    "type": "indicator",
                    "name": f"Blocklist.de {category.upper()}: {ip}",
                    "description": f"blocklist.de — {description} source",
                    "pattern": f"[ipv4-addr:value = '{ip}']",
                    "pattern_type": "stix",
                    "indicator_types": ["malicious-activity", "anomalous-activity"],
                    "valid_from": now,
                    "labels": [label, "blocklist-de", category],
                    "x_clawint_source": "blocklist-de",
                    "x_clawint_category": category,
                    "external_references": [
                        {"source_name": "blocklist.de", "url": "https://www.blocklist.de/"}
                    ],
                }
                stix_objects.append(indicator)

                if len(stix_objects) >= 500:
                    r = await self.push_to_platform(stix_objects)
                    result.objects_created += r.objects_created
                    result.errors += r.errors
                    stix_objects = []

            if stix_objects:
                r = await self.push_to_platform(stix_objects)
                result.objects_created += r.objects_created
                result.errors += r.errors

            self.logger.info(f"Blocklist.de [{category}]: done")

        self.logger.info(f"Blocklist.de: ingested {result.objects_created} indicators total")
        return result
