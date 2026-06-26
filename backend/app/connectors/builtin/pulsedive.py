"""
Pulsedive connector — import.
Ingests high/critical risk indicators from Pulsedive community intelligence.
Requires PULSEDIVE_API_KEY (free tier available at pulsedive.com).
"""
from datetime import datetime, timezone

from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult
from app.config import get_settings

settings = get_settings()

EXPLORE_URL = "https://pulsedive.com/api/explore.php"


class PulsediveConnector(BaseConnector):

    def __init__(self):
        super().__init__(ConnectorConfig(
            name="pulsedive",
            display_name="Pulsedive",
            connector_type="import_external",
            description="Imports high/critical risk indicators from Pulsedive community threat intelligence.",
            schedule="0 */6 * * *",  # every 6 hours
            source_reliability=72,
        ))

    async def run(self) -> IngestResult:
        result = IngestResult()

        if not settings.pulsedive_api_key:
            self.logger.warning("Pulsedive: no API key configured — skipping")
            result.messages.append("No PULSEDIVE_API_KEY configured")
            return result

        self.logger.info("Pulsedive: fetching high/critical risk indicators...")

        try:
            resp = await self.http.get(
                EXPLORE_URL,
                params={
                    "q": "type:indicator risk:high,critical",
                    "pretty": "1",
                    "limit": "1000",
                    "key": settings.pulsedive_api_key,
                },
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            self.logger.error(f"Pulsedive: fetch failed: {e}")
            result.errors += 1
            return result

        indicators_raw = data.get("results", [])
        self.logger.info(f"Pulsedive: processing {len(indicators_raw)} indicators")

        stix_objects: list[dict] = []

        for item in indicators_raw:
            ioc_type = (item.get("type") or "").lower()
            ioc_value = (item.get("indicator") or "").strip()
            risk = (item.get("risk") or "medium").lower()
            threats = item.get("threats") or []
            feeds = item.get("feeds") or []
            stamp = item.get("stamp_updated") or item.get("stamp_added") or ""

            pattern = _to_pattern(ioc_type, ioc_value)
            if not pattern:
                continue

            confidence = {"critical": 90, "high": 75, "medium": 50, "low": 30, "unknown": 40}.get(risk, 50)
            threat_names = [t.get("name", "") for t in threats if t.get("name")]
            feed_names = [f.get("name", "") for f in feeds if f.get("name")]
            labels = (
                [f"threat-{n.lower().replace(' ', '-')}" for n in threat_names[:3]]
                + [f"feed-{n.lower().replace(' ', '-')}" for n in feed_names[:2]]
                + [f"pulsedive-{risk}"]
            )

            indicator = {
                "type": "indicator",
                "name": f"{ioc_type.upper()}: {ioc_value[:80]}",
                "description": (
                    f"Pulsedive {risk}-risk {ioc_type} indicator"
                    + (f" — threats: {', '.join(threat_names[:3])}" if threat_names else "")
                ),
                "pattern": pattern,
                "pattern_type": "stix",
                "indicator_types": ["malicious-activity"],
                "valid_from": _iso(stamp),
                "confidence": confidence,
                "labels": labels,
                "x_clawint_source": "pulsedive",
                "x_clawint_risk": risk,
                "external_references": [
                    {
                        "source_name": "Pulsedive",
                        "url": f"https://pulsedive.com/indicator/?ioc={ioc_value}",
                    }
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

        self.logger.info(f"Pulsedive: ingested {result.objects_created} indicators")
        return result


def _to_pattern(ioc_type: str, value: str) -> str | None:
    safe = value.replace("'", "\\'")
    mapping = {
        "ip":     f"[ipv4-addr:value = '{safe}']",
        "ipv6":   f"[ipv6-addr:value = '{safe}']",
        "domain": f"[domain-name:value = '{safe}']",
        "url":    f"[url:value = '{safe}']",
        "email":  f"[email-addr:value = '{safe}']",
    }
    return mapping.get(ioc_type)


def _iso(ts: str) -> str:
    if not ts:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    try:
        dt = datetime.fromisoformat(ts.replace(" ", "T"))
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    except Exception:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
