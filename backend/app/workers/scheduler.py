"""
Connector scheduler.
Runs import connectors on their configured cron schedules.
"""
import asyncio
import logging
from datetime import datetime, timedelta, timezone
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from app.connectors.builtin.ransomwatch import RansomwatchConnector
from app.connectors.builtin.urlhaus import URLhausConnector
from app.connectors.builtin.cisa_kev import CISAKEVConnector
from app.connectors.builtin.threatfox import ThreatFoxConnector
from app.connectors.builtin.mitre_attack import MITREAttackConnector
from app.connectors.builtin.leaksites import LeakSiteScraper
from app.connectors.builtin.feodotracker import FeodoTrackerConnector
from app.connectors.builtin.sslbl import SpamhausDropConnector
from app.connectors.builtin.dshield import DShieldConnector
from app.connectors.builtin.openphish import OpenPhishConnector
from app.connectors.builtin.ransomware_live import RansomwareLiveConnector
from app.connectors.builtin.ransomlook import RansomLookConnector
from app.connectors.builtin.deepdark_cti import DeepDarkCTIConnector
from app.connectors.builtin.nvd_epss import NVDEPSSConnector
from app.connectors.builtin.otx_import import OTXImportConnector
from app.connectors.builtin.misp_feeds import MISPFeedsConnector
from app.connectors.builtin.taxii_import import TAXIIImportConnector
from app.connectors.builtin.sigma_rules import SigmaRulesConnector
from app.connectors.builtin.malwarebazaar import MalwareBazaarConnector
from app.connectors.builtin.malpedia import MalpediaConnector
from app.connectors.builtin.yara_rules import YaraRulesConnector
from app.connectors.builtin.phishtank import PhishTankConnector
from app.connectors.builtin.pulsedive import PulsediveConnector
from app.connectors.builtin.osv import OSVConnector
from app.connectors.builtin.urlscan import URLScanConnector
from app.connectors.builtin.vulncheck_kev import VulnCheckKEVConnector
from app.connectors.builtin.nist_800_53 import NIST80053Connector
from app.connectors.builtin.nist_csf import NISTCSFConnector

logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler()

# Source reliability overrides (0-100).
# These are applied after connector instantiation.
# 95 = authoritative/official, 80 = vetted community (default), 65 = open/noisy community.
_SOURCE_RELIABILITY: dict[str, int] = {
    "cisa-kev":      95,
    "nvd-epss":      95,
    "mitre-attack":  95,
    "spamhaus-drop": 85,
    "feodotracker":  80,
    "ransomware-live": 80,
    "ransomlook":    80,
    "ransomwatch":   78,
    "urlhaus":       75,
    "threatfox":     75,
    "dshield":       75,
    "misp-feeds":    72,
    "taxii":         70,
    "openphish":     68,
    "otx":           65,
    "malwarebazaar": 75,
    "phishtank":     72,
    "pulsedive":     72,
    "osv-dev":       85,
    "urlscan-io":    72,
    "vulncheck-kev": 90,
    "nist-800-53":   98,
    "nist-csf":      98,
    "malpedia":      85,
    "yara-rules":    80,
}

CONNECTORS = [
    OTXImportConnector(),
    MISPFeedsConnector(),
    TAXIIImportConnector(),
    RansomwatchConnector(),
    RansomwareLiveConnector(),
    RansomLookConnector(),
    DeepDarkCTIConnector(),
    LeakSiteScraper(),
    URLhausConnector(),
    ThreatFoxConnector(),
    FeodoTrackerConnector(),
    SpamhausDropConnector(),
    OpenPhishConnector(),
    DShieldConnector(),
    CISAKEVConnector(),
    NVDEPSSConnector(),
    MITREAttackConnector(),
    SigmaRulesConnector(),
    MalwareBazaarConnector(),
    MalpediaConnector(),
    YaraRulesConnector(),
    PhishTankConnector(),
    PulsediveConnector(),
    OSVConnector(),
    URLScanConnector(),
    VulnCheckKEVConnector(),
    NIST80053Connector(),
    NISTCSFConnector(),
]

# Apply reliability overrides
for _c in CONNECTORS:
    if _c.config.name in _SOURCE_RELIABILITY:
        _c.config.source_reliability = _SOURCE_RELIABILITY[_c.config.name]


async def _run_connector(connector):
    logger.info(f"Connector [{connector.config.name}]: starting run")
    try:
        result = await connector.run()
        logger.info(
            f"Connector [{connector.config.name}]: done — "
            f"{result.objects_created} created, {result.errors} errors"
        )
    except Exception as e:
        logger.error(f"Connector [{connector.config.name}]: unhandled error: {e}")
    finally:
        await connector.close()


async def _decay_indicators():
    """
    Daily indicator decay job.
    - Marks indicators with expired valid_until as revoked.
    - Reduces confidence by 10 for indicators older than 30 days (floor: 10).
    - Marks revoked if confidence reaches 10 and age > 90 days.
    """
    from app.db.opensearch import get_opensearch, STIX_INDEX
    client = get_opensearch()
    now = datetime.now(timezone.utc)
    now_str = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    cutoff_30d = (now - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    cutoff_90d = (now - timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    # 1. Expire indicators past valid_until
    try:
        resp = await client.update_by_query(
            index=STIX_INDEX,
            body={
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"type": "indicator"}},
                            {"term": {"revoked": False}},
                            {"range": {"valid_until": {"lt": now_str}}},
                        ]
                    }
                },
                "script": {
                    "source": "ctx._source.revoked = true; ctx._source.modified = params.now",
                    "params": {"now": now_str},
                },
            },
        )
        expired = resp.get("updated", 0)
        if expired:
            logger.info(f"Indicator decay: expired {expired} indicators past valid_until")
    except Exception as e:
        logger.error(f"Indicator decay (expire): {e}")

    # 2. Reduce confidence on indicators older than 30 days
    #    Skip indicators sighted within the last 30 days (x_clawint_last_sighted).
    try:
        resp = await client.update_by_query(
            index=STIX_INDEX,
            body={
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"type": "indicator"}},
                            {"term": {"revoked": False}},
                            {"range": {"created": {"lt": cutoff_30d}}},
                            {"range": {"confidence": {"gt": 10}}},
                        ],
                        "must_not": [
                            # Do not decay indicators that were recently sighted
                            {"range": {"x_clawint_last_sighted": {"gte": cutoff_30d}}},
                        ],
                    }
                },
                "script": {
                    "source": (
                        "if (ctx._source.confidence > 10) {"
                        "  ctx._source.confidence = Math.max(10, ctx._source.confidence - 10);"
                        "  ctx._source.modified = params.now;"
                        "} else {"
                        "  ctx.op = 'noop';"
                        "}"
                    ),
                    "params": {"now": now_str},
                },
            },
        )
        decayed = resp.get("updated", 0)
        if decayed:
            logger.info(f"Indicator decay: reduced confidence on {decayed} old indicators")
    except Exception as e:
        logger.error(f"Indicator decay (confidence): {e}")

    # 3. Revoke very old low-confidence indicators (>90d, confidence == 10)
    #    Skip indicators sighted within the last 30 days.
    try:
        resp = await client.update_by_query(
            index=STIX_INDEX,
            body={
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"type": "indicator"}},
                            {"term": {"revoked": False}},
                            {"range": {"created": {"lt": cutoff_90d}}},
                            {"term": {"confidence": 10}},
                        ],
                        "must_not": [
                            {"range": {"x_clawint_last_sighted": {"gte": cutoff_30d}}},
                        ],
                    }
                },
                "script": {
                    "source": "ctx._source.revoked = true; ctx._source.modified = params.now",
                    "params": {"now": now_str},
                },
            },
        )
        revoked = resp.get("updated", 0)
        if revoked:
            logger.info(f"Indicator decay: revoked {revoked} aged-out low-confidence indicators")
    except Exception as e:
        logger.error(f"Indicator decay (revoke): {e}")


def setup_scheduler():
    for connector in CONNECTORS:
        schedule = connector.config.schedule
        # Parse cron expression (5-field)
        parts = schedule.split()
        if len(parts) == 5:
            minute, hour, day, month, day_of_week = parts
            trigger = CronTrigger(
                minute=minute, hour=hour, day=day,
                month=month, day_of_week=day_of_week,
            )
        else:
            trigger = CronTrigger(hour="*/6")  # default fallback

        scheduler.add_job(
            _run_connector,
            trigger=trigger,
            args=[connector],
            id=connector.config.name,
            name=connector.config.display_name,
            replace_existing=True,
        )
        logger.info(f"Scheduled connector: {connector.config.name} ({schedule})")

    # Indicator decay — runs daily at 03:00
    scheduler.add_job(
        _decay_indicators,
        CronTrigger(hour=3, minute=0),
        id="indicator-decay",
        name="Indicator Decay",
        replace_existing=True,
    )
    logger.info("Scheduled: indicator decay (daily 03:00)")

    # Alert rule matcher — runs every hour
    from app.workers.alert_matcher import run_alert_matcher
    scheduler.add_job(
        run_alert_matcher,
        CronTrigger(minute=5),  # :05 past every hour
        id="alert-matcher",
        name="Alert Rule Matcher",
        replace_existing=True,
    )
    logger.info("Scheduled: alert rule matcher (hourly :05)")

    scheduler.start()
    logger.info(f"Scheduler started with {len(CONNECTORS)} connectors + decay job")


async def run_connector_now(name: str) -> bool:
    """Trigger a connector immediately by name."""
    connector = next((c for c in CONNECTORS if c.config.name == name), None)
    if not connector:
        return False
    task = asyncio.create_task(_run_connector(connector))
    task.add_done_callback(
        lambda t: logger.error(f"Connector [{name}]: task raised: {t.exception()}")
        if not t.cancelled() and t.exception() else None
    )
    return True
