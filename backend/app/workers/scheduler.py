"""
Connector scheduler.
Runs import connectors on their configured cron schedules.
"""
import asyncio
import logging
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
from app.connectors.builtin.otx_import import OTXImportConnector
from app.connectors.builtin.misp_feeds import MISPFeedsConnector
from app.connectors.builtin.taxii_import import TAXIIImportConnector

logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler()

CONNECTORS = [
    OTXImportConnector(),
    MISPFeedsConnector(),
    TAXIIImportConnector(),
    RansomwatchConnector(),
    RansomwareLiveConnector(),
    LeakSiteScraper(),
    URLhausConnector(),
    ThreatFoxConnector(),
    FeodoTrackerConnector(),
    SpamhausDropConnector(),
    OpenPhishConnector(),
    DShieldConnector(),
    CISAKEVConnector(),
    MITREAttackConnector(),
]


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

    scheduler.start()
    logger.info(f"Scheduler started with {len(CONNECTORS)} connectors")


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
