"""
Telegram CTI monitor.
Polls configured public Telegram channels for breach/threat actor announcements.
Uses Telethon MTProto with a StringSession (no interactive auth required after setup).

Setup:
1. Get API ID + hash at https://my.telegram.org/apps (free)
2. Run `python backend/generate_tg_session.py` once to generate session string
3. Set TG_API_ID, TG_API_HASH, TG_SESSION, TG_CTI_CHANNELS in .env

TG_CTI_CHANNELS: comma-separated list of public channel usernames or invite links.
Examples of public threat intel / breach monitoring channels to consider:
  - @vxunderground          (malware/threat intel)
  - @darkwebinformer        (dark web breach announcements)
  - @breachdetector         (breach monitoring)
  - @H4ckManac              (breach aggregator)
  - @RansomwareNews         (ransomware tracking)
  - @DataBreachNews         (breach news aggregator)

Disabled gracefully if TG_API_ID/TG_API_HASH/TG_SESSION not set.
"""
import re
import hashlib
import logging
from datetime import datetime, timezone, timedelta

from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult
from app.db.opensearch import get_opensearch, DARKWEB_INDEX
from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

# Keywords that flag a message as breach/threat-intel relevant
KEYWORDS = [
    "shinyhunters", "shiny hunters",
    "breachforums", "breach forum",
    "sp1d3r", "unc5537",
    "data breach", "database leak", "db leak",
    "leaked", "combo list", "combolist",
    "stealer log", "infostealer",
    "ransomware", "ransom",
    "credentials", "passwd", "password dump",
    "0day", "zero day", "rce",
    "initial access", "access broker",
    "scattered spider",
]

_KW_RE = re.compile(
    r'(' + '|'.join(re.escape(k) for k in KEYWORDS) + r')',
    re.IGNORECASE,
)

# How far back to look on each poll (hours)
LOOKBACK_HOURS = 3


class TelegramCTIConnector(BaseConnector):

    def __init__(self):
        super().__init__(ConnectorConfig(
            name="telegram-cti",
            display_name="Telegram CTI Monitor",
            connector_type="import_external",
            description=(
                "Polls configured public Telegram channels for breach announcements, "
                "threat actor activity, and CTI relevant to ShinyHunters/BreachForums. "
                "Requires TG_API_ID, TG_API_HASH, TG_SESSION in environment."
            ),
            schedule="0 */1 * * *",  # hourly
        ))

    async def run(self) -> IngestResult:
        result = IngestResult()

        if not _is_configured():
            self.logger.info("Telegram CTI: not configured (TG_API_ID/TG_API_HASH/TG_SESSION missing) — skipping")
            return result

        channels = _get_channels()
        if not channels:
            self.logger.info("Telegram CTI: no channels configured (TG_CTI_CHANNELS empty) — skipping")
            return result

        try:
            from telethon import TelegramClient
            from telethon.sessions import StringSession
        except ImportError:
            self.logger.error("Telegram CTI: telethon not installed — run: pip install telethon")
            result.errors += 1
            return result

        tg = TelegramClient(
            StringSession(settings.tg_session),
            settings.tg_api_id,
            settings.tg_api_hash,
        )

        try:
            await tg.connect()
            if not await tg.is_user_authorized():
                self.logger.error("Telegram CTI: session invalid — re-run generate_tg_session.py")
                result.errors += 1
                return result

            self.logger.info(f"Telegram CTI: polling {len(channels)} channels...")
            cutoff = datetime.now(timezone.utc) - timedelta(hours=LOOKBACK_HOURS)

            for channel in channels:
                try:
                    r = await self._poll_channel(tg, channel.strip(), cutoff)
                    result.objects_created += r.objects_created
                    result.errors += r.errors
                except Exception as e:
                    self.logger.warning(f"Telegram CTI: [{channel}] error: {e}")
                    result.errors += 1

        finally:
            await tg.disconnect()

        self.logger.info(
            f"Telegram CTI: {result.objects_created} messages stored, {result.errors} errors"
        )
        return result

    async def _poll_channel(self, tg, channel: str, cutoff: datetime) -> IngestResult:
        result = IngestResult()
        try:
            entity = await tg.get_entity(channel)
        except Exception as e:
            self.logger.warning(f"Telegram CTI: cannot resolve channel '{channel}': {e}")
            result.errors += 1
            return result

        client = get_opensearch()
        bulk = []
        now = _now()

        async for msg in tg.iter_messages(entity, limit=200):
            if not msg.date:
                continue
            msg_dt = msg.date.replace(tzinfo=timezone.utc) if msg.date.tzinfo is None else msg.date
            if msg_dt < cutoff:
                break

            text = msg.message or ""
            if not text or not _KW_RE.search(text):
                continue

            channel_name = getattr(entity, "username", None) or str(entity.id)
            msg_url = f"https://t.me/{channel_name}/{msg.id}" if channel_name else ""
            doc_id = f"tg-msg--{hashlib.sha1(f'{channel_name}:{msg.id}'.encode()).hexdigest()[:20]}"

            doc = {
                "id": doc_id,
                "type": "tg-message",
                "created": msg_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "modified": now,
                "source": "telegram-cti",
                "channel": channel_name,
                "channel_title": getattr(entity, "title", channel_name),
                "message_id": msg.id,
                "message_url": msg_url,
                "text": text[:2000],
                "keywords_matched": [m.lower() for m in set(_KW_RE.findall(text))],
                "views": getattr(msg, "views", None),
                "forwards": getattr(msg, "forwards", None),
            }
            bulk.append({"create": {"_index": DARKWEB_INDEX, "_id": doc_id}})
            bulk.append(doc)
            result.objects_created += 1

        if bulk:
            try:
                resp = await client.bulk(body=bulk, refresh=False)
                for item in resp["items"]:
                    err = item.get("create", {}).get("error")
                    if err and err.get("type") != "version_conflict_engine_exception":
                        result.errors += 1
                        result.objects_created -= 1
            except Exception as e:
                self.logger.error(f"Telegram CTI: bulk error [{channel}]: {e}")
                result.errors += len(bulk) // 2
                result.objects_created = 0

        if result.objects_created > 0:
            self.logger.info(
                f"Telegram CTI: [{channel}] stored {result.objects_created} new messages"
            )
        return result


def _is_configured() -> bool:
    return bool(
        getattr(settings, "tg_api_id", None) and
        getattr(settings, "tg_api_hash", None) and
        getattr(settings, "tg_session", None)
    )


def _get_channels() -> list[str]:
    raw = getattr(settings, "tg_cti_channels", "") or ""
    return [c.strip() for c in raw.split(",") if c.strip()]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
