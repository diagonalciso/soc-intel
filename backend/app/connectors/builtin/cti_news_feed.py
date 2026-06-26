"""
CTI news feed connector.
Scrapes RSS feeds from major threat intelligence / breach reporting outlets.
Filters for ShinyHunters, BreachForums, UNC5537, and related actors.
Stores matched articles as cti-report objects in the darkweb index.

No API key required. Uses lxml for RSS/Atom parsing.
"""
import hashlib
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from lxml import etree

from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult
from app.db.opensearch import get_opensearch, DARKWEB_INDEX

# RSS/Atom feeds to monitor
CTI_FEEDS = [
    {"name": "bleepingcomputer",  "url": "https://www.bleepingcomputer.com/feed/",                   "reliability": 88},
    {"name": "therecord",         "url": "https://therecord.media/feed",                              "reliability": 90},
    {"name": "krebs",             "url": "https://krebsonsecurity.com/feed/",                          "reliability": 92},
    {"name": "securityweek",      "url": "https://feeds.feedburner.com/securityweek",                  "reliability": 85},
    {"name": "databreaches",      "url": "https://www.databreaches.net/feed/",                         "reliability": 82},
    {"name": "darkreading",       "url": "https://www.darkreading.com/rss.xml",                        "reliability": 83},
    {"name": "hackread",          "url": "https://hackread.com/feed/",                                 "reliability": 78},
    # cybernews.com returns 403 for bots — removed
]

# Threat actor / keyword filter — match any of these (case-insensitive)
KEYWORDS = [
    "shinyhunters", "shiny hunters",
    "breachforums", "breach forums", "breachforum",
    "sp1d3r",
    "unc5537",
    "scattered spider",
    "lapsus",
    "nmfb",                     # BreachForums admin handle
    "pompompurin",              # previous BF admin
    "snowflake breach",
    "snowflake hack",
    "infostealer",
    "stealer logs",
    "combolists",
    "combo list",
]

_KW_RE = re.compile(
    r'\b(' + '|'.join(re.escape(k) for k in KEYWORDS) + r')\b',
    re.IGNORECASE,
)


class CTINewsFeedConnector(BaseConnector):

    def __init__(self):
        super().__init__(ConnectorConfig(
            name="cti-news-feed",
            display_name="CTI News Feed (RSS)",
            connector_type="import_external",
            description=(
                "Monitors RSS feeds from BleepingComputer, The Record, Krebs, SecurityWeek, "
                "and others. Filters for ShinyHunters, BreachForums, UNC5537, stealer log activity, "
                "and related threat intel keywords."
            ),
            schedule="0 */2 * * *",  # every 2 hours
        ))

    async def run(self) -> IngestResult:
        self.logger.info(f"CTINews: scanning {len(CTI_FEEDS)} RSS feeds...")
        result = IngestResult()

        for feed in CTI_FEEDS:
            try:
                r = await self._process_feed(feed)
                result.objects_created += r.objects_created
                result.errors += r.errors
            except Exception as e:
                self.logger.warning(f"CTINews: [{feed['name']}] unhandled error: {e}")
                result.errors += 1

        self.logger.info(
            f"CTINews: {result.objects_created} reports stored, {result.errors} errors"
        )
        return result

    async def _process_feed(self, feed: dict) -> IngestResult:
        result = IngestResult()
        try:
            resp = await self.http.get(
                feed["url"],
                headers={"User-Agent": "SOCINT/1.0 CTI Monitor (research)"},
            )
            resp.raise_for_status()
        except Exception as e:
            self.logger.warning(f"CTINews: [{feed['name']}] fetch failed: {e}")
            result.errors += 1
            return result

        try:
            items = _parse_feed(resp.content)
        except Exception as e:
            self.logger.warning(f"CTINews: [{feed['name']}] parse failed: {e}")
            result.errors += 1
            return result

        matched = [i for i in items if _matches(i)]
        if not matched:
            return result

        client = get_opensearch()
        bulk = []
        now = _now()

        for item in matched:
            url = item.get("link", "")
            doc_id = f"cti-report--{hashlib.sha1(url.encode()).hexdigest()[:20]}"
            doc = {
                "id": doc_id,
                "type": "cti-report",
                "created": item.get("published", now),
                "modified": now,
                "source": feed["name"],
                "source_reliability": feed["reliability"],
                "title": item.get("title", "")[:300],
                "url": url,
                "summary": item.get("summary", "")[:1000],
                "published": item.get("published", now),
                "keywords_matched": _extract_keywords(item),
                "threat_actors": _extract_actors(item),
            }
            bulk.append({"create": {"_index": DARKWEB_INDEX, "_id": doc_id}})
            bulk.append(doc)
            result.objects_created += 1

        if bulk:
            try:
                resp_bulk = await client.bulk(body=bulk, refresh=False)
                for item in resp_bulk["items"]:
                    err = item.get("create", {}).get("error")
                    if err and err.get("type") != "version_conflict_engine_exception":
                        result.errors += 1
                        result.objects_created -= 1
            except Exception as e:
                self.logger.error(f"CTINews: [{feed['name']}] bulk error: {e}")
                result.errors += len(bulk) // 2
                result.objects_created = 0

        if result.objects_created > 0:
            self.logger.info(
                f"CTINews: [{feed['name']}] stored {result.objects_created} new reports"
            )
        return result


# ── Feed parsing ───────────────────��────────────────────────────────────────

_NS = {
    "atom": "http://www.w3.org/2005/Atom",
    "dc":   "http://purl.org/dc/elements/1.1/",
    "content": "http://purl.org/rss/1.0/modules/content/",
}


def _parse_feed(raw: bytes) -> list[dict]:
    """Parse RSS 2.0 or Atom feed. Returns list of {title, link, summary, published}."""
    root = etree.fromstring(raw)
    tag = root.tag.lower()

    if "feed" in tag:
        return _parse_atom(root)
    return _parse_rss(root)


def _parse_rss(root) -> list[dict]:
    items = []
    for item in root.findall(".//item"):
        title = _text(item, "title")
        link = _text(item, "link") or _text(item, "guid")
        pub = _text(item, "pubDate") or _text(item, "dc:date", _NS)
        summary = _text(item, "description") or _text(item, "content:encoded", _NS) or ""
        summary = re.sub(r"<[^>]+>", " ", summary).strip()
        items.append({
            "title": title,
            "link": link,
            "summary": summary[:1000],
            "published": _parse_date(pub),
        })
    return items


def _parse_atom(root) -> list[dict]:
    items = []
    ns = root.tag.split("}")[0].lstrip("{") if "}" in root.tag else ""
    prefix = f"{{{ns}}}" if ns else ""
    for entry in root.findall(f"{prefix}entry"):
        title = _text(entry, f"{prefix}title")
        link_el = entry.find(f"{prefix}link[@rel='alternate']") or entry.find(f"{prefix}link")
        link = link_el.get("href", "") if link_el is not None else ""
        pub = _text(entry, f"{prefix}published") or _text(entry, f"{prefix}updated")
        summary = _text(entry, f"{prefix}summary") or _text(entry, f"{prefix}content") or ""
        summary = re.sub(r"<[^>]+>", " ", summary).strip()
        items.append({
            "title": title,
            "link": link,
            "summary": summary[:1000],
            "published": _parse_date(pub),
        })
    return items


def _text(el, path: str, ns: dict | None = None) -> str:
    child = el.find(path, ns or {})
    if child is None:
        return ""
    return (child.text or "").strip()


def _parse_date(s: str) -> str:
    if not s:
        return _now()
    try:
        dt = parsedate_to_datetime(s)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    except Exception:
        pass
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    except Exception:
        return _now()


# ── Matching ──────────────────────���───────────────────────��──────────────────

def _matches(item: dict) -> bool:
    haystack = f"{item.get('title', '')} {item.get('summary', '')}".lower()
    return bool(_KW_RE.search(haystack))


def _extract_keywords(item: dict) -> list[str]:
    haystack = f"{item.get('title', '')} {item.get('summary', '')}"
    found = _KW_RE.findall(haystack)
    return list({k.lower() for k in found})


_ACTOR_MAP = {
    "shinyhunters":   "shinyhunters",
    "shiny hunters":  "shinyhunters",
    "breachforums":   "breachforums",
    "sp1d3r":         "unc5537",
    "unc5537":        "unc5537",
    "scattered spider": "scattered-spider",
    "lapsus":         "lapsus$",
    "nmfb":           "breachforums",
    "pompompurin":    "breachforums",
}


def _extract_actors(item: dict) -> list[str]:
    haystack = f"{item.get('title', '')} {item.get('summary', '')}".lower()
    actors = set()
    for kw, actor in _ACTOR_MAP.items():
        if re.search(r'\b' + re.escape(kw) + r'\b', haystack, re.IGNORECASE):
            actors.add(actor)
    return list(actors)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
