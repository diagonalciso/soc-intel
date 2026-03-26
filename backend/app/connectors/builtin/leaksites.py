"""
Ransomware Leak Site Scraper.
Scrapes known ransomware DLS (.onion) via the Tor proxy.
Sites and addresses sourced from public security research:
CISA/FBI advisories, Sophos X-Ops, Unit42, Trend Micro, Mandiant, CrowdStrike reports.
"""
import asyncio
import hashlib
import re
import logging
from datetime import datetime, timezone

import httpx
from bs4 import BeautifulSoup

from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult
from app.db.opensearch import get_opensearch, DARKWEB_INDEX
from app.config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)

# ── Known ransomware DLS — from public threat intel reports ─────────────────
# Sources: CISA advisories, Sophos/Unit42/Trend Micro/Mandiant published reports
# Status verified against public ransomware trackers (ransomwatch, ransomware.live)

LEAK_SITES = [
    # ── RansomHub ── (CISA Advisory AA24-242A)
    {
        "group": "ransomhub",
        "display": "RansomHub",
        "url": "http://ransomxifxwc5eteopdobynonjctkxxvap77yqifu2emfbecgbqdw6qd.onion",
        "parser": "ransomhub",
    },
    # ── Akira ── (CISA Advisory AA24-109A)
    {
        "group": "akira",
        "display": "Akira",
        "url": "http://akiralkzxzq2dsrzsrvbr2xgbbu2woarfxgtka45ap5aci6c53ysqoad.onion",
        "parser": "akira",
    },
    # ── Cl0p ── (CISA/FBI Joint Advisory, MOVEit campaign)
    {
        "group": "clop",
        "display": "Cl0p",
        "url": "http://santat7kpllt6iyvqbr7q4amdv6dzrh6paatvyrzl7ry3zm72zigf4ad.onion",
        "parser": "generic",
    },
    # ── Play ── (CISA Advisory AA23-352A)
    {
        "group": "play",
        "display": "PLAY",
        "url": "http://k7kg3jqxang3wh7hnmaiokchk7qoebupfgoik6rha6mjpzwupwtj25yd.onion",
        "parser": "play",
    },
    # ── Medusa ── (Sophos X-Ops, CISA Advisory AA25-071A)
    {
        "group": "medusa",
        "display": "Medusa",
        "url": "http://medusaxko7ul4aum5ei2iceybog37j5a3m3okh3kg4suupwxzzdwqad.onion",
        "parser": "generic",
    },
    # ── BianLian ── (CISA Advisory AA23-136A)
    {
        "group": "bianlian",
        "display": "BianLian",
        "url": "http://bianlianlbc5an4kgnay3opdemgcryg2kpfcbgczopmm3dnbz3uaunad.onion",
        "parser": "bianlian",
    },
    # ── Hunters International ── (Bitdefender Labs report 2024)
    {
        "group": "hunters",
        "display": "Hunters International",
        "url": "http://hunters55rdxciehoqzwv7vgyv6nt37tbwax2reroyzxhou7my5ejyid.onion",
        "parser": "generic",
    },
    # ── Rhysida ── (CISA Advisory AA23-319A)
    {
        "group": "rhysida",
        "display": "Rhysida",
        "url": "http://rhysidafohrhyy2aszi7bm32tnjat5xri65fopcxkdfxhi4tidsg7cad.onion",
        "parser": "rhysida",
    },
    # ── Qilin / Agenda ── (Trend Micro report 2024)
    {
        "group": "qilin",
        "display": "Qilin",
        "url": "http://ijzn3sicrcy3nfghfbqznvfiwjnxp3tqkkgbvyf4bhwcrbz3hmsqlbad.onion",
        "parser": "generic",
    },
    # ── INC Ransom ── (CISA Advisory 2024) — URL pending verification
    # {
    #     "group": "incransom",
    #     "display": "INC Ransom",
    #     "url": "",  # original URL contained corrupted Cyrillic characters; needs correct address
    #     "parser": "generic",
    # },
    # ── DragonForce ── (Unit42 report 2024)
    {
        "group": "dragonforce",
        "display": "DragonForce",
        "url": "http://z3wqggtxft7id3ibr7srivv5gjof5fwg76slewnzwwakjuf3nlhukdid.onion",
        "parser": "generic",
    },
    # ── LockBit 3.0 mirrors still accessible ── (FBI/Europol Operation Cronos)
    {
        "group": "lockbit",
        "display": "LockBit 3.0",
        "url": "http://lockbit3753ekp7tf.onion",
        "parser": "lockbit",
    },
]


class LeakSiteScraper(BaseConnector):

    def __init__(self):
        super().__init__(ConnectorConfig(
            name="leaksites",
            display_name="Ransomware Leak Sites (Tor)",
            connector_type="import_external",
            description=(
                "Scrapes ransomware group leak sites via Tor. "
                "Sites sourced from CISA, FBI, Europol, and public vendor advisories."
            ),
            schedule="0 */3 * * *",  # every 3 hours
        ))

    async def run(self) -> IngestResult:
        result = IngestResult()
        self.logger.info(f"LeakSites: scraping {len(LEAK_SITES)} sites via Tor...")

        # Persist known sites to the dark web index
        await self._register_sites()

        tasks = [self._scrape_site(site) for site in LEAK_SITES]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, r in enumerate(results):
            if isinstance(r, Exception):
                self.logger.warning(f"LeakSites: {LEAK_SITES[i]['group']}: {r}")
                result.errors += 1
            elif isinstance(r, IngestResult):
                result.objects_created += r.objects_created
                result.errors += r.errors

        self.logger.info(
            f"LeakSites: done — {result.objects_created} victims scraped, {result.errors} site errors"
        )
        return result

    async def _register_sites(self):
        """Upsert DarkWebForum records for each known site."""
        client = get_opensearch()
        bulk = []
        for site in LEAK_SITES:
            doc_id = f"darkwebforum--leaksite-{site['group']}"
            doc = {
                "id": doc_id,
                "type": "darkwebforum",
                "created": _now(),
                "modified": _now(),
                "source": "leaksites-connector",
                "forum_name": site["display"],
                "group_name": site["group"],
                "url": site["url"],
                "category": "ransomware-dls",
            }
            bulk.append({"index": {"_index": DARKWEB_INDEX, "_id": doc_id}})
            bulk.append(doc)
        if bulk:
            try:
                await client.bulk(body=bulk, refresh=False)
            except Exception as e:
                logger.error(f"LeakSites: failed to register sites in OpenSearch: {e}")

    async def _scrape_site(self, site: dict) -> IngestResult:
        result = IngestResult()
        group = site["group"]
        url = site["url"]

        proxies = {
            "http://": f"socks5://{_tor_host()}:9050",
            "https://": f"socks5://{_tor_host()}:9050",
        }

        try:
            async with httpx.AsyncClient(
                proxies=proxies,
                timeout=45.0,
                verify=False,
                follow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"},
            ) as client:
                resp = await client.get(url)
                if resp.status_code != 200:
                    self.logger.warning(f"{group}: HTTP {resp.status_code}")
                    return result

                html = resp.text
                victims = _parse(site["parser"], group, html)

                if victims:
                    self.logger.info(f"{group}: found {len(victims)} victims")
                    r = await self._store_victims(group, victims)
                    result.objects_created += r.objects_created
                    result.errors += r.errors
                else:
                    self.logger.info(f"{group}: site reachable but no victims parsed (may need parser tuning)")

        except httpx.ConnectError:
            self.logger.warning(f"{group}: connection failed (site may be down or address changed)")
            result.errors += 1
        except httpx.TimeoutException:
            self.logger.warning(f"{group}: timed out via Tor")
            result.errors += 1
        except Exception as e:
            self.logger.warning(f"{group}: {type(e).__name__}: {e}")
            result.errors += 1

        return result

    async def _store_victims(self, group: str, victims: list[dict]) -> IngestResult:
        result = IngestResult()
        client = get_opensearch()
        bulk = []

        for v in victims:
            victim_name = v.get("name", "").strip()
            if not victim_name:
                continue

            doc_id = f"ransomware-leak--{group}-{_slug(victim_name)}"
            doc = {
                "id": doc_id,
                "type": "ransomware-leak",
                "created": _now(),
                "modified": _now(),
                "source": "leaksites-connector",
                "group_name": group,
                "victim_name": victim_name,
                "victim_domain": v.get("domain", ""),
                "country": v.get("country", ""),
                "sector": v.get("sector", ""),
                "date_posted": v.get("date", _now()),
                "files_published": v.get("published", False),
                "data_size_gb": v.get("size_gb"),
                "description": v.get("description", ""),
            }
            bulk.append({"index": {"_index": DARKWEB_INDEX, "_id": doc_id}})
            bulk.append(doc)
            result.objects_created += 1

        if bulk:
            try:
                resp = await client.bulk(body=bulk, refresh=False)
                errors = sum(1 for item in resp["items"] if item.get("index", {}).get("error"))
                result.errors += errors
                result.objects_created -= errors
            except Exception as e:
                logger.error(f"LeakSites: OpenSearch bulk error for {group}: {e}")
                result.errors += len(bulk) // 2
                result.objects_created = 0

        return result


# ── Parsers ─────────────────────────────────────────────────────────────────

def _parse(parser_name: str, group: str, html: str) -> list[dict]:
    try:
        parsers = {
            "ransomhub": _parse_ransomhub,
            "akira": _parse_akira,
            "play": _parse_play,
            "bianlian": _parse_bianlian,
            "rhysida": _parse_rhysida,
            "lockbit": _parse_lockbit,
            "generic": _parse_generic,
        }
        fn = parsers.get(parser_name, _parse_generic)
        return fn(html)
    except Exception as e:
        logger.warning(f"Parser [{parser_name}] failed: {e}")
        return []


def _parse_generic(html: str) -> list[dict]:
    """Generic parser — tries common patterns for victim names."""
    soup = BeautifulSoup(html, "html.parser")
    victims = []

    # Pattern: look for elements with class containing 'victim', 'company', 'target', 'name'
    for selector in [
        "[class*='victim']", "[class*='company']", "[class*='target']",
        "[class*='name']", "[class*='title']", "h2", "h3",
        "[class*='post']", "[class*='entry']",
    ]:
        try:
            elements = soup.select(selector)
            for el in elements:
                text = el.get_text(strip=True)
                if 5 < len(text) < 200 and not _is_nav_text(text):
                    victims.append({"name": text})
            if victims:
                break
        except Exception:
            continue

    return _dedupe(victims)


def _parse_ransomhub(html: str) -> list[dict]:
    soup = BeautifulSoup(html, "html.parser")
    victims = []
    for el in soup.select(".col-span-2, .victim-name, h3, .font-bold"):
        text = el.get_text(strip=True)
        if 3 < len(text) < 150 and not _is_nav_text(text):
            parent_text = el.parent.get_text(separator=" ", strip=True) if el.parent else ""
            domain = _extract_domain(parent_text)
            country = _extract_country(parent_text)
            victims.append({"name": text, "domain": domain, "country": country})
    return _dedupe(victims)


def _parse_akira(html: str) -> list[dict]:
    soup = BeautifulSoup(html, "html.parser")
    victims = []
    for el in soup.select(".post-header, .victim, h2.title, .company-name, p.name"):
        text = el.get_text(strip=True)
        if 3 < len(text) < 150 and not _is_nav_text(text):
            victims.append({"name": text})
    if not victims:
        return _parse_generic(html)
    return _dedupe(victims)


def _parse_play(html: str) -> list[dict]:
    soup = BeautifulSoup(html, "html.parser")
    victims = []
    for el in soup.select("h3, .name, .company, li > a"):
        text = el.get_text(strip=True)
        if 3 < len(text) < 150 and not _is_nav_text(text):
            href = el.get("href", "")
            domain = _extract_domain(href + " " + text)
            victims.append({"name": text, "domain": domain})
    return _dedupe(victims)


def _parse_bianlian(html: str) -> list[dict]:
    soup = BeautifulSoup(html, "html.parser")
    victims = []
    for el in soup.select(".post, .victim, article, h2, h3"):
        text = el.get_text(strip=True)
        if 3 < len(text) < 150 and not _is_nav_text(text):
            victims.append({"name": text})
    return _dedupe(victims)


def _parse_rhysida(html: str) -> list[dict]:
    soup = BeautifulSoup(html, "html.parser")
    victims = []
    for el in soup.select(".target, .victim, h3, .organization"):
        text = el.get_text(strip=True)
        if 3 < len(text) < 150 and not _is_nav_text(text):
            victims.append({"name": text})
    if not victims:
        return _parse_generic(html)
    return _dedupe(victims)


def _parse_lockbit(html: str) -> list[dict]:
    soup = BeautifulSoup(html, "html.parser")
    victims = []
    for el in soup.select(".post-title, .company, h4, .countdown"):
        text = el.get_text(strip=True)
        if 3 < len(text) < 150 and not _is_nav_text(text):
            victims.append({"name": text})
    return _dedupe(victims)


# ── Helpers ──────────────────────────────────────────────────────────────────

_NAV_WORDS = {
    "home", "about", "contact", "login", "logout", "register", "download",
    "search", "menu", "navigation", "cookie", "privacy", "terms", "back",
    "next", "previous", "page", "load more", "read more", "click here",
}


def _is_nav_text(text: str) -> bool:
    return text.lower().strip() in _NAV_WORDS


def _extract_domain(text: str) -> str:
    m = re.search(r'(?:https?://)?(?:www\.)?([a-z0-9\-]+\.[a-z]{2,})', text.lower())
    return m.group(1) if m else ""


def _extract_country(text: str) -> str:
    countries = [
        "USA", "United States", "UK", "United Kingdom", "Germany", "France",
        "Canada", "Australia", "Italy", "Spain", "Netherlands", "Brazil",
        "India", "Japan", "Russia", "China",
    ]
    for c in countries:
        if c.lower() in text.lower():
            return c
    return ""


def _dedupe(victims: list[dict]) -> list[dict]:
    seen = set()
    result = []
    for v in victims:
        key = v.get("name", "").lower().strip()
        if key and key not in seen:
            seen.add(key)
            result.append(v)
    return result


def _slug(text: str) -> str:
    return re.sub(r'[^a-z0-9]+', '-', text.lower().strip())[:64]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _tor_host() -> str:
    """Return the Tor proxy hostname (Docker service name or localhost)."""
    import os
    return os.getenv("TOR_HOST", "tor")
