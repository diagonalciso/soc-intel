"""
ShinyHunters breach tracker.
Tracks known breaches attributed to ShinyHunters and related BreachForums actors.
Enriches each with HIBP breach data where available (victim count, data classes, date).

Also fetches:
  - OTX public pulses tagged "shinyhunters" → STIX indicators via push_to_platform()
  - MISP Galaxy threat-actor cluster → STIX threat-actor object via push_to_platform()
  - ransomware.live recent victims for shinyhunters → STIX identity+relationship objects

ShinyHunters does not operate a public .onion DLS — they sell/leak on BreachForums.
This connector uses a curated breach reference list sourced from public CTI reporting
(Unit42, CrowdStrike, Mandiant, CISA, ZDNet, BleepingComputer, Wired) combined with
live HIBP API enrichment.
"""
import asyncio
import logging
import re
import uuid
from datetime import datetime, timezone

from app.connectors.sdk.base import BaseConnector, ConnectorConfig, IngestResult
from app.config import get_settings
from app.db.opensearch import get_opensearch, DARKWEB_INDEX

logger = logging.getLogger(__name__)
settings = get_settings()

OTX_BASE = "https://otx.alienvault.com/api/v1"
MISP_GALAXY_URL = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"
RLIVE_URL = "https://api.ransomware.live/recentvictims"

_ACTOR_NAMES = {"shinyhunters", "shinySp1d3r", "shiny hunters"}

_OTX_TYPE_MAP = {
    "IPv4":            lambda v: f"[ipv4-addr:value = '{v}']",
    "IPv6":            lambda v: f"[ipv6-addr:value = '{v}']",
    "domain":          lambda v: f"[domain-name:value = '{v}']",
    "hostname":        lambda v: f"[domain-name:value = '{v}']",
    "URL":             lambda v: "[url:value = '" + v.replace("'", "%27") + "']",
    "FileHash-MD5":    lambda v: f"[file:hashes.MD5 = '{v}']",
    "FileHash-SHA1":   lambda v: f"[file:hashes.'SHA-1' = '{v}']",
    "FileHash-SHA256": lambda v: f"[file:hashes.'SHA-256' = '{v}']",
    "email":           lambda v: f"[email-addr:value = '{v}']",
}

HIBP_BREACHES_URL = "https://haveibeenpwned.com/api/v3/breaches"

# Curated list of ShinyHunters-attributed breaches.
# Sources: Unit42, CrowdStrike, Mandiant, BleepingComputer, Wired, ZDNet, The Record.
# hibp_name: the breach Name field in HIBP (for enrichment); None = not in HIBP yet.
SHINYHUNTERS_BREACHES = [
    # ── 2024 Snowflake campaign ──────────────────────────────────────────────
    {"victim": "Ticketmaster / Live Nation",  "domain": "ticketmaster.com",    "date": "2024-05-20", "records": 560_000_000, "data": ["names", "addresses", "phone numbers", "partial payment cards"], "hibp_name": "Ticketmaster"},
    {"victim": "Santander",                   "domain": "santander.com",        "date": "2024-05-01", "records": 30_000_000,  "data": ["names", "bank account numbers", "HR data"], "hibp_name": None},
    {"victim": "Advance Auto Parts",          "domain": "advanceautoparts.com", "date": "2024-06-01", "records": 380_000_000, "data": ["names", "email addresses", "SSNs", "employment data"], "hibp_name": "AdvanceAutoParts"},
    {"victim": "AT&T",                        "domain": "att.com",              "date": "2024-04-01", "records": 73_000_000,  "data": ["email addresses", "phone numbers", "SSNs", "passcodes"], "hibp_name": "ATT"},
    {"victim": "QuoteWizard / LendingTree",   "domain": "quotewizard.com",      "date": "2024-06-01", "records": 190_000_000, "data": ["names", "email addresses", "phone numbers", "vehicle data"], "hibp_name": None},
    {"victim": "Neiman Marcus",               "domain": "neimanmarcus.com",     "date": "2024-05-01", "records": 31_000_000,  "data": ["names", "email addresses", "phone numbers", "gift card data"], "hibp_name": "NeimanMarcus2024"},
    # ── 2022 ────────────────────────────────────────────────────────────────
    {"victim": "Microsoft",                   "domain": "microsoft.com",        "date": "2022-03-26", "records": None,         "data": ["source code (Bing, Cortana)"], "hibp_name": None},
    {"victim": "T-Mobile",                    "domain": "t-mobile.com",         "date": "2022-04-01", "records": 37_000_000,  "data": ["names", "email addresses", "SSNs", "PINs"], "hibp_name": "TMobile2022"},
    {"victim": "Plex",                        "domain": "plex.tv",              "date": "2022-08-24", "records": 15_000_000,  "data": ["email addresses", "usernames", "hashed passwords"], "hibp_name": "Plex"},
    {"victim": "Dunzo",                       "domain": "dunzo.com",            "date": "2022-07-01", "records": 3_500_000,   "data": ["email addresses", "phone numbers", "addresses"], "hibp_name": None},
    # ── 2021 ────────────────────────────────────────────────────────────────
    {"victim": "Mercari",                     "domain": "mercari.com",          "date": "2021-03-01", "records": None,         "data": ["names", "email addresses", "banking information"], "hibp_name": None},
    {"victim": "Reverb",                      "domain": "reverb.com",           "date": "2021-07-01", "records": 5_700_000,   "data": ["names", "email addresses", "phone numbers", "PayPal info"], "hibp_name": "Reverb"},
    # ── 2020 ────────────────────────────────────────────────────────────────
    {"victim": "Tokopedia",                   "domain": "tokopedia.com",        "date": "2020-05-01", "records": 91_000_000,  "data": ["names", "email addresses", "hashed passwords"], "hibp_name": "Tokopedia"},
    {"victim": "Wattpad",                     "domain": "wattpad.com",          "date": "2020-06-01", "records": 271_000_000, "data": ["names", "email addresses", "IP addresses", "hashed passwords"], "hibp_name": "Wattpad"},
    {"victim": "BigBasket",                   "domain": "bigbasket.com",        "date": "2020-10-01", "records": 20_000_000,  "data": ["names", "email addresses", "phone numbers", "hashed passwords", "addresses"], "hibp_name": "BigBasket"},
    {"victim": "Dave",                        "domain": "dave.com",             "date": "2020-07-01", "records": 7_500_000,   "data": ["names", "email addresses", "phone numbers", "SSNs (partial)"], "hibp_name": "Dave"},
    {"victim": "Havenly",                     "domain": "havenly.com",          "date": "2020-07-01", "records": 1_300_000,   "data": ["names", "email addresses", "IP addresses", "hashed passwords"], "hibp_name": "Havenly"},
    {"victim": "Promo.com",                   "domain": "promo.com",            "date": "2020-07-01", "records": 22_000_000,  "data": ["names", "email addresses", "hashed passwords"], "hibp_name": "Promo"},
    {"victim": "Mashable",                    "domain": "mashable.com",         "date": "2020-07-01", "records": 2_200_000,   "data": ["names", "email addresses", "social profiles"], "hibp_name": None},
    {"victim": "Couchsurfing",               "domain": "couchsurfing.com",     "date": "2020-07-01", "records": 17_000_000,  "data": ["names", "email addresses", "IP addresses", "hashed passwords"], "hibp_name": "Couchsurfing"},
]


class ShinyHuntersConnector(BaseConnector):

    def __init__(self):
        super().__init__(ConnectorConfig(
            name="shinyhunters",
            display_name="ShinyHunters Breach Tracker",
            connector_type="import_external",
            description=(
                "Tracks breaches attributed to ShinyHunters and related BreachForums actors. "
                "Curated from public CTI reporting (Unit42, CrowdStrike, BleepingComputer, etc.). "
                "Enriched via HIBP API where available."
            ),
            schedule="0 12 * * *",  # once daily at noon
            source_reliability=80,
        ))

    async def run(self) -> IngestResult:
        self.logger.info("ShinyHunters: starting breach ingestion...")
        result = IngestResult()

        # Run all sources concurrently
        breaches_result, otx_result, profile_result, live_result = await asyncio.gather(
            self._ingest_breaches(),
            self._ingest_otx_pulses(),
            self._ingest_misp_profile(),
            self._ingest_live_victims(),
            return_exceptions=True,
        )
        for r in (breaches_result, otx_result, profile_result, live_result):
            if isinstance(r, Exception):
                self.logger.error(f"ShinyHunters: sub-task error: {r}")
                result.errors += 1
            elif isinstance(r, IngestResult):
                result.objects_created += r.objects_created
                result.errors += r.errors

        self.logger.info(
            f"ShinyHunters: {result.objects_created} objects ingested, {result.errors} errors"
        )
        return result

    async def _ingest_breaches(self) -> IngestResult:
        result = IngestResult()
        hibp_index = await self._fetch_hibp_index()
        client = get_opensearch()
        bulk = []
        now = _now()

        for breach in SHINYHUNTERS_BREACHES:
            victim = breach["victim"]
            domain = breach["domain"]
            date = breach["date"]
            records = breach.get("records")
            data_classes = breach.get("data", [])
            hibp_name = breach.get("hibp_name")

            # Enrich from HIBP if matched
            if hibp_name and hibp_name in hibp_index:
                h = hibp_index[hibp_name]
                records = records or h.get("PwnCount")
                if not data_classes:
                    data_classes = h.get("DataClasses", [])
                date = h.get("BreachDate") or date

            doc_id = f"credential-exposure--shinyhunters-{_slug(victim)}"
            doc = {
                "id": doc_id,
                "type": "credential-exposure",
                "created": _iso(date),
                "modified": now,
                "source": "shinyhunters-connector",
                "threat_actor": "shinyhunters",
                "platform": "breachforums",
                "domain": domain,
                "victim_name": victim,
                "exposure_type": "breach",
                "date_discovered": _iso(date),
                "records_exposed": records,
                "data_classes": data_classes,
            }
            # create-only: preserves first-seen timestamp for existing records
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
                self.logger.error(f"ShinyHunters: OpenSearch bulk error: {e}")
                result.errors += len(bulk) // 2
                result.objects_created = 0

        self.logger.info(
            f"ShinyHunters: {result.objects_created} breach records ingested, "
            f"{result.errors} errors, {len(hibp_index)} HIBP breaches indexed"
        )
        return result

    async def _fetch_hibp_index(self) -> dict:
        try:
            resp = await self.http.get(
                HIBP_BREACHES_URL,
                headers={"User-Agent": "SOCINT/1.0 CTI Platform (research)"},
            )
            resp.raise_for_status()
            breaches = resp.json()
            return {b["Name"]: b for b in breaches if isinstance(b, dict)}
        except Exception as e:
            self.logger.warning(f"ShinyHunters: HIBP fetch failed (enrichment skipped): {e}")
            return {}

    async def _ingest_otx_pulses(self) -> IngestResult:
        """Search OTX for public pulses tagged 'shinyhunters'; ingest IOCs as STIX indicators."""
        result = IngestResult()
        if not settings.otx_api_key:
            self.logger.info("ShinyHunters/OTX: skipping — OTX_API_KEY not set")
            return result

        headers = {"X-OTX-API-KEY": settings.otx_api_key, "Accept": "application/json"}
        try:
            resp = await self.http.get(
                f"{OTX_BASE}/search/pulses",
                headers=headers,
                params={"q": "shinyhunters", "sort": "modified", "limit": 25},
            )
            resp.raise_for_status()
            pulses = resp.json().get("results", [])
        except Exception as e:
            self.logger.warning(f"ShinyHunters/OTX: search failed: {e}")
            result.errors += 1
            return result

        stix_objects = []
        now = _now()
        for pulse in pulses:
            pulse_id   = pulse.get("id", "")
            pulse_name = pulse.get("name", "unknown")
            valid_from = _iso(pulse.get("created") or "")
            labels     = ["otx", "shinyhunters"] + [
                t.lower().replace(" ", "-")[:64]
                for t in pulse.get("tags", []) if isinstance(t, str)
            ]
            refs = [{"source_name": "AlienVault OTX", "url": f"https://otx.alienvault.com/pulse/{pulse_id}"}]
            for ioc in pulse.get("indicators", []):
                ioc_type  = ioc.get("type", "")
                ioc_value = (ioc.get("indicator") or "").strip()
                if not ioc_value or ioc_type not in _OTX_TYPE_MAP:
                    continue
                stix_objects.append({
                    "type":            "indicator",
                    "name":            f"{ioc_type}: {ioc_value[:100]}",
                    "description":     ioc.get("description") or pulse_name,
                    "pattern":         _OTX_TYPE_MAP[ioc_type](ioc_value),
                    "pattern_type":    "stix",
                    "indicator_types": ["malicious-activity"],
                    "valid_from":      valid_from,
                    "confidence":      65,
                    "labels":          list(dict.fromkeys(labels)),
                    "x_clawint_source":     "otx-shinyhunters",
                    "x_clawint_tlp":        "TLP:WHITE",
                    "x_clawint_pulse_id":   pulse_id,
                    "x_clawint_pulse_name": pulse_name,
                    "external_references":  refs,
                })
                if len(stix_objects) >= 250:
                    r = await self.push_to_platform(stix_objects)
                    result.objects_created += r.objects_created
                    result.errors          += r.errors
                    stix_objects = []

        if stix_objects:
            r = await self.push_to_platform(stix_objects)
            result.objects_created += r.objects_created
            result.errors          += r.errors

        self.logger.info(f"ShinyHunters/OTX: {result.objects_created} IOCs from {len(pulses)} pulses")
        return result

    async def _ingest_misp_profile(self) -> IngestResult:
        """Fetch MISP Galaxy threat-actor cluster and store ShinyHunters as a STIX threat-actor."""
        result = IngestResult()
        try:
            resp = await self.http.get(
                MISP_GALAXY_URL,
                headers={"User-Agent": "SOCINT/1.0 CTI Platform (research)"},
                timeout=30,
            )
            resp.raise_for_status()
            galaxy = resp.json()
        except Exception as e:
            self.logger.warning(f"ShinyHunters/MISP: fetch failed: {e}")
            result.errors += 1
            return result

        profile = None
        for entry in galaxy.get("values", []):
            if entry.get("value", "").lower() in _ACTOR_NAMES:
                profile = entry
                break

        if not profile:
            self.logger.info("ShinyHunters/MISP: actor not found in galaxy")
            return result

        meta = profile.get("meta", {})
        aliases  = meta.get("synonyms", [])
        refs_raw = meta.get("refs", [])

        stix_actor = {
            "type":              "threat-actor",
            "name":              profile["value"],
            "description":       profile.get("description", ""),
            "aliases":           aliases,
            "threat_actor_types": ["criminal"],
            "sophistication":    "intermediate",
            "resource_level":    "criminal-infrastructure",
            "primary_motivation":"financial-gain",
            "labels":            ["shinyhunters", "breachforums", "data-theft", "misp-galaxy"],
            "x_clawint_source":  "misp-galaxy",
            "x_clawint_tlp":     "TLP:WHITE",
            "confidence":        85,
            "valid_from":        _now(),
            "external_references": [
                {"source_name": r, "url": r} if r.startswith("http")
                else {"source_name": r}
                for r in refs_raw[:6]
            ],
        }

        r = await self.push_to_platform([stix_actor])
        result.objects_created += r.objects_created
        result.errors          += r.errors
        self.logger.info(f"ShinyHunters/MISP: threat-actor profile ingested ({r.objects_created} obj)")
        return result

    async def _ingest_live_victims(self) -> IngestResult:
        """Fetch ransomware.live recent victims for ShinyHunters; store as STIX identity+relationship."""
        result = IngestResult()
        import httpx
        try:
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
                resp = await client.get(
                    RLIVE_URL,
                    headers={"User-Agent": "SOCINT/1.0 CTI Platform (research)"},
                )
                resp.raise_for_status()
                all_victims = resp.json()
        except Exception as e:
            self.logger.warning(f"ShinyHunters/rlive: fetch failed: {e}")
            result.errors += 1
            return result

        victims = [
            v for v in all_victims
            if (v.get("group_name") or "").lower() in _ACTOR_NAMES
        ]
        if not victims:
            return result

        now = _now()
        # Static threat-actor identity for ShinyHunters
        actor_id = f"threat-actor--{uuid.uuid5(uuid.NAMESPACE_DNS, 'shinyhunters.threat-actor')}"
        stix_objects: list[dict] = [{
            "type":              "threat-actor",
            "id":                actor_id,
            "name":              "ShinyHunters",
            "aliases":           ["ShinySp1d3r"],
            "threat_actor_types": ["criminal"],
            "primary_motivation": "financial-gain",
            "labels":            ["shinyhunters", "ransomware-live"],
            "x_clawint_source":  "ransomware-live-shinyhunters",
            "x_clawint_tlp":     "TLP:WHITE",
            "confidence":        80,
            "valid_from":        now,
        }]

        for v in victims:
            victim_name = (v.get("post_title") or v.get("website") or "").strip()
            if not victim_name:
                continue
            identity_id = f"identity--{uuid.uuid5(uuid.NAMESPACE_DNS, f'shinyhunters-victim-{_slug(victim_name)}')}"
            rel_id      = f"relationship--{uuid.uuid5(uuid.NAMESPACE_DNS, f'sh-targets-{_slug(victim_name)}')}"
            date_str    = (v.get("discovered") or v.get("published") or "")

            stix_objects.append({
                "type":             "identity",
                "id":               identity_id,
                "name":             victim_name,
                "identity_class":   "organization",
                "labels":           ["shinyhunters-victim", "ransomware-live"],
                "x_clawint_source": "ransomware-live-shinyhunters",
                "x_clawint_tlp":    "TLP:WHITE",
                "confidence":       80,
                "valid_from":       _iso(date_str),
                "x_victim_domain":  v.get("website", ""),
                "x_victim_country": v.get("country", ""),
                "x_victim_sector":  v.get("activity", ""),
            })
            stix_objects.append({
                "type":              "relationship",
                "id":                rel_id,
                "relationship_type": "targets",
                "source_ref":        actor_id,
                "target_ref":        identity_id,
                "labels":            ["shinyhunters", "ransomware-live"],
                "x_clawint_source":  "ransomware-live-shinyhunters",
                "x_clawint_tlp":     "TLP:WHITE",
                "confidence":        80,
                "valid_from":        _iso(date_str),
            })

        r = await self.push_to_platform(stix_objects)
        result.objects_created += r.objects_created
        result.errors          += r.errors
        self.logger.info(f"ShinyHunters/rlive: {len(victims)} victims → {r.objects_created} STIX objects")
        return result


def _iso(date_str: str) -> str:
    if not date_str:
        return _now()
    try:
        # Accept YYYY-MM-DD or full ISO
        if len(date_str) == 10:
            dt = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        else:
            dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    except Exception:
        return _now()


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower().strip())[:64]
