"""
Warning lists — false-positive suppression for indicators.
Fetches and caches MISP-format warning lists (top domains, CDN IPs, cloud ranges).
Indicators that match a warning list are flagged, not silently dropped.
"""
import asyncio
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import NamedTuple

import httpx

logger = logging.getLogger(__name__)

# MISP warninglists on GitHub — fast, authoritative, free
_MISP_BASE = "https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists"

WARNINGLISTS = {
    "top-1000":   f"{_MISP_BASE}/top-1000/list.json",
    "microsoft":  f"{_MISP_BASE}/microsoft/list.json",
    "google":     f"{_MISP_BASE}/google/list.json",
    "amazon-aws": f"{_MISP_BASE}/amazon-aws/list.json",
    "cloudflare": f"{_MISP_BASE}/cloudflare/list.json",
    "akamai":     f"{_MISP_BASE}/akamai/list.json",
    "alexa":      f"{_MISP_BASE}/alexa/list.json",
    "tranco":     f"{_MISP_BASE}/tranco/list.json",
}

REFRESH_HOURS = 24


class _Cache(NamedTuple):
    domains: frozenset[str]
    cidrs: list[str]           # kept as strings for simple prefix matching
    refreshed_at: datetime


_cache: _Cache | None = None
_lock = asyncio.Lock()


async def _load() -> _Cache:
    domains: set[str] = set()
    cidrs: list[str] = []

    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        for name, url in WARNINGLISTS.items():
            try:
                resp = await client.get(url)
                if resp.status_code != 200:
                    continue
                data = resp.json()
                for entry in data.get("list", []):
                    entry = entry.strip().lower()
                    if not entry:
                        continue
                    if "/" in entry and _looks_like_cidr(entry):
                        cidrs.append(entry)
                    else:
                        # Strip leading *. from wildcard entries
                        domains.add(entry.lstrip("*."))
            except Exception as e:
                logger.warning(f"Warning lists: failed to load {name}: {e}")

    logger.info(f"Warning lists: loaded {len(domains):,} domains, {len(cidrs)} CIDR ranges")
    return _Cache(
        domains=frozenset(domains),
        cidrs=cidrs,
        refreshed_at=datetime.now(timezone.utc),
    )


async def get_cache() -> _Cache:
    global _cache
    async with _lock:
        if _cache is None or (
            datetime.now(timezone.utc) - _cache.refreshed_at > timedelta(hours=REFRESH_HOURS)
        ):
            _cache = await _load()
    return _cache


async def is_false_positive(indicator_type: str, value: str) -> tuple[bool, str]:
    """
    Check whether a value is likely a false positive.
    Returns (is_fp, reason).
    """
    value = value.strip().lower()
    cache = await get_cache()

    if indicator_type in ("domain-name", "url", "hostname"):
        # Extract hostname from URL if needed
        domain = _extract_domain(value)
        if domain in cache.domains:
            return True, "domain in warning list (top sites / CDN / cloud)"
        # Check parent domain match (e.g. sub.google.com → google.com)
        parts = domain.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in cache.domains:
                return True, f"subdomain of warning-listed domain ({parent})"

    elif indicator_type in ("ipv4-addr", "ipv6-addr"):
        # Simple prefix match against known CDN/cloud CIDRs
        for cidr in cache.cidrs:
            if _ip_in_prefix(value, cidr):
                return True, f"IP in warning-listed CIDR ({cidr})"

    return False, ""


def _extract_domain(value: str) -> str:
    """Extract hostname from a URL or return value as-is."""
    if value.startswith(("http://", "https://")):
        try:
            from urllib.parse import urlparse
            return urlparse(value).hostname or value
        except Exception:
            pass
    return value.split("/")[0].split(":")[0]


def _looks_like_cidr(s: str) -> bool:
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$", s) or
                re.match(r"^[0-9a-f:]+/\d{1,3}$", s))


def _ip_in_prefix(ip: str, cidr: str) -> bool:
    """Very fast IPv4-only prefix check without ipaddress module overhead."""
    try:
        ip_part, prefix_str = cidr.split("/")
        prefix_len = int(prefix_str)
        ip_int = _ip_to_int(ip)
        net_int = _ip_to_int(ip_part)
        mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
        return (ip_int & mask) == (net_int & mask)
    except Exception:
        return False


def _ip_to_int(ip: str) -> int:
    try:
        parts = ip.split(".")
        return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])
    except Exception:
        return -1
