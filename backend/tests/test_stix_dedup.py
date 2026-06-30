"""
Deterministic-dedup guarantees for STIX indicators.

The whole platform relies on the same IoC, seen by any connector at any time,
resolving to the *same* STIX id so OpenSearch upserts instead of duplicating.
That contract lives in app.core.stix_engine — these tests pin it down.
"""
import re
import uuid

from app.core.stix_engine import (
    _deterministic_indicator_id,
    _extract_pattern_value,
    _INDICATOR_NAMESPACE,
)

_ID_RE = re.compile(r"^indicator--[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


def _ind(pattern, itype="malicious-activity"):
    return {"pattern": pattern, "indicator_types": [itype]}


# ── _extract_pattern_value ────────────────────────────────────────────────────

def test_extract_ipv4():
    assert _extract_pattern_value("[ipv4-addr:value = '1.2.3.4']") == "1.2.3.4"


def test_extract_domain_double_quotes():
    assert _extract_pattern_value('[domain-name:value = "evil.com"]') == "evil.com"


def test_extract_file_hash():
    pattern = "[file:hashes.'SHA-256' = 'abc123def456']"
    assert _extract_pattern_value(pattern) == "abc123def456"


def test_extract_returns_none_when_no_value():
    assert _extract_pattern_value("no quoted value here") is None
    assert _extract_pattern_value("") is None
    assert _extract_pattern_value(None) is None


# ── _deterministic_indicator_id ───────────────────────────────────────────────

def test_id_format_is_valid_stix_uuid5():
    sid = _deterministic_indicator_id(_ind("[ipv4-addr:value = '1.2.3.4']"))
    assert _ID_RE.match(sid), sid
    # uuid5 → version field is 5
    assert uuid.UUID(sid.split("--", 1)[1]).version == 5


def test_same_ioc_same_id():
    a = _deterministic_indicator_id(_ind("[ipv4-addr:value = '8.8.8.8']"))
    b = _deterministic_indicator_id(_ind("[ipv4-addr:value = '8.8.8.8']"))
    assert a == b


def test_value_is_case_and_whitespace_normalized():
    # seed lowercases + strips, so these must collapse to one id
    a = _deterministic_indicator_id(_ind('[domain-name:value = "Evil.COM"]'))
    b = _deterministic_indicator_id(_ind('[domain-name:value = "  evil.com  "]'))
    assert a == b


def test_different_values_differ():
    a = _deterministic_indicator_id(_ind("[ipv4-addr:value = '1.1.1.1']"))
    b = _deterministic_indicator_id(_ind("[ipv4-addr:value = '2.2.2.2']"))
    assert a != b


def test_type_is_part_of_seed():
    # same value, different indicator_type → different id
    a = _deterministic_indicator_id(_ind("[ipv4-addr:value = '9.9.9.9']", "benign"))
    b = _deterministic_indicator_id(_ind("[ipv4-addr:value = '9.9.9.9']", "malicious-activity"))
    assert a != b


def test_missing_indicator_types_falls_back_to_unknown():
    # no indicator_types key → "unknown" type, still deterministic, no crash
    obj = {"pattern": "[ipv4-addr:value = '3.3.3.3']"}
    a = _deterministic_indicator_id(obj)
    b = _deterministic_indicator_id(obj)
    assert a == b
    assert a.startswith("indicator--")


def test_unextractable_pattern_uses_full_pattern_as_seed():
    # no quoted value → seed falls back to the raw pattern; still stable + distinct
    p1 = "weird-pattern-aaa"
    p2 = "weird-pattern-bbb"
    a1 = _deterministic_indicator_id(_ind(p1))
    a2 = _deterministic_indicator_id(_ind(p1))
    b = _deterministic_indicator_id(_ind(p2))
    assert a1 == a2
    assert a1 != b


def test_id_matches_manual_uuid5_computation():
    # lock the exact seed formula so a refactor can't silently shift every id
    obj = _ind("[ipv4-addr:value = '4.4.4.4']", "malicious-activity")
    seed = "malicious-activity:4.4.4.4"
    expected = f"indicator--{uuid.uuid5(_INDICATOR_NAMESPACE, seed)}"
    assert _deterministic_indicator_id(obj) == expected
