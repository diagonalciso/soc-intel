"""
Export router.
Exports threat intelligence in multiple formats:
  - STIX 2.1 bundle (JSON)
  - Splunk lookup CSV (value, type, confidence, threat)
  - Elastic/ECS NDJSON bulk
  - Plain CSV
"""
import csv
import io
import json
from datetime import datetime, timezone
from typing import Any
from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse, JSONResponse

from app.core.stix_engine import get_stix_engine, STIXEngine
from app.auth.dependencies import get_current_user
from app.models.user import User

router = APIRouter(prefix="/export", tags=["export"])


# ── STIX 2.1 Bundle ─────────────────────────────────────────────

@router.get("/stix")
async def export_stix_bundle(
    type: str | None = Query(None, description="STIX object type to export"),
    q: str | None = Query(None, description="Free-text search query"),
    source: str | None = Query(None, description="Filter by connector source"),
    tlp: str | None = Query(None, description="Filter by TLP marking"),
    size: int = Query(1000, le=5000),
    engine: STIXEngine = Depends(get_stix_engine),
    user: User = Depends(get_current_user),
):
    """Export objects as a STIX 2.1 bundle (application/json)."""
    filters: dict = {}
    if tlp:
        filters["tlp.keyword"] = tlp
    if source:
        filters["x_clawint_source"] = source

    result = await engine.search(
        stix_type=type, query=q, filters=filters or None, from_=0, size=size
    )
    objects = result.get("objects", [])

    bundle = {
        "type": "bundle",
        "id": f"bundle--{_uuid()}",
        "spec_version": "2.1",
        "created": _now(),
        "objects": objects,
    }

    def _stream():
        yield json.dumps(bundle, indent=2)

    return StreamingResponse(
        _stream(),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="socint-export-{_date()}.json"'},
    )


# ── Splunk Lookup CSV ────────────────────────────────────────────

@router.get("/splunk")
async def export_splunk_csv(
    source: str | None = Query(None),
    tlp: str | None = Query(None),
    confidence_min: int = Query(0, ge=0, le=100),
    size: int = Query(5000, le=10000),
    engine: STIXEngine = Depends(get_stix_engine),
    user: User = Depends(get_current_user),
):
    """
    Export indicators as a Splunk threat intel lookup CSV.
    Columns: value, type, confidence, threat_name, source, valid_from
    """
    filters: dict = {}
    if tlp:
        filters["tlp.keyword"] = tlp
    if source:
        filters["x_clawint_source"] = source

    result = await engine.search(
        stix_type="indicator", query=None, filters=filters or None, from_=0, size=size
    )
    indicators = result.get("objects", [])

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["value", "type", "confidence", "threat_name", "source", "valid_from", "labels"])

    for ind in indicators:
        if ind.get("confidence", 0) < confidence_min:
            continue
        pattern = ind.get("pattern", "")
        values = _extract_values_from_pattern(pattern)
        ioc_type = _pattern_type(pattern)
        for val in values:
            writer.writerow([
                val,
                ioc_type,
                ind.get("confidence", 0),
                ind.get("name", ""),
                ind.get("x_clawint_source", ""),
                ind.get("valid_from", ""),
                " ".join(ind.get("labels", [])),
            ])

    content = output.getvalue()

    return StreamingResponse(
        iter([content]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="socint-splunk-{_date()}.csv"'},
    )


# ── Elastic / ECS NDJSON ─────────────────────────────────────────

@router.get("/elastic")
async def export_elastic_ndjson(
    type: str | None = Query(None),
    source: str | None = Query(None),
    tlp: str | None = Query(None),
    size: int = Query(5000, le=10000),
    engine: STIXEngine = Depends(get_stix_engine),
    user: User = Depends(get_current_user),
):
    """
    Export as Elasticsearch bulk NDJSON (ECS threat fields).
    Index: threat-intel-*
    """
    filters: dict = {}
    if tlp:
        filters["tlp.keyword"] = tlp
    if source:
        filters["x_clawint_source"] = source

    result = await engine.search(
        stix_type=type or "indicator", query=None, filters=filters or None, from_=0, size=size
    )
    objects = result.get("objects", [])

    lines: list[str] = []
    index_name = "threat-intel-socint"

    for obj in objects:
        meta = json.dumps({"index": {"_index": index_name, "_id": obj.get("id", "")}})
        doc = _to_ecs(obj)
        lines.append(meta)
        lines.append(json.dumps(doc))

    content = "\n".join(lines) + "\n"

    return StreamingResponse(
        iter([content]),
        media_type="application/x-ndjson",
        headers={"Content-Disposition": f'attachment; filename="socint-elastic-{_date()}.ndjson"'},
    )


# ── Generic CSV ──────────────────────────────────────────────────

@router.get("/csv")
async def export_csv(
    type: str | None = Query(None),
    q: str | None = Query(None),
    source: str | None = Query(None),
    tlp: str | None = Query(None),
    size: int = Query(5000, le=10000),
    engine: STIXEngine = Depends(get_stix_engine),
    user: User = Depends(get_current_user),
):
    """Export STIX objects as a flat CSV."""
    filters: dict = {}
    if tlp:
        filters["tlp.keyword"] = tlp
    if source:
        filters["x_clawint_source"] = source

    result = await engine.search(
        stix_type=type, query=q, filters=filters or None, from_=0, size=size
    )
    objects = result.get("objects", [])

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "id", "type", "name", "description", "confidence",
        "source", "tlp", "created", "modified", "labels",
    ])

    for obj in objects:
        writer.writerow([
            obj.get("id", ""),
            obj.get("type", ""),
            obj.get("name", ""),
            (obj.get("description") or "")[:200],
            obj.get("confidence", ""),
            obj.get("x_clawint_source", ""),
            obj.get("tlp") or obj.get("x_clawint_tlp", ""),
            obj.get("created", ""),
            obj.get("modified", ""),
            " ".join(obj.get("labels", [])),
        ])

    content = output.getvalue()

    return StreamingResponse(
        iter([content]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="socint-export-{_date()}.csv"'},
    )


# ── Helpers ──────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _date() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d")


def _uuid() -> str:
    import uuid
    return str(uuid.uuid4())


def _extract_values_from_pattern(pattern: str) -> list[str]:
    """Extract IOC values from a STIX pattern string."""
    import re
    # Match value = 'something' or value = "something"
    matches = re.findall(r"=\s*['\"]([^'\"]+)['\"]", pattern)
    # Return unique values, skip hash algorithm labels
    return list({m for m in matches if not any(c in m for c in [" ", "\n"])})[:5]


def _pattern_type(pattern: str) -> str:
    if "ipv4-addr" in pattern:
        return "ip"
    if "ipv6-addr" in pattern:
        return "ipv6"
    if "domain-name" in pattern:
        return "domain"
    if "url:value" in pattern:
        return "url"
    if "file:hashes" in pattern:
        return "file_hash"
    if "email-addr" in pattern:
        return "email"
    return "unknown"


def _to_ecs(obj: dict) -> dict:
    """Convert a STIX object to Elastic Common Schema threat fields."""
    ecs: dict[str, Any] = {
        "@timestamp": obj.get("created") or _now(),
        "threat": {
            "indicator": {
                "type": _pattern_type(obj.get("pattern", "")),
                "confidence": _ecs_confidence(obj.get("confidence", 50)),
                "name": obj.get("name", ""),
                "description": obj.get("description", ""),
                "provider": obj.get("x_clawint_source", "socint"),
                "first_seen": obj.get("valid_from") or obj.get("created"),
                "last_seen": obj.get("modified") or obj.get("created"),
                "tlp": obj.get("tlp") or obj.get("x_clawint_tlp", ""),
                "marking": {
                    "tlp": obj.get("tlp") or obj.get("x_clawint_tlp", ""),
                },
            },
        },
        "event": {
            "kind": "enrichment",
            "category": ["threat"],
            "type": ["indicator"],
        },
        "tags": obj.get("labels", []),
        "socint": {
            "stix_id": obj.get("id"),
            "source": obj.get("x_clawint_source"),
            "source_reliability": obj.get("x_clawint_source_reliability"),
        },
    }

    # Add IOC value to appropriate ECS field
    values = _extract_values_from_pattern(obj.get("pattern", ""))
    if values:
        t = _pattern_type(obj.get("pattern", ""))
        ioc = ecs["threat"]["indicator"]
        if t in ("ip", "ipv6"):
            ioc["ip"] = values[0]
        elif t == "domain":
            ioc["domain"] = values[0]
        elif t == "url":
            ioc["url"] = {"full": values[0]}
        elif t == "file_hash":
            ioc["file"] = {"hash": {"sha256": values[0]}}
        elif t == "email":
            ioc["email"] = {"address": values[0]}

    return ecs


def _ecs_confidence(score: int) -> str:
    if score >= 85:
        return "High"
    if score >= 50:
        return "Medium"
    return "Low"
