"""
Alert rules REST endpoints.
CRUD for condition-based auto-alerting rules.
"""
import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Any

from app.db.postgres import get_db
from app.auth.dependencies import get_current_user, require_analyst
from app.models.user import User
from app.models.alert_rules import AlertRule, AlertRuleCondition, AlertRuleSeverity

router = APIRouter(prefix="/alert-rules", tags=["alert-rules"])


class AlertRuleCreate(BaseModel):
    name: str
    description: str | None = None
    condition_type: AlertRuleCondition
    condition_params: dict[str, Any] = {}
    severity: AlertRuleSeverity = AlertRuleSeverity.medium
    enabled: bool = True
    dedup_window_minutes: int = 60


class AlertRuleUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    condition_params: dict[str, Any] | None = None
    severity: AlertRuleSeverity | None = None
    enabled: bool | None = None
    dedup_window_minutes: int | None = None


def _rule_to_dict(r: AlertRule) -> dict:
    return {
        "id":                     str(r.id),
        "name":                   r.name,
        "description":            r.description,
        "condition_type":         r.condition_type,
        "condition_params":       r.condition_params or {},
        "severity":               r.severity,
        "enabled":                r.enabled,
        "dedup_window_minutes":   r.dedup_window_minutes,
        "matched_count":          r.matched_count,
        "last_matched_at":        r.last_matched_at.isoformat() if r.last_matched_at else None,
        "created_at":             r.created_at.isoformat() if r.created_at else None,
        "updated_at":             r.updated_at.isoformat() if r.updated_at else None,
    }


@router.post("", status_code=201)
async def create_alert_rule(
    payload: AlertRuleCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    rule = AlertRule(
        name=payload.name,
        description=payload.description,
        condition_type=payload.condition_type,
        condition_params=payload.condition_params,
        severity=payload.severity,
        enabled=payload.enabled,
        dedup_window_minutes=payload.dedup_window_minutes,
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return _rule_to_dict(rule)


@router.get("")
async def list_alert_rules(
    enabled: bool | None = Query(None),
    condition_type: AlertRuleCondition | None = Query(None),
    from_: int = Query(0, alias="from"),
    size: int = Query(50, le=500),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    stmt = select(AlertRule)
    if enabled is not None:
        stmt = stmt.where(AlertRule.enabled == enabled)
    if condition_type:
        stmt = stmt.where(AlertRule.condition_type == condition_type)

    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    stmt = stmt.order_by(AlertRule.created_at.desc()).offset(from_).limit(size)
    rows = (await db.execute(stmt)).scalars().all()

    return {"total": total, "objects": [_rule_to_dict(r) for r in rows]}


@router.get("/conditions")
async def list_condition_types(user: User = Depends(get_current_user)):
    """Return all available condition types with metadata."""
    return {
        "conditions": [
            {
                "type": "new_ransomware_victim",
                "label": "New Ransomware Victim",
                "description": "Fires when a new ransomware victim is posted",
                "params": [
                    {"key": "sector", "type": "string", "description": "Industry sector (e.g. Healthcare)", "required": False},
                    {"key": "country", "type": "string", "description": "Country name", "required": False},
                    {"key": "group", "type": "string", "description": "Ransomware group name", "required": False},
                ],
            },
            {
                "type": "new_indicator",
                "label": "New Indicator Ingested",
                "description": "Fires when a new indicator matches criteria",
                "params": [
                    {"key": "source", "type": "string", "description": "Connector source name", "required": False},
                    {"key": "confidence_min", "type": "integer", "description": "Minimum confidence (0-100)", "required": False},
                ],
            },
            {
                "type": "new_malware",
                "label": "New Malware Family",
                "description": "Fires when a new malware object is added",
                "params": [
                    {"key": "name_contains", "type": "string", "description": "Substring to match in malware name", "required": False},
                ],
            },
            {
                "type": "new_threat_actor",
                "label": "New Threat Actor",
                "description": "Fires when a new threat actor is added",
                "params": [
                    {"key": "name_contains", "type": "string", "description": "Substring to match in actor name", "required": False},
                ],
            },
            {
                "type": "high_epss_cve",
                "label": "High EPSS CVE",
                "description": "Fires when a CVE with high exploitation probability is ingested",
                "params": [
                    {"key": "epss_min", "type": "float", "description": "Minimum EPSS score (0.0-1.0)", "required": False, "default": 0.5},
                ],
            },
            {
                "type": "cisa_kev_added",
                "label": "CISA KEV Entry Added",
                "description": "Fires when CISA adds a new Known Exploited Vulnerability",
                "params": [],
            },
            {
                "type": "credential_exposure",
                "label": "Credential Exposure Detected",
                "description": "Fires when credential exposures are recorded",
                "params": [
                    {"key": "domain", "type": "string", "description": "Domain to watch", "required": False},
                    {"key": "exposure_type", "type": "string", "description": "Type: breach, stealer_log, combo_list", "required": False},
                ],
            },
            {
                "type": "iab_listing",
                "label": "Initial Access Broker Listing",
                "description": "Fires when a new IAB listing appears",
                "params": [
                    {"key": "sector", "type": "string", "description": "Target sector", "required": False},
                    {"key": "country", "type": "string", "description": "Target country", "required": False},
                ],
            },
            {
                "type": "ioc_sighted",
                "label": "IOC Sighted",
                "description": "Fires when a sighting is reported for an indicator",
                "params": [
                    {"key": "source", "type": "string", "description": "Sighting source", "required": False},
                ],
            },
        ]
    }


@router.get("/{rule_id}")
async def get_alert_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    rule = await db.get(AlertRule, uuid.UUID(rule_id))
    if not rule:
        raise HTTPException(status_code=404, detail="Alert rule not found")
    return _rule_to_dict(rule)


@router.patch("/{rule_id}")
async def update_alert_rule(
    rule_id: str,
    payload: AlertRuleUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    rule = await db.get(AlertRule, uuid.UUID(rule_id))
    if not rule:
        raise HTTPException(status_code=404, detail="Alert rule not found")

    updates = payload.model_dump(exclude_none=True)
    for k, v in updates.items():
        setattr(rule, k, v)
    rule.updated_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(rule)
    return _rule_to_dict(rule)


@router.delete("/{rule_id}", status_code=204)
async def delete_alert_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    rule = await db.get(AlertRule, uuid.UUID(rule_id))
    if not rule:
        raise HTTPException(status_code=404, detail="Alert rule not found")
    await db.delete(rule)
    await db.commit()


@router.post("/{rule_id}/test")
async def test_alert_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    """Dry-run: check how many current objects would match this rule."""
    rule = await db.get(AlertRule, uuid.UUID(rule_id))
    if not rule:
        raise HTTPException(status_code=404, detail="Alert rule not found")

    from app.workers.alert_matcher import check_rule_matches
    matches = await check_rule_matches(rule, dry_run=True)
    return {"rule_id": rule_id, "matching_objects": matches, "dry_run": True}
