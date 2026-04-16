"""
Detection rules REST endpoints.
CRUD for YARA, Sigma, Snort/Suricata, and STIX Pattern rules.
"""
import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func, update
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Any

from app.db.postgres import get_db
from app.auth.dependencies import get_current_user, require_analyst
from app.models.user import User
from app.models.rules import DetectionRule, RuleType, RuleStatus, RuleSeverity

router = APIRouter(prefix="/rules", tags=["detection-rules"])


class RuleCreate(BaseModel):
    name: str
    rule_type: RuleType
    content: str
    description: str | None = None
    author: str | None = None
    tags: list[str] = []
    severity: RuleSeverity = RuleSeverity.medium
    status: RuleStatus = RuleStatus.active
    linked_stix_ids: list[str] = []
    mitre_techniques: list[str] = []
    nist_800_53: list[str] = []


class RuleUpdate(BaseModel):
    name: str | None = None
    content: str | None = None
    description: str | None = None
    author: str | None = None
    tags: list[str] | None = None
    severity: RuleSeverity | None = None
    status: RuleStatus | None = None
    linked_stix_ids: list[str] | None = None
    mitre_techniques: list[str] | None = None
    nist_800_53: list[str] | None = None


def _rule_to_dict(r: DetectionRule) -> dict:
    return {
        "id":               str(r.id),
        "name":             r.name,
        "rule_type":        r.rule_type,
        "content":          r.content,
        "description":      r.description,
        "author":           r.author,
        "tags":             r.tags or [],
        "severity":         r.severity,
        "status":           r.status,
        "linked_stix_ids":  r.linked_stix_ids or [],
        "mitre_techniques": r.mitre_techniques or [],
        "nist_800_53":      r.nist_800_53 or [],
        "created_at":       r.created_at.isoformat() if r.created_at else None,
        "updated_at":       r.updated_at.isoformat() if r.updated_at else None,
    }


@router.post("")
async def create_rule(
    payload: RuleCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    rule = DetectionRule(
        name=payload.name,
        rule_type=payload.rule_type,
        content=payload.content,
        description=payload.description,
        author=payload.author or user.username,
        tags=payload.tags,
        severity=payload.severity,
        status=payload.status,
        linked_stix_ids=payload.linked_stix_ids,
        mitre_techniques=payload.mitre_techniques,
        nist_800_53=payload.nist_800_53,
        created_by_id=user.id,
        organization_id=user.organization_id,
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return _rule_to_dict(rule)


@router.get("")
async def list_rules(
    rule_type: RuleType | None = Query(None),
    status: RuleStatus | None = Query(None),
    severity: RuleSeverity | None = Query(None),
    q: str | None = Query(None),
    from_: int = Query(0, alias="from"),
    size: int = Query(50, le=500),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    stmt = select(DetectionRule)
    if rule_type:
        stmt = stmt.where(DetectionRule.rule_type == rule_type)
    if status:
        stmt = stmt.where(DetectionRule.status == status)
    if severity:
        stmt = stmt.where(DetectionRule.severity == severity)
    if q:
        stmt = stmt.where(DetectionRule.name.ilike(f"%{q}%"))

    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    stmt = stmt.order_by(DetectionRule.created_at.desc()).offset(from_).limit(size)
    rows = (await db.execute(stmt)).scalars().all()

    return {"total": total, "objects": [_rule_to_dict(r) for r in rows]}


@router.get("/stats")
async def rule_stats(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Summary counts by type and status."""
    by_type = {}
    for rt in RuleType:
        count = (await db.execute(
            select(func.count()).where(DetectionRule.rule_type == rt)
        )).scalar() or 0
        by_type[rt.value] = count

    by_status = {}
    for rs in RuleStatus:
        count = (await db.execute(
            select(func.count()).where(DetectionRule.status == rs)
        )).scalar() or 0
        by_status[rs.value] = count

    total = (await db.execute(select(func.count()).select_from(DetectionRule))).scalar() or 0
    return {"total": total, "by_type": by_type, "by_status": by_status}


@router.get("/{rule_id}")
async def get_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    rule = await db.get(DetectionRule, uuid.UUID(rule_id))
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return _rule_to_dict(rule)


@router.patch("/{rule_id}")
async def update_rule(
    rule_id: str,
    payload: RuleUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    rule = await db.get(DetectionRule, uuid.UUID(rule_id))
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    updates = payload.model_dump(exclude_none=True)
    for k, v in updates.items():
        setattr(rule, k, v)
    rule.updated_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(rule)
    return _rule_to_dict(rule)


@router.delete("/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    rule = await db.get(DetectionRule, uuid.UUID(rule_id))
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    await db.delete(rule)
    await db.commit()
