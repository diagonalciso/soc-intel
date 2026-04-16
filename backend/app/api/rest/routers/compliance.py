"""
Compliance REST endpoints.
Serves NIST SP 800-53 Rev 5 controls and NIST CSF 2.0 framework elements.
Provides tagging endpoints to associate rules with controls and cases with CSF elements.
"""
import uuid
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_

from app.db.postgres import get_db
from app.auth.dependencies import get_current_user, require_analyst
from app.models.user import User
from app.models.compliance import NistControl, CsfElement
from app.models.rules import DetectionRule
from app.models.cases import Case

router = APIRouter(prefix="/compliance", tags=["compliance"])


# ── SP 800-53 endpoints ───────────────────────────────────────────

@router.get("/800-53/families")
async def list_families(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(NistControl.family, NistControl.family_name, func.count(NistControl.id).label("count"))
        .where(NistControl.is_enhancement == False)
        .where(NistControl.withdrawn == False)
        .group_by(NistControl.family, NistControl.family_name)
        .order_by(NistControl.family)
    )
    return [{"family": r.family, "name": r.family_name, "count": r.count} for r in result.all()]


@router.get("/800-53/controls")
async def list_controls(
    family: str | None = Query(None),
    baseline: str | None = Query(None, description="LOW, MODERATE, or HIGH"),
    include_enhancements: bool = Query(False),
    include_withdrawn: bool = Query(False),
    q: str | None = Query(None),
    from_: int = Query(0, alias="from"),
    size: int = Query(100, le=500),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    stmt = select(NistControl)
    if not include_withdrawn:
        stmt = stmt.where(NistControl.withdrawn == False)
    if not include_enhancements:
        stmt = stmt.where(NistControl.is_enhancement == False)
    if family:
        stmt = stmt.where(NistControl.family == family.upper())
    if q:
        stmt = stmt.where(or_(
            NistControl.control_id.ilike(f"%{q}%"),
            NistControl.title.ilike(f"%{q}%"),
        ))

    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    stmt = stmt.order_by(NistControl.control_id).offset(from_).limit(size)
    rows = (await db.execute(stmt)).scalars().all()

    # baseline filter is done in Python because JSON array containment in standard JSON
    # columns requires a cast; post-filter on the fetched page is fine for this dataset size
    if baseline:
        bl = baseline.upper()
        rows = [r for r in rows if bl in (r.baseline_impact or [])]
        total = len(rows)

    return {"total": total, "controls": [_control_dict(c) for c in rows]}


@router.get("/800-53/controls/{control_id}")
async def get_control(
    control_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    control = (await db.execute(
        select(NistControl).where(NistControl.control_id == control_id.upper())
    )).scalar_one_or_none()
    if not control:
        raise HTTPException(status_code=404, detail="Control not found")
    return _control_dict(control)


@router.get("/800-53/controls/{control_id}/rules")
async def rules_for_control(
    control_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    cid = control_id.upper()
    rows = (await db.execute(select(DetectionRule))).scalars().all()
    tagged = [r for r in rows if cid in (r.nist_800_53 or [])]
    return [{"id": str(r.id), "name": r.name, "rule_type": r.rule_type, "severity": r.severity} for r in tagged]


@router.get("/800-53/controls/{control_id}/cases")
async def cases_for_control(
    control_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    cid = control_id.upper()
    rows = (await db.execute(select(Case))).scalars().all()
    tagged = [c for c in rows if cid in (c.nist_800_53 or [])]
    return [{"id": str(c.id), "title": c.title, "severity": c.severity, "status": c.status} for c in tagged]


# ── CSF 2.0 endpoints ─────────────────────────────────────────────

@router.get("/csf/functions")
async def list_functions(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    rows = (await db.execute(
        select(CsfElement).where(CsfElement.element_type == "function").order_by(CsfElement.element_id)
    )).scalars().all()
    return [_csf_dict(e) for e in rows]


@router.get("/csf/elements")
async def list_csf_elements(
    function_id: str | None = Query(None),
    element_type: str | None = Query(None, description="function | category | subcategory"),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    stmt = select(CsfElement)
    if function_id:
        stmt = stmt.where(CsfElement.function_id == function_id.upper())
    if element_type:
        stmt = stmt.where(CsfElement.element_type == element_type)
    stmt = stmt.order_by(CsfElement.element_id)
    rows = (await db.execute(stmt)).scalars().all()
    return [_csf_dict(e) for e in rows]


@router.get("/csf/elements/{element_id}/cases")
async def cases_for_csf(
    element_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    eid = element_id.upper()
    rows = (await db.execute(select(Case))).scalars().all()
    tagged = [c for c in rows if eid in (c.csf_tags or [])]
    return [{"id": str(c.id), "title": c.title, "severity": c.severity, "status": c.status} for c in tagged]


# ── Tagging endpoints ─────────────────────────────────────────────

class RuleCompliancePatch(BaseModel):
    nist_800_53: list[str]


class CaseCompliancePatch(BaseModel):
    nist_800_53: list[str] | None = None
    csf_tags: list[str] | None = None


@router.patch("/tag/rule/{rule_id}")
async def tag_rule(
    rule_id: str,
    payload: RuleCompliancePatch,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    rule = await db.get(DetectionRule, uuid.UUID(rule_id))
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule.nist_800_53 = [c.upper() for c in payload.nist_800_53]
    await db.commit()
    return {"id": str(rule.id), "nist_800_53": rule.nist_800_53}


@router.patch("/tag/case/{case_id}")
async def tag_case(
    case_id: str,
    payload: CaseCompliancePatch,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    case = await db.get(Case, uuid.UUID(case_id))
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    if payload.nist_800_53 is not None:
        case.nist_800_53 = [c.upper() for c in payload.nist_800_53]
    if payload.csf_tags is not None:
        case.csf_tags = [t.upper() for t in payload.csf_tags]
    await db.commit()
    return {"id": str(case.id), "nist_800_53": case.nist_800_53, "csf_tags": case.csf_tags}


# ── Stats endpoint ────────────────────────────────────────────────

@router.get("/stats")
async def compliance_stats(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    controls_total = (await db.execute(
        select(func.count()).select_from(NistControl)
        .where(NistControl.withdrawn == False)
        .where(NistControl.is_enhancement == False)
    )).scalar() or 0

    csf_total = (await db.execute(
        select(func.count()).select_from(CsfElement)
    )).scalar() or 0

    rules = (await db.execute(select(DetectionRule))).scalars().all()
    rules_tagged = sum(1 for r in rules if r.nist_800_53)

    cases = (await db.execute(select(Case))).scalars().all()
    cases_800_53 = sum(1 for c in cases if c.nist_800_53)
    cases_csf = sum(1 for c in cases if c.csf_tags)

    return {
        "nist_800_53": {"controls": controls_total, "rules_tagged": rules_tagged, "cases_tagged": cases_800_53},
        "csf": {"elements": csf_total, "cases_tagged": cases_csf},
    }


# ── Helpers ───────────────────────────────────────────────────────

def _control_dict(c: NistControl) -> dict:
    return {
        "id": str(c.id),
        "control_id": c.control_id,
        "family": c.family,
        "family_name": c.family_name,
        "title": c.title,
        "description": c.description,
        "is_enhancement": c.is_enhancement,
        "parent_id": c.parent_id,
        "baseline_impact": c.baseline_impact or [],
        "related": c.related or [],
        "withdrawn": c.withdrawn,
    }


def _csf_dict(e: CsfElement) -> dict:
    return {
        "id": str(e.id),
        "element_type": e.element_type,
        "element_id": e.element_id,
        "function_id": e.function_id,
        "function_name": e.function_name,
        "category_id": e.category_id,
        "category_name": e.category_name,
        "description": e.description,
    }
