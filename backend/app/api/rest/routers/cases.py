from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from pydantic import BaseModel
from datetime import datetime
from typing import Any
import uuid

from app.db.postgres import get_db
from app.models.cases import Case, CaseTask, Observable, CaseComment, Alert, CaseSeverity, CaseStatus, ObservableType
from app.auth.dependencies import get_current_user, require_analyst
from app.models.user import User

router = APIRouter(prefix="/cases", tags=["cases"])


class CaseCreate(BaseModel):
    title: str
    description: str | None = None
    severity: CaseSeverity = CaseSeverity.medium
    tlp: str = "TLP:AMBER"
    tags: list[str] | None = None


class CaseUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    severity: CaseSeverity | None = None
    status: CaseStatus | None = None
    tlp: str | None = None
    tags: list[str] | None = None
    nist_800_53: list[str] | None = None
    csf_tags: list[str] | None = None


class TaskCreate(BaseModel):
    title: str
    description: str | None = None


class ObservableCreate(BaseModel):
    type: ObservableType
    value: str
    is_ioc: bool = False
    tags: list[str] | None = None


class CommentCreate(BaseModel):
    content: str


# ── Cases ───────────────────────────────────────────────────────

@router.post("", status_code=201)
async def create_case(
    payload: CaseCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    case = Case(**payload.model_dump(), assigned_to_id=user.id)
    db.add(case)
    await db.commit()
    await db.refresh(case)
    return _case_dict(case)


@router.get("")
async def list_cases(
    status: CaseStatus | None = Query(None),
    severity: CaseSeverity | None = None,
    from_: int = Query(0, alias="from"),
    size: int = Query(25, le=100),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    q = select(Case)
    if status:
        q = q.where(Case.status == status)
    if severity:
        q = q.where(Case.severity == severity)
    q = q.offset(from_).limit(size).order_by(Case.created_at.desc())
    result = await db.execute(q)
    cases = result.scalars().all()
    return [_case_dict(c) for c in cases]


@router.get("/{case_id}")
async def get_case(
    case_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Case).where(Case.id == case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return _case_dict(case)


@router.patch("/{case_id}")
async def update_case(
    case_id: uuid.UUID,
    payload: CaseUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    result = await db.execute(select(Case).where(Case.id == case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    for key, value in payload.model_dump(exclude_none=True).items():
        setattr(case, key, value)

    if payload.status == CaseStatus.closed:
        case.closed_at = datetime.utcnow()

    await db.commit()
    await db.refresh(case)
    return _case_dict(case)


# ── Tasks ───────────────────────────────────────────────────────

@router.post("/{case_id}/tasks", status_code=201)
async def add_task(
    case_id: uuid.UUID,
    payload: TaskCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    task = CaseTask(case_id=case_id, **payload.model_dump())
    db.add(task)
    await db.commit()
    await db.refresh(task)
    return {"id": str(task.id), "title": task.title, "status": task.status.value}


@router.get("/{case_id}/tasks")
async def list_tasks(
    case_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(CaseTask).where(CaseTask.case_id == case_id))
    return [{"id": str(t.id), "title": t.title, "status": t.status.value} for t in result.scalars().all()]


# ── Observables ─────────────────────────────────────────────────

@router.post("/{case_id}/observables", status_code=201)
async def add_observable(
    case_id: uuid.UUID,
    payload: ObservableCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    obs = Observable(case_id=case_id, **payload.model_dump())
    db.add(obs)
    await db.commit()
    await db.refresh(obs)
    return {"id": str(obs.id), "type": obs.type.value, "value": obs.value, "is_ioc": obs.is_ioc}


@router.get("/{case_id}/observables")
async def list_observables(
    case_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    result = await db.execute(select(Observable).where(Observable.case_id == case_id))
    return [
        {"id": str(o.id), "type": o.type.value, "value": o.value, "is_ioc": o.is_ioc, "enrichment_data": o.enrichment_data}
        for o in result.scalars().all()
    ]


# ── Comments ────────────────────────────────────────────────────

@router.post("/{case_id}/comments", status_code=201)
async def add_comment(
    case_id: uuid.UUID,
    payload: CommentCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    comment = CaseComment(case_id=case_id, author_id=user.id, content=payload.content)
    db.add(comment)
    await db.commit()
    await db.refresh(comment)
    return {"id": str(comment.id), "content": comment.content, "created_at": comment.created_at.isoformat()}


# ── Alerts ──────────────────────────────────────────────────────

alert_router = APIRouter(prefix="/alerts", tags=["alerts"])


@alert_router.get("")
async def list_alerts(
    status: str | None = Query(None),
    from_: int = Query(0, alias="from"),
    size: int = Query(25, le=100),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    q = select(Alert)
    if status:
        q = q.where(Alert.status == status)
    q = q.offset(from_).limit(size).order_by(Alert.created_at.desc())
    result = await db.execute(q)
    return [_alert_dict(a) for a in result.scalars().all()]


@alert_router.post("/{alert_id}/promote")
async def promote_to_case(
    alert_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(require_analyst),
):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    case = Case(
        title=alert.title,
        description=alert.description,
        severity=alert.severity,
        assigned_to_id=user.id,
    )
    db.add(case)
    await db.flush()

    alert.promoted_to_case_id = case.id
    alert.status = "escalated"
    await db.commit()
    return {"case_id": str(case.id)}


# ── Helpers ─────────────────────────────────────────────────────

def _case_dict(c: Case) -> dict:
    return {
        "id": str(c.id),
        "title": c.title,
        "description": c.description,
        "severity": c.severity.value,
        "status": c.status.value,
        "tlp": c.tlp,
        "tags": c.tags,
        "stix_refs": c.stix_refs,
        "nist_800_53": c.nist_800_53 or [],
        "csf_tags": c.csf_tags or [],
        "created_at": c.created_at.isoformat(),
        "updated_at": c.updated_at.isoformat(),
    }


def _alert_dict(a: Alert) -> dict:
    return {
        "id": str(a.id),
        "title": a.title,
        "description": a.description,
        "source": a.source,
        "severity": a.severity.value,
        "status": a.status,
        "created_at": a.created_at.isoformat(),
    }
