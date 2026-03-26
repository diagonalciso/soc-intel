"""
Connector management endpoints.
List, trigger, and monitor connectors.
"""
from fastapi import APIRouter, Depends, HTTPException

from app.workers.scheduler import CONNECTORS, run_connector_now
from app.auth.dependencies import require_analyst, require_admin
from app.models.user import User

router = APIRouter(prefix="/connectors", tags=["connectors"])


@router.get("")
async def list_connectors(user: User = Depends(require_analyst)):
    return [
        {
            "name": c.config.name,
            "display_name": c.config.display_name,
            "type": c.config.connector_type,
            "description": c.config.description,
            "schedule": c.config.schedule,
        }
        for c in CONNECTORS
    ]


@router.post("/{name}/trigger")
async def trigger_connector(name: str, user: User = Depends(require_analyst)):
    ok = await run_connector_now(name)
    if not ok:
        raise HTTPException(status_code=404, detail=f"Connector '{name}' not found")
    return {"status": "triggered", "connector": name}
