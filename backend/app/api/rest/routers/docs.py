"""
Documentation endpoints — serve user and admin manuals.
"""
from fastapi import APIRouter
from fastapi.responses import FileResponse
from pathlib import Path

router = APIRouter(prefix="/docs", tags=["documentation"])

# Get path to backend root where manual files are located
# __file__ = /app/app/api/rest/routers/docs.py (in container) or actual path locally
# Go up: routers -> rest -> api -> app -> app -> backend root
DOCS_DIR = Path(__file__).parent.parent.parent.parent.parent

@router.get("/user-manual")
async def user_manual():
    """Serve user manual HTML."""
    manual_path = DOCS_DIR / "SOCINT_USER_MANUAL.html"
    if not manual_path.exists():
        return {"error": "User manual not found. Ensure SOCINT_USER_MANUAL.html is in socint root directory."}
    return FileResponse(manual_path, media_type="text/html")

@router.get("/admin-manual")
async def admin_manual():
    """Serve admin manual HTML."""
    manual_path = DOCS_DIR / "SOCINT_ADMIN_MANUAL.html"
    if not manual_path.exists():
        return {"error": "Admin manual not found. Ensure SOCINT_ADMIN_MANUAL.html is in socint root directory."}
    return FileResponse(manual_path, media_type="text/html")
