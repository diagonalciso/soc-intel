"""Auth disabled — open access for local network use."""
from fastapi import Depends
from app.models.user import User, UserRole
import uuid


class _AnonUser:
    id = uuid.UUID("00000000-0000-0000-0000-000000000001")
    email = "anon@local"
    username = "local"
    role = UserRole.admin
    is_active = True
    organization_id = None


_ANON = _AnonUser()


async def get_current_user() -> User:
    return _ANON  # type: ignore


async def require_analyst() -> User:
    return _ANON  # type: ignore


async def require_admin() -> User:
    return _ANON  # type: ignore
