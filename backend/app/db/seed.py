"""
First-run seeder.
Creates a default admin user if no users exist.
Credentials are read from env vars with safe defaults.
"""
import logging
import os

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User, Organization, UserRole
from app.auth.security import hash_password

logger = logging.getLogger(__name__)

DEFAULT_ORG   = os.getenv("SEED_ORG",      "SOCINT")
DEFAULT_EMAIL = os.getenv("SEED_EMAIL",     "admin@socint.internal")
DEFAULT_USER  = os.getenv("SEED_USERNAME",  "admin")
DEFAULT_PASS  = os.getenv("SEED_PASSWORD",  "changeme123!")


async def seed_default_admin(db: AsyncSession) -> None:
    result = await db.execute(select(User).limit(1))
    if result.scalar_one_or_none():
        return  # already have users — skip

    logger.info("No users found — seeding default admin account")

    # Create org
    org = Organization(name=DEFAULT_ORG)
    db.add(org)
    await db.flush()

    # Create admin
    user = User(
        email=DEFAULT_EMAIL,
        username=DEFAULT_USER,
        hashed_password=hash_password(DEFAULT_PASS),
        role=UserRole.admin,
        organization_id=org.id,
    )
    db.add(user)
    await db.commit()

    logger.info(
        "Default admin created — email: %s  password: %s  "
        "(set SEED_EMAIL / SEED_PASSWORD in .env to change)",
        DEFAULT_EMAIL,
        DEFAULT_PASS,
    )
