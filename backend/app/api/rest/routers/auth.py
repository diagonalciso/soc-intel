from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, EmailStr
from datetime import datetime

from app.db.postgres import get_db
from app.models.user import User, Organization, APIKey
from app.auth.security import (
    hash_password, verify_password, create_access_token, generate_api_key
)
from app.auth.dependencies import get_current_user

router = APIRouter(prefix="/auth", tags=["auth"])


class RegisterRequest(BaseModel):
    email: EmailStr
    username: str
    password: str
    organization_name: str | None = None


class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(req: RegisterRequest, db: AsyncSession = Depends(get_db)):
    # Check unique
    result = await db.execute(select(User).where(User.email == req.email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

    org = None
    if req.organization_name:
        result = await db.execute(select(Organization).where(Organization.name == req.organization_name))
        org = result.scalar_one_or_none()
        if not org:
            org = Organization(name=req.organization_name)
            db.add(org)
            await db.flush()

    user = User(
        email=req.email,
        username=req.username,
        hashed_password=hash_password(req.password),
        organization_id=org.id if org else None,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return {"id": str(user.id), "email": user.email, "username": user.username}


@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == req.email, User.is_active == True))
    user = result.scalar_one_or_none()
    if not user or not verify_password(req.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    user.last_login = datetime.utcnow()
    await db.commit()

    token = create_access_token({"sub": str(user.id), "role": user.role.value})
    return TokenResponse(access_token=token)


class APIKeyCreate(BaseModel):
    label: str = "unnamed"


@router.post("/api-keys")
async def create_api_key(
    payload: APIKeyCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    raw, hashed = generate_api_key()
    api_key = APIKey(name=payload.label, key_hash=hashed, user_id=current_user.id)
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)
    # Return raw key ONCE — never stored in plain text
    return {
        "key": raw,
        "id": str(api_key.id),
        "label": payload.label,
        "key_prefix": raw[:8],
        "created_at": api_key.created_at.isoformat() if api_key.created_at else None,
        "message": "Store this key — it will not be shown again",
    }


@router.get("/api-keys")
async def list_api_keys(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(APIKey).where(APIKey.user_id == current_user.id, APIKey.is_active == True)
    )
    keys = result.scalars().all()
    return {
        "api_keys": [
            {
                "id": str(k.id),
                "label": k.name,
                "key_prefix": k.key_hash[:8] if k.key_hash else "?",
                "created_at": k.created_at.isoformat() if k.created_at else None,
            }
            for k in keys
        ]
    }


@router.delete("/api-keys/{key_id}", status_code=204)
async def revoke_api_key(
    key_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    import uuid as _uuid
    key = await db.get(APIKey, _uuid.UUID(key_id))
    if not key or key.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="API key not found")
    key.is_active = False
    await db.commit()


@router.get("/me")
async def me(current_user: User = Depends(get_current_user)):
    return {
        "id": str(current_user.id),
        "email": current_user.email,
        "username": current_user.username,
        "role": current_user.role.value,
    }
