"""
FastAPI dependencies — inject into routes via Depends().

Usage:
    @router.get("/me")
    async def me(user: User = Depends(get_current_user)):
        ...
"""
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from models.database import get_db
from models.user import User
from security.jwt_handler import decode_token

bearer_scheme = HTTPBearer(auto_error=True)


async def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db:    AsyncSession                 = Depends(get_db),
) -> User:
    """
    Dependency that:
    1. Extracts Bearer token from Authorization header
    2. Decodes + validates JWT
    3. Rejects pre_auth tokens (2FA not complete)
    4. Loads user from DB
    """
    payload = decode_token(creds.credentials)

    if payload.get("type") == "pre_auth":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Complete 2FA verification first — use /api/auth/verify-2fa",
        )

    user_id = int(payload["sub"])
    result  = await db.execute(select(User).where(User.id == user_id, User.is_active == True))
    user    = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    return user


async def get_pre_auth_user(
    creds: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db:    AsyncSession                 = Depends(get_db),
) -> tuple[User, dict]:
    """
    Dependency for /verify-2fa only.
    Requires a pre_auth token (rejects full access tokens).
    Returns (user, payload).
    """
    payload = decode_token(creds.credentials)

    if payload.get("type") != "pre_auth":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Use /api/auth/login first to get a pre_auth token",
        )

    user_id = int(payload["sub"])
    result  = await db.execute(select(User).where(User.id == user_id, User.is_active == True))
    user    = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    return user, payload


async def get_refresh_user(
    creds: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db:    AsyncSession                 = Depends(get_db),
) -> User:
    """Dependency for /refresh — requires a refresh token."""
    payload = decode_token(creds.credentials)

    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="A refresh token is required for this endpoint",
        )

    user_id = int(payload["sub"])
    result  = await db.execute(select(User).where(User.id == user_id, User.is_active == True))
    user    = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    return user
