"""
JWT handler — create and decode access / refresh / pre-auth tokens.
Uses python-jose with HS256.
"""
from datetime import datetime, timedelta, timezone
from typing import Literal
from jose import JWTError, jwt
from fastapi import HTTPException, status
from config import settings

# In-memory blacklist (swap with Redis in production)
_blacklist: set[str] = set()

TokenType = Literal["access", "refresh", "pre_auth"]


def create_token(user_id: int, token_type: TokenType) -> str:
    now = datetime.now(timezone.utc)

    if token_type == "access":
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    elif token_type == "refresh":
        expire = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    else:  # pre_auth — short lived, 5 minutes
        expire = now + timedelta(minutes=5)

    payload = {
        "sub":  str(user_id),
        "type": token_type,
        "exp":  expire,
        "iat":  now,
        # unique ID for blacklisting
        "jti":  f"{user_id}:{token_type}:{now.timestamp()}",
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    """Decode and validate a JWT. Raises HTTPException on any failure."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if payload.get("jti") in _blacklist:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has been revoked")
    return payload


def blacklist_token(jti: str) -> None:
    _blacklist.add(jti)


def revoke_token(token: str) -> None:
    """Decode (ignoring expiry) and blacklist the token's jti."""
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options={"verify_exp": False},
        )
        if jti := payload.get("jti"):
            blacklist_token(jti)
    except JWTError:
        pass  # already invalid — nothing to do
