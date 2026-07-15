"""
Auth routes
-----------
POST /api/auth/register      — create account, get QR code
POST /api/auth/login         — email + password → pre_auth token
POST /api/auth/verify-2fa    — TOTP code → real JWT tokens
POST /api/auth/refresh       — swap refresh token for new access token
POST /api/auth/logout        — blacklist current token
GET  /api/auth/me            — get current user info
POST /api/auth/enable-2fa    — re-generate TOTP secret + QR
"""
import io, base64
import qrcode
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from models.database import get_db
from models.user import User
from security.validators import RegisterRequest, LoginRequest, TwoFARequest, UserOut
from security.jwt_handler import create_token, decode_token, revoke_token
from security.dependencies import get_current_user, get_pre_auth_user, get_refresh_user
from security.rate_limiter import limiter, LOGIN_LIMIT, REGISTER_LIMIT, TWOFA_LIMIT
from security.audit_log import (
    log_register, log_login_success, log_login_failure,
    log_2fa_success, log_2fa_failure, log_logout
)

router = APIRouter(prefix="/api/auth", tags=["Auth"])


def _qr_b64(uri: str) -> str:
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


# ── Register ──────────────────────────────────────────────────────────────────

@router.post("/register", status_code=status.HTTP_201_CREATED)
@limiter.limit(REGISTER_LIMIT)
async def register(
    body: RegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    email_hash = User.make_email_hash(body.email)

    existing = await db.execute(select(User).where(User.email_search_hash == email_hash))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="An account with this email already exists")

    user = User(full_name=body.full_name)
    user.set_email(body.email)
    user.set_password(body.password)
    user.generate_totp_secret()
    user.is_2fa_enabled  = True
    user.is_2fa_verified = False

    db.add(user)
    await db.commit()
    await db.refresh(user)
    log_register(user.id, request)

    totp_uri = user.get_totp_uri()
    return {
        "success":  True,
        "message":  "Account created. Scan the QR code in Google Authenticator.",
        "user":     user.to_dict(),
        "totp_uri": totp_uri,
        "qr_code":  _qr_b64(totp_uri),
    }


# ── Login step 1 ──────────────────────────────────────────────────────────────

@router.post("/login")
@limiter.limit(LOGIN_LIMIT)
async def login(
    body: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    email_hash = User.make_email_hash(body.email)
    result = await db.execute(
        select(User).where(User.email_search_hash == email_hash, User.is_active == True)
    )
    user = result.scalar_one_or_none()

    # Always verify password (constant time — prevents user enumeration)
    if not user or not user.verify_password(body.password):
        log_login_failure(body.email, request)
        raise HTTPException(status_code=401, detail="Invalid email or password")

    pre_auth_token = create_token(user.id, "pre_auth")
    return {
        "success":        True,
        "requires_2fa":   True,
        "pre_auth_token": pre_auth_token,
        "message":        "Enter the 6-digit code from your authenticator app",
    }


# ── Login step 2 — verify TOTP ────────────────────────────────────────────────

@router.post("/verify-2fa")
@limiter.limit(TWOFA_LIMIT)
async def verify_2fa(
    body: TwoFARequest,
    request: Request,
    auth_data: tuple = Depends(get_pre_auth_user),
    db: AsyncSession  = Depends(get_db),
):
    user, payload = auth_data

    if not user.verify_totp(body.code):
        log_2fa_failure(user.id, request)
        raise HTTPException(status_code=401, detail="Invalid or expired 2FA code")

    # First-time: mark 2FA as verified
    if not user.is_2fa_verified:
        user.is_2fa_verified = True
        await db.commit()

    # Blacklist pre-auth token
    revoke_token(payload.get("jti", ""))

    access  = create_token(user.id, "access")
    refresh = create_token(user.id, "refresh")
    log_2fa_success(user.id, request)
    log_login_success(user.id, request)

    return {
        "success":       True,
        "message":       "2FA verified. Logged in successfully.",
        "access_token":  access,
        "refresh_token": refresh,
        "token_type":    "bearer",
        "user":          user.to_dict(),
    }


# ── Refresh ───────────────────────────────────────────────────────────────────

@router.post("/refresh")
async def refresh(user: User = Depends(get_refresh_user)):
    return {
        "success":      True,
        "access_token": create_token(user.id, "access"),
        "token_type":   "bearer",
    }


# ── Logout ────────────────────────────────────────────────────────────────────

@router.post("/logout")
async def logout(
    request: Request,
    user: User = Depends(get_current_user),
):
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "").strip()
    revoke_token(token)
    log_logout(user.id, request)
    return {"success": True, "message": "Logged out successfully"}


# ── Me ────────────────────────────────────────────────────────────────────────

@router.get("/me")
async def me(user: User = Depends(get_current_user)):
    return {"success": True, "user": user.to_dict()}


# ── Re-setup 2FA ──────────────────────────────────────────────────────────────

@router.post("/enable-2fa")
async def enable_2fa(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    user.generate_totp_secret()
    user.is_2fa_enabled  = True
    user.is_2fa_verified = False
    await db.commit()

    totp_uri = user.get_totp_uri()
    return {
        "success":  True,
        "message":  "Scan this QR code with your authenticator app.",
        "totp_uri": totp_uri,
        "qr_code":  _qr_b64(totp_uri),
    }
