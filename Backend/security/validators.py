"""
Layer 4 — Pydantic v2 request schemas.
FastAPI validates all incoming JSON automatically against these.
Unknown fields are ignored (extra="ignore").
"""
import re
from typing import Literal
from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator

ALLOWED_ALGORITHMS = {"xor", "aes", "3des", "perm", "rc4", "blowfish"}
AlgorithmType = Literal["xor", "aes", "3des", "perm", "rc4", "blowfish"]


class _Base(BaseModel):
    model_config = {"extra": "ignore"}   # drop unknown fields — injection protection


# ── Auth schemas ──────────────────────────────────────────────────────────────

class RegisterRequest(_Base):
    email:     EmailStr
    password:  str = Field(min_length=8, max_length=128)
    full_name: str | None = Field(default=None, max_length=128)

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v

    @field_validator("full_name")
    @classmethod
    def no_special_chars(cls, v: str | None) -> str | None:
        if v and re.search(r"[<>\"'%;()&+]", v):
            raise ValueError("Full name contains invalid characters")
        return v


class LoginRequest(_Base):
    email:    EmailStr
    password: str = Field(min_length=1, max_length=256)


class TwoFARequest(_Base):
    code: str = Field(min_length=6, max_length=6)

    @field_validator("code")
    @classmethod
    def digits_only(cls, v: str) -> str:
        if not v.isdigit():
            raise ValueError("Code must be exactly 6 digits")
        return v


# ── Process schemas ───────────────────────────────────────────────────────────

class ProcessRequest(_Base):
    image_id:  int          = Field(gt=0)
    algorithm: AlgorithmType
    key:       str          = Field(min_length=1, max_length=256)

    @field_validator("key")
    @classmethod
    def no_null_bytes(cls, v: str) -> str:
        if "\x00" in v:
            raise ValueError("Key must not contain null bytes")
        return v


class BenchmarkRequest(_Base):
    image_id:   int                     = Field(gt=0)
    key:        str                     = Field(min_length=1, max_length=256)
    algorithms: list[AlgorithmType] | None = Field(default=None, max_length=6)

    @field_validator("key")
    @classmethod
    def no_null_bytes(cls, v: str) -> str:
        if "\x00" in v:
            raise ValueError("Key must not contain null bytes")
        return v


# ── Response schemas (for OpenAPI docs) ──────────────────────────────────────

class UserOut(_Base):
    id:             int
    email:          str
    full_name:      str | None
    is_2fa_enabled: bool
    created_at:     str | None


class ImageOut(_Base):
    id:            int
    url:           str
    filename:      str
    original_name: str | None
    file_size:     int | None
    mime_type:     str | None
    uploaded_at:   str | None
    result_count:  int


class MetricsOut(_Base):
    mse:     float
    psnr:    float
    ssim:    float
    npcr:    float
    uaci:    float
    entropy: float


class ResultOut(_Base):
    id:                  int
    image_id:            int
    algorithm:           str
    metrics:             dict
    encrypted_image_url: str | None
    processing_time_ms:  float | None
    created_at:          str | None


class SuccessResponse(_Base):
    success: bool = True
