import hashlib
from datetime import datetime, timezone
from sqlalchemy import String, Boolean, DateTime, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship
from models.database import Base
import bcrypt
import pyotp


class User(Base):
    __tablename__ = "users"

    id:               Mapped[int]  = mapped_column(Integer, primary_key=True)
    email:            Mapped[str]  = mapped_column(String(512), unique=True, nullable=False)
    email_search_hash:Mapped[str]  = mapped_column(String(64),  unique=True, nullable=False, index=True)
    password_hash:    Mapped[str]  = mapped_column(String(255), nullable=False)
    full_name:        Mapped[str | None] = mapped_column(String(255), nullable=True)

    totp_secret_enc:  Mapped[str | None] = mapped_column(String(512), nullable=True)
    is_2fa_enabled:   Mapped[bool] = mapped_column(Boolean, default=True,  nullable=False)
    is_2fa_verified:  Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_active:        Mapped[bool] = mapped_column(Boolean, default=True,  nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    images:  Mapped[list["Image"]]  = relationship(back_populates="user", cascade="all, delete-orphan")
    results: Mapped[list["Result"]] = relationship(back_populates="user", cascade="all, delete-orphan")

    # ── Password (raw bcrypt — no passlib) ────────────────────────────────────
    def set_password(self, plain: str) -> None:
        self.password_hash = bcrypt.hashpw(
            plain.encode("utf-8"), bcrypt.gensalt(rounds=12)
        ).decode("utf-8")

    def verify_password(self, plain: str) -> bool:
        return bcrypt.checkpw(plain.encode("utf-8"), self.password_hash.encode("utf-8"))

    # ── Email (AES-256-GCM encrypted) ─────────────────────────────────────────
    def set_email(self, plain: str) -> None:
        from security.encryption import encrypt_field
        plain = plain.strip().lower()
        self.email             = encrypt_field(plain)
        self.email_search_hash = hashlib.sha256(plain.encode()).hexdigest()

    def get_email(self) -> str:
        from security.encryption import decrypt_field
        try:
            return decrypt_field(self.email)
        except Exception:
            return self.email

    @staticmethod
    def make_email_hash(plain: str) -> str:
        return hashlib.sha256(plain.strip().lower().encode()).hexdigest()

    # ── TOTP (AES-256-GCM encrypted) ──────────────────────────────────────────
    def set_totp_secret(self, secret: str) -> None:
        from security.encryption import encrypt_field
        self.totp_secret_enc = encrypt_field(secret)

    def get_totp_secret(self) -> str | None:
        if not self.totp_secret_enc:
            return None
        from security.encryption import decrypt_field
        try:
            return decrypt_field(self.totp_secret_enc)
        except Exception:
            return self.totp_secret_enc

    def generate_totp_secret(self) -> str:
        secret = pyotp.random_base32()
        self.set_totp_secret(secret)
        return secret

    def get_totp_uri(self) -> str:
        return pyotp.totp.TOTP(self.get_totp_secret()).provisioning_uri(
            name=self.get_email(), issuer_name="CipherLens"
        )

    def verify_totp(self, code: str) -> bool:
        secret = self.get_totp_secret()
        if not secret:
            return False
        return pyotp.TOTP(secret).verify(code, valid_window=1)

    def to_dict(self) -> dict:
        return {
            "id":             self.id,
            "email":          self.get_email(),
            "full_name":      self.full_name,
            "is_2fa_enabled": self.is_2fa_enabled,
            "created_at":     self.created_at.isoformat() if self.created_at else None,
        }
