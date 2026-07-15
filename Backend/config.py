"""
Central config — reads from .env automatically.
Access anywhere: from config import settings
"""
import os
from functools import lru_cache
from dotenv import load_dotenv

load_dotenv()

class Settings:
    APP_ENV:                    str = os.getenv("APP_ENV", "development")
    SECRET_KEY:                 str = os.getenv("SECRET_KEY", "dev-secret-change-in-prod-min-32c")
    JWT_ALGORITHM:              str = os.getenv("JWT_ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES:int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60))
    REFRESH_TOKEN_EXPIRE_DAYS:  int = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", 30))

    DATABASE_URL:  str = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./cipherlens.db")
    UPLOAD_FOLDER: str = os.getenv("UPLOAD_FOLDER", "static/uploads")
    MAX_UPLOAD_MB: int = int(os.getenv("MAX_UPLOAD_MB", 16))
    BASE_URL:      str = os.getenv("BASE_URL", "http://localhost:8000")

    FIELD_ENCRYPTION_KEY: str = os.getenv(
        "FIELD_ENCRYPTION_KEY", "dev-field-key-change-in-prod-min-32c"
    )

    ALLOWED_EXTENSIONS: set = {"png", "jpg", "jpeg", "webp", "bmp"}
    ALLOWED_ALGORITHMS: set = {"xor", "aes", "3des", "perm", "rc4", "blowfish"}

    TESTING: bool = os.getenv("APP_ENV") == "testing"

    @property
    def upload_dir(self) -> str:
        base = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(base, self.UPLOAD_FOLDER)

    @property
    def max_upload_bytes(self) -> int:
        return self.MAX_UPLOAD_MB * 1024 * 1024


@lru_cache()
def get_settings() -> Settings:
    return Settings()

settings = get_settings()
