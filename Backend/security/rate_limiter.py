"""
Layer 1 — Rate Limiting via SlowAPI (FastAPI-compatible).
Skipped automatically in TESTING mode.
"""
from slowapi import Limiter
from slowapi.util import get_remote_address
from config import settings

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200/day", "50/hour"],
    enabled=not settings.TESTING,
    storage_uri="memory://",
)

# Limit strings used as decorator args in routes
LOGIN_LIMIT    = "5/minute;20/hour"
REGISTER_LIMIT = "3/minute;10/hour"
UPLOAD_LIMIT   = "20/minute;200/day"
PROCESS_LIMIT  = "30/minute;500/day"
TWOFA_LIMIT    = "10/minute;30/hour"
