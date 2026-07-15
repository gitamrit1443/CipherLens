"""
Append-only audit log — security events for every auth + data action.
"""
import json, logging, os
from datetime import datetime, timezone
from fastapi import Request

audit_logger = logging.getLogger("cipherlens.audit")
_configured  = False


def init_audit_log(log_path: str = "audit.log") -> None:
    global _configured
    if _configured:
        return
    h = logging.FileHandler(log_path, encoding="utf-8")
    h.setFormatter(logging.Formatter("%(message)s"))
    audit_logger.addHandler(h)
    audit_logger.setLevel(logging.INFO)
    audit_logger.propagate = False
    _configured = True


def _ip(request: Request | None) -> str:
    if not request:
        return "unknown"
    forwarded = request.headers.get("X-Forwarded-For")
    return forwarded.split(",")[0].strip() if forwarded else (request.client.host if request.client else "unknown")


def log_event(event: str, user_id: int | None = None,
               request: Request | None = None, extra: dict | None = None) -> None:
    entry = {
        "ts":      datetime.now(timezone.utc).isoformat(),
        "event":   event,
        "user_id": user_id,
        "ip":      _ip(request),
        "path":    request.url.path if request else None,
    }
    if extra:
        entry.update(extra)
    audit_logger.info(json.dumps(entry))


def log_register(user_id: int, req: Request | None = None)           -> None: log_event("register",      user_id, req)
def log_login_success(user_id: int, req: Request | None = None)      -> None: log_event("login_success", user_id, req)
def log_login_failure(email: str,  req: Request | None = None)       -> None: log_event("login_failure", None,    req, {"email_hash": hash(email) & 0xFFFF})
def log_2fa_success(user_id: int,  req: Request | None = None)       -> None: log_event("2fa_success",   user_id, req)
def log_2fa_failure(user_id: int,  req: Request | None = None)       -> None: log_event("2fa_failure",   user_id, req)
def log_logout(user_id: int,       req: Request | None = None)       -> None: log_event("logout",        user_id, req)
def log_upload(user_id: int, fname: str, req: Request | None = None) -> None: log_event("image_upload",  user_id, req, {"filename": fname})
def log_process(user_id: int, algo: str, req: Request | None = None) -> None: log_event("process_image", user_id, req, {"algorithm": algo})
