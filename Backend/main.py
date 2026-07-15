
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from models.database import init_db
from routes.auth    import router as auth_router
from routes.images  import router as images_router
from routes.process import router as process_router
from security.rate_limiter import limiter
from security.audit_log import init_audit_log
from config import settings


# ── Lifespan (startup / shutdown) ─────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    os.makedirs(settings.upload_dir, exist_ok=True)
    await init_db()
    init_audit_log()
    yield
    # Shutdown — nothing to clean up for SQLite


# ── App factory ───────────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    app = FastAPI(
        title="CipherLens API",
        description="AI-assisted image cryptography benchmarking — hardened backend",
        version="3.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # ── Rate limiter state ────────────────────────────────────────────────────
    app.state.limiter = limiter

    # ── Middleware ────────────────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:4200", "http://127.0.0.1:4200", "http://localhost:3000"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(SlowAPIMiddleware)

    # ── Security headers middleware ───────────────────────────────────────────
    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"]  = "nosniff"
        response.headers["X-Frame-Options"]          = "DENY"
        response.headers["Referrer-Policy"]          = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"]       = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"]  = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data: blob:; frame-ancestors 'none'; base-uri 'self';"
        )
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"]        = "no-cache"
        return response

    # ── Rate limit error handler ──────────────────────────────────────────────
    @app.exception_handler(RateLimitExceeded)
    async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
        return JSONResponse(
            status_code=429,
            content={"success": False, "error": "Too many requests. Please slow down."},
        )

    # ── Routers ───────────────────────────────────────────────────────────────
    app.include_router(auth_router)
    app.include_router(images_router)
    app.include_router(process_router)

    # ── Static uploads ────────────────────────────────────────────────────────
    os.makedirs(settings.upload_dir, exist_ok=True)
    app.mount("/uploads", StaticFiles(directory=settings.upload_dir), name="uploads")

    # ── Health ────────────────────────────────────────────────────────────────
    @app.get("/api/health", tags=["Health"])
    async def health():
        return {
            "success": True,
            "status":  "ok",
            "version": "3.0.0",
            "framework": "FastAPI",
            "docs": "/docs",
            "security": {
                "rate_limiting":     True,
                "security_headers":  True,
                "jwt_2fa_auth":      True,
                "input_validation":  True,
                "file_hardening":    True,
                "field_encryption":  True,
                "db_isolation":      True,
                "audit_logging":     True,
            },
            "algorithms": list(settings.ALLOWED_ALGORITHMS),
        }

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
