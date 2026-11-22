"""SecureScan AI FastAPI application entry point."""
import os
import sys
from pathlib import Path

# Prepend application and local binary directories to PATH so pinned CLI tools are immediately discoverable
_bin_dir = Path(__file__).resolve().parent.parent / ".bin"
_local_bin = Path.home() / ".local" / "bin"
_current_path = os.environ.get("PATH", "")
_extra_paths = [str(_bin_dir), str(_local_bin), "/usr/local/bin", "/usr/bin", "/bin"]
_paths_to_add = [p for p in _extra_paths if p not in _current_path]
if _paths_to_add:
    os.environ["PATH"] = os.pathsep.join(_paths_to_add) + os.pathsep + _current_path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from app.core.config import settings
from app.core.errors import (
    SecureScanException,
    securescan_exception_handler,
    validation_exception_handler,
    unhandled_exception_handler
)
from app.core.security_headers import SecurityHeadersMiddleware
from app.core.rate_limit import RateLimitMiddleware
from app.api.v1 import api_v1_router
from app.core.db import engine, Base
import app.models  # ensure models are registered with Base.metadata

# Create DB tables if not present (useful for SQLite test & local dev)
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="SecureScan AI — Security and India DPDP Audit Platform",
    docs_url="/docs",
    redoc_url="/redoc"
)

# 1. Security Headers middleware (Playbook §1, §20)
app.add_middleware(SecurityHeadersMiddleware)

# 2. Rate limiting middleware (Playbook §16)
app.add_middleware(RateLimitMiddleware)

# 3. CORS middleware with explicit origin allow-list and domain regex (Playbook §9)
cors_origins = list(settings.CORS_ORIGINS)
for domain in [
    "https://securescanbox.xyz",
    "https://www.securescanbox.xyz",
    "http://securescanbox.xyz",
    "http://www.securescanbox.xyz",
    "https://secure-scan-two.vercel.app",
]:
    if domain not in cors_origins:
        cors_origins.append(domain)

default_cors_regex = r"^https?:\/\/(localhost|127\.0\.0\.1|.*\.vercel\.app|(.*\.)?securescanbox\.xyz)(:\d+)?$"
combined_cors_regex = (
    f"(?:{settings.CORS_ORIGIN_REGEX})|(?:{default_cors_regex})"
    if settings.CORS_ORIGIN_REGEX and settings.CORS_ORIGIN_REGEX != default_cors_regex
    else default_cors_regex
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_origin_regex=combined_cors_regex,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["X-RateLimit-Limit", "X-RateLimit-Remaining", "Retry-After"]
)

# Custom typed error handlers and generic 500 error mask (Playbook §20)
app.add_exception_handler(SecureScanException, securescan_exception_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(Exception, unhandled_exception_handler)

# Mount API v1 router
app.include_router(api_v1_router, prefix=settings.API_V1_STR)


@app.on_event("startup")
def startup_event():
    """Bootstrap primary security tools and verify environment readiness."""
    import threading
    from app.core.tools import ensure_tools_installed
    threading.Thread(target=ensure_tools_installed, daemon=True).start()


@app.get("/")
def root():
    return {
        "project": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "docs": "/docs",
        "health": f"{settings.API_V1_STR}/health"
    }

