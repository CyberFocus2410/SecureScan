"""SecureScan AI FastAPI application entry point."""
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

# 3. CORS middleware with explicit origin allow-list (Playbook §9)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-Session-ID", "Authorization", "Accept"],
    expose_headers=["X-RateLimit-Limit", "X-RateLimit-Remaining", "Retry-After"]
)

# Custom typed error handlers and generic 500 error mask (Playbook §20)
app.add_exception_handler(SecureScanException, securescan_exception_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(Exception, unhandled_exception_handler)

# Mount API v1 router
app.include_router(api_v1_router, prefix=settings.API_V1_STR)


@app.get("/")
def root():
    return {
        "project": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "docs": "/docs",
        "health": f"{settings.API_V1_STR}/health"
    }

