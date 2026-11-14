"""SecureScan AI FastAPI application entry point."""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from app.core.config import settings
from app.core.errors import (
    SecureScanException,
    securescan_exception_handler,
    validation_exception_handler
)
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

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Custom typed error handlers
app.add_exception_handler(SecureScanException, securescan_exception_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)

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

