"""Application configuration using Pydantic Settings."""
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Union, List
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Global application settings and environment overrides."""
    PROJECT_NAME: str = "SecureScan AI"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False

    # Database
    DATABASE_URL: str = "sqlite:///./securescan_dev.db"

    # Redis & RQ
    REDIS_URL: str = "redis://localhost:6379/0"
    RQ_QUEUE_NAME: str = "securescan_audits"

    # Governance & Dates
    AS_OF_DATE: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        description="Statutory baseline as-of date (UTC). Defaults to today's date."
    )

    # Sandbox Isolation (Architecture §5, ADR-002)
    SANDBOX_BACKEND: str = "auto"

    # Security & CORS
    CORS_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://securescanbox.xyz",
        "https://www.securescanbox.xyz",
        "http://securescanbox.xyz",
        "http://www.securescanbox.xyz",
        "https://secure-scan-two.vercel.app",
    ]
    CORS_ORIGIN_REGEX: str = r"^https?:\/\/(localhost|127\.0\.0\.1|.*\.vercel\.app|(.*\.)?securescanbox\.xyz)(:\d+)?$"

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            v_stripped = v.strip()
            if v_stripped.startswith("[") and v_stripped.endswith("]"):
                try:
                    return json.loads(v_stripped)
                except Exception:
                    pass
            return [i.strip() for i in v.split(",") if i.strip()]
        elif isinstance(v, list):
            return v
        return [
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "https://securescanbox.xyz",
            "https://www.securescanbox.xyz",
            "http://securescanbox.xyz",
            "http://www.securescanbox.xyz",
            "https://secure-scan-two.vercel.app",
        ]
    SECURITY_HEADERS_ENABLED: bool = True
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_REQUESTS_PER_MINUTE: int = 120
    WEBHOOK_SECRET: str | None = None

    # Paths
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent.parent
    POLICY_DIR: Path = Path(__file__).resolve().parent.parent.parent.parent / "policies"
    WORKTREE_STORAGE_DIR: Path = Path(__file__).resolve().parent.parent.parent.parent / "tmp" / "worktrees"
    REPORTS_STORAGE_DIR: Path = Path(__file__).resolve().parent.parent.parent.parent / "tmp" / "reports"

    # AI Configuration (Optional P1)
    GEMINI_API_KEY: str | None = None
    AI_EXPLAIN_ENABLED: bool = False

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()

