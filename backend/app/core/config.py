"""Application configuration using Pydantic Settings."""
from pathlib import Path
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
    AS_OF_DATE: str = "2026-11-14"

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

