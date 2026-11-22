"""Resource limits, quotas, and boundary constraints."""
from pydantic_settings import BaseSettings, SettingsConfigDict


class LimitSettings(BaseSettings):
    """Enforceable resource limits for repository fetching and scanner execution."""
    # Repository ingestion caps (FRD §2, NFR-02)
    MAX_REPO_SIZE_BYTES: int = 150 * 1024 * 1024    # 150 MB
    MAX_FILE_COUNT: int = 2000                      # 2,000 files
    MAX_SINGLE_FILE_BYTES: int = 5 * 1024 * 1024    # 5 MB (for code/text files)
    MAX_MEDIA_FILE_BYTES: int = 100 * 1024 * 1024  # 100 MB (for binary media/assets/ML models)
    CLONE_TIMEOUT_SECONDS: int = 120                # 120 seconds
    SCANNER_TOOL_TIMEOUT_SECONDS: int = 120         # 120 seconds per scanner container

    # Queue & Session Quotas (FRD §10, NFR-06)
    MAX_ACTIVE_AUDITS_PER_SESSION: int = 2
    MAX_AUDITS_PER_HOUR_PER_SESSION: int = 10
    SESSION_TTL_HOURS: int = 24
    REPORT_RETENTION_HOURS: int = 24

    # Container Sandbox Caps (Architecture §5, NFR-03)
    CONTAINER_MEMORY_LIMIT: str = "1g"
    CONTAINER_CPU_LIMIT: float = 1.5
    CONTAINER_PIDS_LIMIT: int = 100

    model_config = SettingsConfigDict(
        env_prefix="LIMIT_",
        extra="ignore"
    )


limits = LimitSettings()

