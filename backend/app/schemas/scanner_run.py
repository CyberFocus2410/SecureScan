"""ScannerRun schema specification."""
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, ConfigDict
from app.schemas.enums import ScannerName


class ScannerRunBase(BaseModel):
    scanner: ScannerName
    version: str
    status: str = Field(..., description="QUEUED, RUNNING, COMPLETED, FAILED, TIMEOUT, SKIPPED")
    duration_ms: int = 0
    findings_count: int = 0
    error_code: str | None = None


class ScannerRunCreate(ScannerRunBase):
    audit_id: UUID


class ScannerRun(ScannerRunBase):
    id: UUID = Field(default_factory=uuid4)
    audit_id: UUID

    model_config = ConfigDict(from_attributes=True)
