"""Normalized Finding schema specification."""
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, ConfigDict
from app.schemas.enums import Severity, Confidence, ScannerName
from app.schemas.evidence import Evidence


class FindingRemediation(BaseModel):
    """Actionable remediation guidance."""
    technical_fix: str
    validation_steps: str


class FindingBase(BaseModel):
    fingerprint: str = Field(..., description="SHA-256 fingerprint for deduplication")
    scanner_name: ScannerName
    scanner_version: str
    rule_id: str
    title: str
    description: str
    category: str = Field(..., description="secrets, injection, auth, api, misconfig, dependency, data_exposure")
    severity: Severity
    confidence: Confidence
    file_path: str
    start_line: int
    end_line: int
    cwe_ids: list[str] = Field(default_factory=list)
    owasp_refs: list[str] = Field(default_factory=list)


class FindingCreate(FindingBase):
    audit_id: UUID
    remediation: FindingRemediation | None = None
    redacted_snippet: str | None = None


class Finding(FindingBase):
    id: UUID = Field(default_factory=uuid4)
    audit_id: UUID
    evidence: Evidence | None = None
    remediation: FindingRemediation | None = None
    redacted_snippet: str | None = None

    model_config = ConfigDict(from_attributes=True)


class FindingListResponse(BaseModel):
    items: list[Finding]
    total: int
    page: int
    page_size: int
