"""Normalized Finding schema specification."""
from uuid import UUID, uuid4
from typing import Any
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

    # Section 6 Unified Finding Extensions (ADR-002, Step 3)
    engine: str | None = None
    tool: str | None = None
    tool_version: str | None = None
    verified_state: str | None = None
    exploitability: str | None = None
    exposure: str | None = None
    data_sensitivity: str | None = None
    source: str | None = None
    data_flow: list[dict[str, Any]] | None = None
    sink: str | None = None
    affected: str | None = None
    request_evidence: str | None = None
    response_evidence: str | None = None
    standards: dict[str, Any] | None = None
    priority: str | None = None
    plain_title: str | None = None
    plain_summary: str | None = None
    why_it_matters: str | None = None
    how_to_fix: str | None = None
    how_to_verify_fix: str | None = None
    fix_effort: str | None = None
    fix_prompt: str | None = None
    related_finding_ids: list[str] | None = None
    attack_chain_id: str | None = None
    first_seen_scan_id: str | None = None
    status: str = "open"
    status_reason: str | None = None
    status_expires_at: Any | None = None
    status_updated_at: Any | None = None
    signals: list[str] | None = None


class FindingStatusUpdate(BaseModel):
    """Payload for finding lifecycle state transitions."""
    status: str = Field(..., description="Target state: open, fixed, accepted-risk, false-positive")
    reason: str | None = Field(None, description="Justification reason (mandatory for accepted-risk and false-positive)")
    expires_at: str | None = Field(None, description="ISO-8601 expiry timestamp for accepted risks")



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
