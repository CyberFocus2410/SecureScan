"""ControlResult and Security/DPDP coverage schemas."""
from datetime import date, datetime
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, ConfigDict
from app.schemas.enums import ControlState, EvidenceTier, EffectiveDateStatus
from app.schemas.evidence import Evidence


class StatutoryRef(BaseModel):
    """Citation metadata for legal obligations and penalty schedule."""
    source_doc: str
    clause: str
    source_url: str | None = None
    schedule_item: int | None = None
    statutory_ceiling: str | None = None
    mandatory_caveat: str = "Potential legal category; applicability and liability not determined."


class ControlResultBase(BaseModel):
    control_id: str = Field(..., description="SEC-xxx or DPDP-xxx")
    domain: str = Field(..., description="SECURITY or DPDP")
    title: str
    state: ControlState
    readiness_label: str | None = None
    effective_date_status: EffectiveDateStatus = EffectiveDateStatus.NOT_DETERMINED
    effective_date: date | None = None
    rationale: str
    evidence_tier: EvidenceTier | None = None
    statutory_ref: StatutoryRef | None = None


class ControlResultCreate(ControlResultBase):
    audit_id: UUID


class ControlResult(ControlResultBase):
    id: UUID = Field(default_factory=uuid4)
    audit_id: UUID
    evaluated_at: datetime = Field(default_factory=datetime.utcnow)
    evidence_items: list[Evidence] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class SecurityCoverageSummary(BaseModel):
    total_controls: int
    evidenced_pass: int
    evidenced_fail: int
    potential_gap: int
    not_verified: int
    not_applicable: int
    error: int = 0
    applicable_controls: int = 0
    evidenced_controls: int = 0
    coverage_ratio: float = 0.0
    denominator: int = 0


class SecurityCoverageResponse(BaseModel):
    summary: SecurityCoverageSummary
    controls: list[ControlResult]
