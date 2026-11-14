"""Evidence schema specification."""
from typing import Any
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, ConfigDict
from app.schemas.enums import EvidenceTier


class EvidenceBase(BaseModel):
    """Base schema for evidence records."""
    tier: EvidenceTier
    path: str
    start_line: int | None = None
    end_line: int | None = None
    redacted_excerpt: str = Field(..., description="Sanitized excerpt with secret tokens replaced by [REDACTED:<type>]")
    raw_data: dict[str, Any] = Field(default_factory=dict, description="Scanner-specific metadata, scrubbed of secrets")
    provenance: str = Field(..., description="Origin scanner name, rule identifier, and tool version")


class EvidenceCreate(EvidenceBase):
    audit_id: UUID
    finding_id: UUID | None = None
    control_result_id: UUID | None = None


class Evidence(EvidenceBase):
    id: UUID = Field(default_factory=uuid4)
    audit_id: UUID
    finding_id: UUID | None = None
    control_result_id: UUID | None = None

    model_config = ConfigDict(from_attributes=True)
