"""Report artifact schemas."""
from datetime import datetime
from uuid import UUID
from typing import Optional, Literal
from pydantic import BaseModel, Field, ConfigDict


class ReportCreateRequest(BaseModel):
    format: Literal["pdf", "json"] = Field("pdf", description="Requested report format ('pdf' or 'json')")

    model_config = ConfigDict(extra="forbid")


class ReportResponse(BaseModel):
    id: UUID
    audit_id: UUID
    format: str
    status: str = Field(..., description="PROCESSING, COMPLETED, FAILED")
    download_url: Optional[str] = None
    expires_at: datetime
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

