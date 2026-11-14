"""Remediation action schema."""
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, ConfigDict


class RemediationActionBase(BaseModel):
    priority: str = Field(..., description="P0, P1, P2")
    action_type: str = Field(..., description="ENGINEERING, DOCUMENTATION, ORGANIZATIONAL")
    target_id: str = Field(..., description="SEC-xxx, DPDP-xxx, or finding fingerprint")
    title: str
    steps: list[str]
    validation_method: str


class RemediationActionCreate(RemediationActionBase):
    audit_id: UUID


class RemediationAction(RemediationActionBase):
    id: UUID = Field(default_factory=uuid4)
    audit_id: UUID

    model_config = ConfigDict(from_attributes=True)
