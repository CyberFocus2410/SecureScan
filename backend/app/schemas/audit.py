"""Audit and Repository schemas."""
from datetime import datetime
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, HttpUrl, ConfigDict
from app.schemas.enums import AuditStatus, AuditScope


class RepositoryCreate(BaseModel):
    github_url: HttpUrl
    branch: str = "main"


class Repository(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    github_owner: str
    github_repo: str
    canonical_url: str
    default_branch: str
    last_commit_sha: str | None = None
    detected_languages: list[str] = Field(default_factory=list)
    detected_frameworks: list[str] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class AuditCreate(BaseModel):
    repository_id: UUID
    scopes: list[AuditScope] = [AuditScope.SECURITY, AuditScope.DPDP]
    commit_sha: str | None = None


class AuditEvent(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    stage: str
    state: str
    message: str


class AuditCoverage(BaseModel):
    security: dict[str, int] = Field(default_factory=dict)
    dpdp: dict[str, int] = Field(default_factory=dict)


class Audit(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    repository_id: UUID
    commit_sha: str | None = None
    scopes: list[AuditScope]
    status: AuditStatus = AuditStatus.QUEUED
    current_stage: str = "QUEUED"
    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None
    coverage: AuditCoverage | None = None

    model_config = ConfigDict(from_attributes=True)
