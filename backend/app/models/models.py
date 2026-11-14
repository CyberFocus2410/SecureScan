"""SQLAlchemy ORM models corresponding to Architecture §6 data architecture."""
import uuid
from datetime import datetime
from sqlalchemy import (
    Column,
    String,
    Integer,
    DateTime,
    ForeignKey,
    JSON,
    Text,
    Date
)
from sqlalchemy.orm import relationship
from app.core.db import Base


def generate_uuid() -> str:
    return str(uuid.uuid4())


class RepositoryModel(Base):
    __tablename__ = "repositories"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    github_owner = Column(String(255), nullable=False)
    github_repo = Column(String(255), nullable=False)
    canonical_url = Column(String(512), unique=True, nullable=False, index=True)
    default_branch = Column(String(100), default="main", nullable=False)
    last_commit_sha = Column(String(40), nullable=True)
    detected_languages = Column(JSON, default=list)
    detected_frameworks = Column(JSON, default=list)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    audits = relationship("AuditModel", back_populates="repository", cascade="all, delete-orphan")


class AuditModel(Base):
    __tablename__ = "audits"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    repository_id = Column(String(36), ForeignKey("repositories.id"), nullable=False, index=True)
    session_id = Column(String(64), nullable=False, index=True)
    commit_sha = Column(String(40), nullable=True)
    scopes = Column(JSON, default=list, nullable=False)
    status = Column(String(30), default="QUEUED", nullable=False, index=True)
    current_stage = Column(String(50), default="QUEUED", nullable=False)
    coverage_json = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)

    repository = relationship("RepositoryModel", back_populates="audits")
    scanner_runs = relationship("ScannerRunModel", back_populates="audit", cascade="all, delete-orphan")
    findings = relationship("FindingModel", back_populates="audit", cascade="all, delete-orphan")
    control_results = relationship("ControlResultModel", back_populates="audit", cascade="all, delete-orphan")
    events = relationship("AuditEventModel", back_populates="audit", cascade="all, delete-orphan")
    remediations = relationship("RemediationActionModel", back_populates="audit", cascade="all, delete-orphan")
    reports = relationship("ReportArtifactModel", back_populates="audit", cascade="all, delete-orphan")


class ScannerRunModel(Base):
    __tablename__ = "scanner_runs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    audit_id = Column(String(36), ForeignKey("audits.id"), nullable=False, index=True)
    scanner = Column(String(50), nullable=False)
    version = Column(String(50), nullable=False)
    status = Column(String(30), nullable=False)
    duration_ms = Column(Integer, default=0)
    findings_count = Column(Integer, default=0)
    error_code = Column(String(50), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    audit = relationship("AuditModel", back_populates="scanner_runs")


class FindingModel(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    audit_id = Column(String(36), ForeignKey("audits.id"), nullable=False, index=True)
    fingerprint = Column(String(64), nullable=False, index=True)
    scanner_name = Column(String(50), nullable=False)
    scanner_version = Column(String(50), nullable=False)
    rule_id = Column(String(100), nullable=False)
    category = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False)
    confidence = Column(String(20), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    file_path = Column(String(1024), nullable=False)
    start_line = Column(Integer, nullable=False)
    end_line = Column(Integer, nullable=False)
    cwe_ids = Column(JSON, default=list)
    owasp_refs = Column(JSON, default=list)
    redacted_snippet = Column(Text, nullable=True)
    technical_fix = Column(Text, nullable=True)
    validation_steps = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    audit = relationship("AuditModel", back_populates="findings")
    evidence = relationship("EvidenceModel", back_populates="finding", cascade="all, delete-orphan")


class EvidenceModel(Base):
    __tablename__ = "evidence"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    audit_id = Column(String(36), ForeignKey("audits.id"), nullable=False, index=True)
    finding_id = Column(String(36), ForeignKey("findings.id"), nullable=True, index=True)
    control_result_id = Column(String(36), ForeignKey("control_results.id"), nullable=True, index=True)
    tier = Column(String(30), nullable=False)
    path = Column(String(1024), nullable=False)
    start_line = Column(Integer, nullable=True)
    end_line = Column(Integer, nullable=True)
    redacted_excerpt = Column(Text, nullable=False)
    raw_data = Column(JSON, default=dict)
    provenance = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    finding = relationship("FindingModel", back_populates="evidence")
    control_result = relationship("ControlResultModel", back_populates="evidence_items")


class ControlCatalogueModel(Base):
    __tablename__ = "control_catalogue"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    control_id = Column(String(50), unique=True, nullable=False, index=True)
    domain = Column(String(20), nullable=False)  # SECURITY, DPDP
    version = Column(String(20), nullable=False)
    label = Column(String(255), nullable=False)
    source_uri = Column(String(512), nullable=True)
    source_ref = Column(String(100), nullable=True)
    applicability_json = Column(JSON, default=dict)
    effective_at = Column(Date, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class ControlResultModel(Base):
    __tablename__ = "control_results"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    audit_id = Column(String(36), ForeignKey("audits.id"), nullable=False, index=True)
    control_id = Column(String(50), nullable=False, index=True)
    domain = Column(String(20), nullable=False)
    title = Column(String(255), nullable=False)
    state = Column(String(30), nullable=False)
    readiness_label = Column(String(50), nullable=True)
    effective_date_status = Column(String(30), default="NOT_DETERMINED")
    effective_date = Column(Date, nullable=True)
    rationale = Column(Text, nullable=False)
    evidence_tier = Column(String(30), nullable=True)
    evaluated_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    audit = relationship("AuditModel", back_populates="control_results")
    evidence_items = relationship("EvidenceModel", back_populates="control_result", cascade="all, delete-orphan")


class OwaspMappingModel(Base):
    __tablename__ = "owasp_mappings"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    internal_control_id = Column(String(50), nullable=False, index=True)
    standard = Column(String(50), nullable=False)
    standard_version = Column(String(20), nullable=False)
    external_ref = Column(String(50), nullable=False)
    rationale = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class DpdpProfileModel(Base):
    __tablename__ = "dpdp_profiles"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    audit_id = Column(String(36), ForeignKey("audits.id"), unique=True, nullable=False, index=True)
    questionnaire_json = Column(JSON, default=dict, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class LegalSourceModel(Base):
    __tablename__ = "legal_sources"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    doc_name = Column(String(255), nullable=False)
    clause_ref = Column(String(100), nullable=False)
    source_url = Column(String(512), nullable=True)
    gazette_id = Column(String(50), nullable=True)
    version = Column(String(50), nullable=False)
    effective_at = Column(Date, nullable=True)
    reviewed_at = Column(Date, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class PenaltyCategoryModel(Base):
    __tablename__ = "penalty_categories"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    schedule_item = Column(Integer, nullable=False)
    related_act_section = Column(String(100), nullable=False)
    ceiling_inr = Column(String(50), nullable=False)
    legal_source_id = Column(String(36), ForeignKey("legal_sources.id"), nullable=True)
    caveat = Column(String(255), default="Potential legal category; applicability and liability not determined.", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class RemediationActionModel(Base):
    __tablename__ = "remediation_actions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    audit_id = Column(String(36), ForeignKey("audits.id"), nullable=False, index=True)
    priority = Column(String(10), nullable=False)
    action_type = Column(String(30), nullable=False)
    target_id = Column(String(100), nullable=False)
    title = Column(String(255), nullable=False)
    steps_json = Column(JSON, default=list, nullable=False)
    validation_method = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    audit = relationship("AuditModel", back_populates="remediations")

    def __init__(self, **kwargs):
        if "steps" in kwargs and "steps_json" not in kwargs:
            kwargs["steps_json"] = kwargs.pop("steps")
        super().__init__(**kwargs)

    @property
    def steps(self):
        return self.steps_json or []

    @steps.setter
    def steps(self, val):
        self.steps_json = val or []


class ReportArtifactModel(Base):
    __tablename__ = "report_artifacts"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    audit_id = Column(String(36), ForeignKey("audits.id"), nullable=False, index=True)
    format = Column(String(10), nullable=False)  # pdf, json
    status = Column(String(20), default="PROCESSING", nullable=False)
    safe_storage_key = Column(String(512), nullable=True)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    audit = relationship("AuditModel", back_populates="reports")


class AuditEventModel(Base):
    __tablename__ = "audit_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    audit_id = Column(String(36), ForeignKey("audits.id"), nullable=False, index=True)
    stage = Column(String(50), nullable=False)
    state = Column(String(20), nullable=False)
    message = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)

    audit = relationship("AuditModel", back_populates="events")

