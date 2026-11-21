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
    Date,
    Boolean
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
    target_id = Column(String(36), ForeignKey("targets.id", ondelete="SET NULL"), nullable=True, index=True)
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
    tool_runs = relationship("ToolRunModel", back_populates="audit", cascade="all, delete-orphan")
    sbom_components = relationship("SbomComponentModel", back_populates="audit", cascade="all, delete-orphan")
    target = relationship("TargetModel", back_populates="audits")


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


class ToolRunModel(Base):
    """Execution telemetry and coverage tracking per tool run (Step 2, ADR-002)."""
    __tablename__ = "tool_runs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    audit_id = Column(String(36), ForeignKey("audits.id", ondelete="CASCADE"), nullable=False, index=True)
    tool = Column(String(50), nullable=False, index=True)
    version = Column(String(50), nullable=False)
    exit_status = Column(String(30), nullable=False)
    duration_ms = Column(Integer, default=0, nullable=False)
    coverage_metrics = Column(JSON, default=dict)
    stdout_preview = Column(Text, nullable=True)
    stderr_preview = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    audit = relationship("AuditModel", back_populates="tool_runs")


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

    # Unified Finding Model Extensions (Section 6, ADR-002, Step 3)
    engine = Column(String(30), nullable=True)
    tool = Column(String(50), nullable=True)
    tool_version = Column(String(50), nullable=True)
    verified_state = Column(String(30), nullable=True)
    exploitability = Column(String(30), nullable=True)
    exposure = Column(String(30), nullable=True)
    data_sensitivity = Column(String(30), nullable=True)
    source = Column(String(255), nullable=True)
    data_flow = Column(JSON, default=list)
    sink = Column(String(255), nullable=True)
    affected = Column(String(512), nullable=True)
    request_evidence = Column(Text, nullable=True)
    response_evidence = Column(Text, nullable=True)
    standards = Column(JSON, default=dict)
    priority = Column(String(10), nullable=True)
    plain_title = Column(String(255), nullable=True)
    plain_summary = Column(Text, nullable=True)
    why_it_matters = Column(Text, nullable=True)
    how_to_fix = Column(Text, nullable=True)
    how_to_verify_fix = Column(Text, nullable=True)
    fix_effort = Column(String(50), nullable=True)
    fix_prompt = Column(Text, nullable=True)
    related_finding_ids = Column(JSON, default=list)
    attack_chain_id = Column(String(36), nullable=True)
    first_seen_scan_id = Column(String(36), nullable=True)
    status = Column(String(30), default="open", nullable=False)
    status_reason = Column(Text, nullable=True)
    status_expires_at = Column(DateTime, nullable=True)
    status_updated_at = Column(DateTime, nullable=True)
    signals = Column(JSON, default=list)

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


class TargetModel(Base):
    """Owner-verified testing target (repositories, websites, APIs)."""
    __tablename__ = "targets"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    session_id = Column(String(64), nullable=False, index=True)
    name = Column(String(255), nullable=True)
    target_type = Column(String(20), nullable=False)  # REPOSITORY, WEBSITE, API
    url = Column(String(512), nullable=False, index=True)
    verified = Column(Boolean, default=False, nullable=False)
    verified_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    audits = relationship("AuditModel", back_populates="target")
    verifications = relationship("TargetVerificationModel", back_populates="target", cascade="all, delete-orphan")
    scopes = relationship("ScanScopeModel", back_populates="target", cascade="all, delete-orphan")
    consents = relationship("ConsentRecordModel", back_populates="target", cascade="all, delete-orphan")
    test_accounts = relationship("TestAccountModel", back_populates="target", cascade="all, delete-orphan")
    assets = relationship("AssetModel", back_populates="target", cascade="all, delete-orphan")
    endpoints = relationship("EndpointModel", back_populates="target", cascade="all, delete-orphan")


class TargetVerificationModel(Base):
    """Ownership verification records (DNS TXT, well-known file, meta tag, repo token)."""
    __tablename__ = "target_verifications"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    target_id = Column(String(36), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True)
    verification_method = Column(String(30), nullable=False)  # DNS_TXT, WELL_KNOWN_FILE, META_TAG, REPO_TOKEN
    token = Column(String(128), nullable=False)
    status = Column(String(20), default="PENDING", nullable=False)  # PENDING, VERIFIED, EXPIRED, FAILED
    proof_details = Column(JSON, default=dict)
    verified_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    target = relationship("TargetModel", back_populates="verifications")


class ScanProfileModel(Base):
    """Scan execution profile specifying intensity and budget limits."""
    __tablename__ = "scan_profiles"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(100), nullable=False)
    intensity = Column(String(20), default="STANDARD", nullable=False)  # PASSIVE, STANDARD, DEEP
    max_rps = Column(Integer, default=5, nullable=False)
    max_requests = Column(Integer, default=500, nullable=False)
    max_duration_seconds = Column(Integer, default=1200, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class ScanScopeModel(Base):
    """Target scope configuration constraining allowed paths and dropping dangerous operations."""
    __tablename__ = "scan_scopes"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    target_id = Column(String(36), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True)
    allowed_hosts = Column(JSON, default=list, nullable=False)
    allowed_paths = Column(JSON, default=list, nullable=False)
    excluded_paths = Column(JSON, default=list, nullable=False)
    max_rps = Column(Integer, default=5, nullable=False)
    max_crawl_depth = Column(Integer, default=3, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    target = relationship("TargetModel", back_populates="scopes")


class ConsentRecordModel(Base):
    """Immutable legal consent audit record for authorized security assessment."""
    __tablename__ = "consent_records"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    target_id = Column(String(36), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(String(64), nullable=False, index=True)
    client_ip = Column(String(64), nullable=False)
    terms_version = Column(String(20), default="2.0", nullable=False)
    scope_hash = Column(String(64), nullable=False)
    accepted_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    target = relationship("TargetModel", back_populates="consents")


class TestAccountModel(Base):
    """Encrypted test credentials for multi-account auth testing (purged/encrypted)."""
    __tablename__ = "test_accounts"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    target_id = Column(String(36), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True)
    role = Column(String(50), nullable=False)  # user_a, user_b, admin
    auth_type = Column(String(30), default="BEARER", nullable=False)
    encrypted_credentials = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    target = relationship("TargetModel", back_populates="test_accounts")


class AssetModel(Base):
    """Discovered attack-surface assets (hosts, subdomains, open services)."""
    __tablename__ = "assets"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    target_id = Column(String(36), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_type = Column(String(50), nullable=False)  # HOST, SUBDOMAIN, SERVICE, DB_PORT
    value = Column(String(512), nullable=False)
    first_seen_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    target = relationship("TargetModel", back_populates="assets")


class EndpointModel(Base):
    """Discovered API endpoints forming the API inventory."""
    __tablename__ = "endpoints"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    target_id = Column(String(36), ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True)
    method = Column(String(10), nullable=False)
    path = Column(String(1024), nullable=False)
    auth_required = Column(String(20), default="UNKNOWN", nullable=False)
    discovered_via = Column(String(50), default="SOURCE", nullable=False)
    pii_fields = Column(JSON, default=list)
    rate_limited = Column(String(20), default="UNKNOWN")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    target = relationship("TargetModel", back_populates="endpoints")


class SbomComponentModel(Base):
    """Software Bill of Materials (SBOM) dependency components."""
    __tablename__ = "sbom_components"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    audit_id = Column(String(36), ForeignKey("audits.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    version = Column(String(100), nullable=False)
    ecosystem = Column(String(50), nullable=False)
    purl = Column(String(512), nullable=True)
    license = Column(String(100), nullable=True)
    is_direct = Column(Boolean, default=True, nullable=False)
    vulnerabilities_count = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    audit = relationship("AuditModel", back_populates="sbom_components")


class ScanComparisonModel(Base):
    """Diff and comparison metrics across sequential scans."""
    __tablename__ = "scan_comparisons"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    base_audit_id = Column(String(36), ForeignKey("audits.id", ondelete="CASCADE"), nullable=False, index=True)
    target_audit_id = Column(String(36), ForeignKey("audits.id", ondelete="CASCADE"), nullable=False, index=True)
    new_findings_count = Column(Integer, default=0, nullable=False)
    fixed_findings_count = Column(Integer, default=0, nullable=False)
    recurrent_findings_count = Column(Integer, default=0, nullable=False)
    comparison_json = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


