"""Findings and Scanner Run query endpoints (FR-SCN, FR-SEC)."""
from typing import Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.session import get_session_id
from app.core.errors import (
    AuditNotFoundError,
    UnauthorizedSessionError,
    SecureScanException,
    ErrorCode
)
from app.models.models import AuditModel, FindingModel, ScannerRunModel, EvidenceModel
from app.schemas.finding import Finding, FindingListResponse, FindingRemediation, FindingStatusUpdate
from app.schemas.scanner_run import ScannerRun
from app.schemas.evidence import Evidence
from app.schemas.enums import Severity, Confidence, ScannerName, EvidenceTier
from app.schemas.ai import AIExplainRequest, AIExplanation
from app.services.ai_explain import explain_finding

router = APIRouter(tags=["Findings & Scanners"])


def _model_to_finding(f: FindingModel, ev_schema: Optional[Evidence], rem_schema: Optional[FindingRemediation]) -> Finding:
    try:
        scanner_enum = ScannerName(f.scanner_name)
    except Exception:
        scanner_enum = ScannerName.SEMGREP

    try:
        sev_enum = Severity(f.severity)
    except Exception:
        sev_enum = Severity.MEDIUM

    try:
        conf_enum = Confidence(f.confidence)
    except Exception:
        conf_enum = Confidence.CONFIRMED

    return Finding(
        id=f.id,
        audit_id=f.audit_id,
        fingerprint=f.fingerprint,
        scanner_name=scanner_enum,
        scanner_version=f.scanner_version or "1.0.0",
        rule_id=f.rule_id,
        title=f.title,
        description=f.description,
        category=f.category,
        severity=sev_enum,
        confidence=conf_enum,
        file_path=f.file_path,
        start_line=f.start_line,
        end_line=f.end_line,
        cwe_ids=f.cwe_ids or [],
        owasp_refs=f.owasp_refs or [],
        evidence=ev_schema,
        remediation=rem_schema,
        redacted_snippet=f.redacted_snippet,
        engine=getattr(f, "engine", None),
        tool=getattr(f, "tool", None),
        tool_version=getattr(f, "tool_version", None),
        verified_state=getattr(f, "verified_state", None),
        exploitability=getattr(f, "exploitability", None),
        exposure=getattr(f, "exposure", None),
        data_sensitivity=getattr(f, "data_sensitivity", None),
        source=getattr(f, "source", None),
        data_flow=getattr(f, "data_flow", None),
        sink=getattr(f, "sink", None),
        affected=getattr(f, "affected", None),
        request_evidence=getattr(f, "request_evidence", None),
        response_evidence=getattr(f, "response_evidence", None),
        standards=getattr(f, "standards", None),
        priority=getattr(f, "priority", None),
        plain_title=getattr(f, "plain_title", None),
        plain_summary=getattr(f, "plain_summary", None),
        why_it_matters=getattr(f, "why_it_matters", None),
        how_to_fix=getattr(f, "how_to_fix", None),
        how_to_verify_fix=getattr(f, "how_to_verify_fix", None),
        fix_effort=getattr(f, "fix_effort", None),
        fix_prompt=getattr(f, "fix_prompt", None),
        related_finding_ids=getattr(f, "related_finding_ids", None),
        attack_chain_id=getattr(f, "attack_chain_id", None),
        first_seen_scan_id=getattr(f, "first_seen_scan_id", None),
        status=getattr(f, "status", "open"),
        status_reason=getattr(f, "status_reason", None),
        status_expires_at=getattr(f, "status_expires_at", None),
        status_updated_at=getattr(f, "status_updated_at", None),
        signals=getattr(f, "signals", None)
    )


@router.get("/audits/{audit_id}/scanner-runs", response_model=list[ScannerRun])
def get_audit_scanner_runs(
    audit_id: str,
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db)
):
    """Retrieve scanner execution logs and tool versions for an audit."""
    audit = db.query(AuditModel).filter(AuditModel.id == audit_id).first()
    if not audit:
        raise AuditNotFoundError(f"Audit '{audit_id}' not found.")

    if audit.session_id != session_id:
        raise UnauthorizedSessionError("Unauthorized session access.")

    runs = db.query(ScannerRunModel).filter(
        ScannerRunModel.audit_id == audit_id
    ).order_by(ScannerRunModel.created_at.asc()).all()

    return runs


@router.get("/audits/{audit_id}/security/findings", response_model=FindingListResponse)
def get_audit_findings(
    audit_id: str,
    severity: Optional[Severity] = Query(None),
    category: Optional[str] = Query(None),
    scanner: Optional[ScannerName] = Query(None),
    file_path: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db)
):
    """
    Retrieve normalized findings for an audit with filtering and pagination.
    Secrets are guaranteed redacted in the output.
    """
    audit = db.query(AuditModel).filter(AuditModel.id == audit_id).first()
    if not audit:
        raise AuditNotFoundError(f"Audit '{audit_id}' not found.")

    if audit.session_id != session_id:
        raise UnauthorizedSessionError("Unauthorized session access.")

    query = db.query(FindingModel).filter(FindingModel.audit_id == audit_id)

    if severity:
        query = query.filter(FindingModel.severity == severity.value)
    if category:
        query = query.filter(FindingModel.category == category)
    if scanner:
        query = query.filter(FindingModel.scanner_name == scanner.value)
    if file_path:
        query = query.filter(FindingModel.file_path.contains(file_path))

    total = query.count()
    offset = (page - 1) * page_size
    items_raw = query.order_by(FindingModel.start_line.asc()).offset(offset).limit(page_size).all()

    items = []
    for f in items_raw:
        # Load evidence if exists
        ev_model = db.query(EvidenceModel).filter(EvidenceModel.finding_id == f.id).first()
        ev_schema = None
        if ev_model:
            ev_schema = Evidence(
                id=ev_model.id,
                audit_id=ev_model.audit_id,
                finding_id=ev_model.finding_id,
                tier=EvidenceTier(ev_model.tier),
                path=ev_model.path,
                start_line=ev_model.start_line,
                end_line=ev_model.end_line,
                redacted_excerpt=ev_model.redacted_excerpt,
                raw_data=ev_model.raw_data or {},
                provenance=ev_model.provenance
            )

        rem_schema = None
        if f.technical_fix or f.validation_steps:
            rem_schema = FindingRemediation(
                technical_fix=f.technical_fix or "",
                validation_steps=f.validation_steps or ""
            )

        items.append(_model_to_finding(f, ev_schema, rem_schema))

    return FindingListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size
    )


@router.get("/findings/{finding_id}", response_model=Finding)
def get_finding_detail(
    finding_id: str,
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db)
):
    """Retrieve complete finding details with evidence and remediation steps."""
    finding = db.query(FindingModel).filter(FindingModel.id == finding_id).first()
    if not finding:
        raise SecureScanException(
            code=ErrorCode.ERR_AUDIT_NOT_FOUND,
            message=f"Finding '{finding_id}' not found.",
            status_code=status.HTTP_404_NOT_FOUND
        )

    # Verify audit session ownership
    audit = db.query(AuditModel).filter(AuditModel.id == finding.audit_id).first()
    if not audit or audit.session_id != session_id:
        raise UnauthorizedSessionError("Unauthorized session access.")

    ev_model = db.query(EvidenceModel).filter(EvidenceModel.finding_id == finding.id).first()
    ev_schema = None
    if ev_model:
        ev_schema = Evidence(
            id=ev_model.id,
            audit_id=ev_model.audit_id,
            finding_id=ev_model.finding_id,
            tier=EvidenceTier(ev_model.tier),
            path=ev_model.path,
            start_line=ev_model.start_line,
            end_line=ev_model.end_line,
            redacted_excerpt=ev_model.redacted_excerpt,
            raw_data=ev_model.raw_data or {},
            provenance=ev_model.provenance
        )

    rem_schema = FindingRemediation(
        technical_fix=finding.technical_fix or "",
        validation_steps=finding.validation_steps or ""
    ) if finding.technical_fix else None

    return _model_to_finding(finding, ev_schema, rem_schema)


@router.post("/findings/{finding_id}/explain", response_model=AIExplanation)
def request_finding_explanation(
    finding_id: str,
    payload: AIExplainRequest = AIExplainRequest(),
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db)
):
    """
    Generate an AI-assisted explanation for a finding.
    Enforces untrusted-source isolation, schema validation, and deterministic fallback.
    """
    finding = db.query(FindingModel).filter(FindingModel.id == finding_id).first()
    if not finding:
        raise SecureScanException(
            code=ErrorCode.ERR_AUDIT_NOT_FOUND,
            message=f"Finding '{finding_id}' not found.",
            status_code=status.HTTP_404_NOT_FOUND
        )

    # Verify audit session ownership
    audit = db.query(AuditModel).filter(AuditModel.id == finding.audit_id).first()
    if not audit or audit.session_id != session_id:
        raise UnauthorizedSessionError("Unauthorized session access.")

    explanation = explain_finding(
        finding_id=finding_id,
        include_risk_context=payload.include_risk_context,
        db=db
    )
    return explanation


@router.post("/findings/{finding_id}/create-pr")
def create_finding_fix_pr(
    finding_id: str,
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db)
):
    """Generate a clean remediation branch and draft PR for this finding (Step 12, ADR-002)."""
    from app.services.github_pr import GitHubPrService
    from app.services.fix_pack import FixPackGenerator
    from app.models.models import RepositoryModel

    finding = db.query(FindingModel).filter(FindingModel.id == finding_id).first()
    if not finding:
        raise SecureScanException(
            code=ErrorCode.ERR_AUDIT_NOT_FOUND,
            message=f"Finding '{finding_id}' not found.",
            status_code=status.HTTP_404_NOT_FOUND
        )

    audit = db.query(AuditModel).filter(AuditModel.id == finding.audit_id).first()
    if not audit or audit.session_id != session_id:
        raise UnauthorizedSessionError("Unauthorized session access.")

    repo = db.query(RepositoryModel).filter(RepositoryModel.id == audit.repository_id).first()
    repo_owner = repo.github_owner if repo else "repo-owner"
    repo_name = repo.github_repo if repo else "repo-name"

    patch = FixPackGenerator.generate_patch(
        finding_id=finding.id,
        rule_id=finding.rule_id,
        file_path=finding.file_path,
        start_line=finding.start_line
    )

    result = GitHubPrService.create_fix_pr(
        repo_owner=repo_owner,
        repo_name=repo_name,
        finding_id=finding.id,
        patch_content=patch.diff,
        commit_message=f"fix(securescan): remediate {finding.rule_id} at {finding.file_path}"
    )

    return result.to_dict()


@router.patch("/findings/{finding_id}/status", response_model=Finding)
def update_finding_status(
    finding_id: str,
    payload: FindingStatusUpdate,
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db)
):
    """Update finding lifecycle state: open, fixed, accepted-risk, false-positive (Step 15)."""
    finding = db.query(FindingModel).filter(FindingModel.id == finding_id).first()
    if not finding:
        raise SecureScanException(
            code=ErrorCode.ERR_AUDIT_NOT_FOUND,
            message=f"Finding '{finding_id}' not found.",
            status_code=status.HTTP_404_NOT_FOUND
        )

    audit = db.query(AuditModel).filter(AuditModel.id == finding.audit_id).first()
    if not audit or audit.session_id != session_id:
        raise UnauthorizedSessionError("Unauthorized session access.")

    valid_statuses = {"open", "fixed", "accepted-risk", "false-positive"}
    if payload.status not in valid_statuses:
        raise SecureScanException(
            code=ErrorCode.ERR_VALIDATION_ERROR,
            message=f"Invalid status '{payload.status}'. Must be one of: {sorted(list(valid_statuses))}",
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY
        )

    if payload.status in {"accepted-risk", "false-positive"}:
        if not payload.reason or len(payload.reason.strip()) < 5:
            raise SecureScanException(
                code=ErrorCode.ERR_VALIDATION_ERROR,
                message=f"Status '{payload.status}' requires a justification reason of at least 5 characters.",
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY
            )

    expires_at_dt = None
    if payload.expires_at:
        try:
            expires_at_dt = datetime.fromisoformat(payload.expires_at.replace("Z", "+00:00"))
        except Exception:
            raise SecureScanException(
                code=ErrorCode.ERR_VALIDATION_ERROR,
                message=f"Invalid expires_at format '{payload.expires_at}'. Must be ISO-8601.",
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY
            )

    finding.status = payload.status
    finding.status_reason = payload.reason.strip() if payload.reason else None
    finding.status_expires_at = expires_at_dt
    finding.status_updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(finding)

    # Reconstruct evidence/remediation schemas for response
    ev = db.query(EvidenceModel).filter(EvidenceModel.finding_id == finding.id).first()
    ev_schema = Evidence.model_validate(ev) if ev else None
    rem_schema = None
    if getattr(finding, "technical_fix", None) or getattr(finding, "validation_steps", None):
        rem_schema = FindingRemediation(
            technical_fix=getattr(finding, "technical_fix", "") or "",
            validation_steps=getattr(finding, "validation_steps", "") or ""
        )

    return _model_to_finding(finding, ev_schema, rem_schema)


