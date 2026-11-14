"""Findings and Scanner Run query endpoints (FR-SCN, FR-SEC)."""
from typing import Optional
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
from app.schemas.finding import Finding, FindingListResponse, FindingRemediation
from app.schemas.scanner_run import ScannerRun
from app.schemas.evidence import Evidence
from app.schemas.enums import Severity, Confidence, ScannerName, EvidenceTier
from app.schemas.ai import AIExplainRequest, AIExplanation
from app.services.ai_explain import explain_finding

router = APIRouter(tags=["Findings & Scanners"])


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

        items.append(Finding(
            id=f.id,
            audit_id=f.audit_id,
            fingerprint=f.fingerprint,
            scanner_name=ScannerName(f.scanner_name),
            scanner_version=f.scanner_version,
            rule_id=f.rule_id,
            title=f.title,
            description=f.description,
            category=f.category,
            severity=Severity(f.severity),
            confidence=Confidence(f.confidence),
            file_path=f.file_path,
            start_line=f.start_line,
            end_line=f.end_line,
            cwe_ids=f.cwe_ids or [],
            owasp_refs=f.owasp_refs or [],
            evidence=ev_schema,
            remediation=rem_schema,
            redacted_snippet=f.redacted_snippet
        ))

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

    return Finding(
        id=finding.id,
        audit_id=finding.audit_id,
        fingerprint=finding.fingerprint,
        scanner_name=ScannerName(finding.scanner_name),
        scanner_version=finding.scanner_version,
        rule_id=finding.rule_id,
        title=finding.title,
        description=finding.description,
        category=finding.category,
        severity=Severity(finding.severity),
        confidence=Confidence(finding.confidence),
        file_path=finding.file_path,
        start_line=finding.start_line,
        end_line=finding.end_line,
        cwe_ids=finding.cwe_ids or [],
        owasp_refs=finding.owasp_refs or [],
        evidence=ev_schema,
        remediation=FindingRemediation(
            technical_fix=finding.technical_fix or "",
            validation_steps=finding.validation_steps or ""
        ) if finding.technical_fix else None,
        redacted_snippet=finding.redacted_snippet
    )


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


