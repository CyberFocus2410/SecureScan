"""Security API routes: controls evaluation, coverage ratio, and remediations."""
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Header, status
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.session import get_session_id
from app.models.models import AuditModel, ControlResultModel, RemediationActionModel
from app.schemas.control import ControlResult, SecurityCoverageResponse, SecurityCoverageSummary
from app.schemas.remediation import RemediationAction
from app.schemas.enums import ControlState
from app.services.policy_loader import get_policy_bundle
from app.services.security_controls import calculate_security_coverage

router = APIRouter(tags=["Security Controls"])


@router.get("/audits/{audit_id}/security/controls", response_model=list[ControlResult])
def get_security_controls(
    audit_id: UUID,
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db)
):
    audit = db.query(AuditModel).filter(AuditModel.id == str(audit_id)).first()
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")
    if audit.session_id != session_id:
        raise HTTPException(status_code=403, detail="Access forbidden: audit belongs to another session")

    controls = db.query(ControlResultModel).filter(
        ControlResultModel.audit_id == str(audit_id),
        ControlResultModel.domain == "SECURITY"
    ).all()

    bundle = get_policy_bundle()
    ctrl_meta = {c.id: c.title for c in bundle.security_controls.controls}

    result = []
    for c in controls:
        result.append(ControlResult(
            id=UUID(c.id),
            audit_id=UUID(c.audit_id),
            control_id=c.control_id,
            domain="SECURITY",
            title=ctrl_meta.get(c.control_id, c.control_id),
            state=ControlState(c.state),
            rationale=c.rationale,
            evidence_tier=c.evidence_tier
        ))
    return result


@router.get("/audits/{audit_id}/security/coverage", response_model=SecurityCoverageResponse)
def get_security_coverage(
    audit_id: UUID,
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db)
):
    audit = db.query(AuditModel).filter(AuditModel.id == str(audit_id)).first()
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")
    if audit.session_id != session_id:
        raise HTTPException(status_code=403, detail="Access forbidden: audit belongs to another session")

    control_models = db.query(ControlResultModel).filter(
        ControlResultModel.audit_id == str(audit_id),
        ControlResultModel.domain == "SECURITY"
    ).all()

    summary_data = calculate_security_coverage(control_models)
    bundle = get_policy_bundle()
    ctrl_meta = {c.id: c.title for c in bundle.security_controls.controls}

    controls = [
        ControlResult(
            id=UUID(c.id),
            audit_id=UUID(c.audit_id),
            control_id=c.control_id,
            domain="SECURITY",
            title=ctrl_meta.get(c.control_id, c.control_id),
            state=ControlState(c.state),
            rationale=c.rationale,
            evidence_tier=c.evidence_tier
        )
        for c in control_models
    ]

    summary = SecurityCoverageSummary(
        total_controls=summary_data.total_controls,
        evidenced_pass=summary_data.pass_evidenced_count,
        evidenced_fail=summary_data.fail_evidenced_count,
        potential_gap=summary_data.potential_gap_count,
        not_verified=summary_data.not_verified_count,
        not_applicable=summary_data.not_applicable_count,
        error=summary_data.error_count,
        applicable_controls=summary_data.applicable_controls,
        evidenced_controls=summary_data.evidenced_controls,
        coverage_ratio=summary_data.coverage_ratio,
        denominator=summary_data.applicable_controls
    )

    return SecurityCoverageResponse(summary=summary, controls=controls)


@router.get("/audits/{audit_id}/remediations", response_model=list[RemediationAction])
def get_remediations(
    audit_id: UUID,
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db)
):
    audit = db.query(AuditModel).filter(AuditModel.id == str(audit_id)).first()
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")
    if audit.session_id != session_id:
        raise HTTPException(status_code=403, detail="Access forbidden: audit belongs to another session")

    remediations = db.query(RemediationActionModel).filter(
        RemediationActionModel.audit_id == str(audit_id)
    ).all()

    return [
        RemediationAction(
            id=UUID(r.id),
            audit_id=UUID(r.audit_id),
            priority=r.priority,
            action_type=r.action_type,
            target_id=r.target_id,
            title=r.title,
            steps=r.steps or [],
            validation_method=r.validation_method
        )
        for r in remediations
    ]
