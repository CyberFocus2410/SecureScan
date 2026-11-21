"""DPDP API endpoints: controls, questionnaire profile, data flows, and penalty references."""
from uuid import UUID
from pathlib import Path
from typing import Any, Dict
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.db import get_db
from app.core.session import get_session_id
from app.models.models import AuditModel, ControlResultModel, DpdpProfileModel
from app.schemas.control import ControlResult, StatutoryRef
from app.schemas.enums import ControlState, EffectiveDateStatus
from app.dpdp.applicability import DpdpQuestionnaire
from app.dpdp.evidence import extract_data_flows_from_worktree, DataFlowItem
from app.services.dpdp_controls import evaluate_dpdp_controls
from app.services.penalties import evaluate_penalty_exposure, LegalExposureResponse
from app.services.policy_loader import get_policy_bundle

router = APIRouter(tags=["DPDP Compliance & Readiness"])


@router.get("/audits/{audit_id}/dpdp/controls", response_model=list[ControlResult])
def get_dpdp_controls(
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
        ControlResultModel.domain == "DPDP"
    ).all()

    # If DPDP controls have not yet been evaluated for this audit, evaluate them now
    if not controls:
        controls = evaluate_dpdp_controls(db, str(audit_id))

    bundle = get_policy_bundle()
    ctrl_meta = {c.id: c for c in bundle.dpdp_controls.controls}

    result = []
    for c in controls:
        meta = ctrl_meta.get(c.control_id)
        statutory_ref = None
        if meta and meta.legal_source:
            statutory_ref = StatutoryRef(
                source_doc=meta.legal_source.get("document", "DPDP Act 2023"),
                clause=meta.legal_source.get("clause", meta.act_section),
                source_url=meta.legal_source.get("url"),
                mandatory_caveat="Potential legal category; applicability and liability not determined."
            )

        eff_status = EffectiveDateStatus(c.effective_date_status) if c.effective_date_status else EffectiveDateStatus.NOT_DETERMINED

        result.append(ControlResult(
            id=UUID(c.id),
            audit_id=UUID(c.audit_id),
            control_id=c.control_id,
            domain="DPDP",
            title=meta.title if meta else c.control_id,
            state=ControlState(c.state),
            readiness_label=c.readiness_label,
            effective_date_status=eff_status,
            effective_date=c.effective_date,
            rationale=c.rationale,
            evidence_tier=c.evidence_tier,
            statutory_ref=statutory_ref
        ))

    return result


@router.post("/audits/{audit_id}/dpdp/profile", status_code=status.HTTP_202_ACCEPTED)
def submit_dpdp_profile(
    audit_id: UUID,
    questionnaire: DpdpQuestionnaire,
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db)
):
    """
    Submits or updates organizational answers to the applicability questionnaire.
    Refreshes DPDP readiness evaluation (202 Accepted).
    """
    audit = db.query(AuditModel).filter(AuditModel.id == str(audit_id)).first()
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")
    if audit.session_id != session_id:
        raise HTTPException(status_code=403, detail="Access forbidden: audit belongs to another session")

    profile_dict = questionnaire.model_dump()

    prof = db.query(DpdpProfileModel).filter(DpdpProfileModel.audit_id == str(audit_id)).first()
    if not prof:
        import uuid
        prof = DpdpProfileModel(
            id=str(uuid.uuid4()),
            audit_id=str(audit_id),
            answers=profile_dict
        )
        db.add(prof)
    else:
        prof.answers = profile_dict

    db.commit()

    # Re-evaluate DPDP controls with updated profile
    evaluate_dpdp_controls(db, str(audit_id), profile_answers=profile_dict)

    return {
        "status": "ACCEPTED",
        "message": "DPDP profile updated and controls reassessed.",
        "audit_id": str(audit_id)
    }


@router.get("/audits/{audit_id}/dpdp/data-flows", response_model=list[DataFlowItem])
def get_dpdp_data_flows(
    audit_id: UUID,
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db)
):
    audit = db.query(AuditModel).filter(AuditModel.id == str(audit_id)).first()
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")
    if audit.session_id != session_id:
        raise HTTPException(status_code=403, detail="Access forbidden: audit belongs to another session")

    # Inspect worktree or fixtures
    target_dir = settings.WORKTREE_STORAGE_DIR / str(audit_id)
    if not target_dir.exists():
        # Fallback to fixture or clean empty list
        fixtures_dir = Path(__file__).resolve().parent.parent.parent.parent / "fixtures" / "vulnerable-python-api"
        target_dir = fixtures_dir if fixtures_dir.exists() else Path(".")

    flows = extract_data_flows_from_worktree(target_dir)
    return flows


@router.get("/audits/{audit_id}/legal-exposure", response_model=LegalExposureResponse)
def get_legal_exposure(
    audit_id: UUID,
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db)
):
    audit = db.query(AuditModel).filter(AuditModel.id == str(audit_id)).first()
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")
    if audit.session_id != session_id:
        raise HTTPException(status_code=403, detail="Access forbidden: audit belongs to another session")

    items = evaluate_penalty_exposure(db, str(audit_id))
    return LegalExposureResponse(items=items)


@router.get("/audits/{audit_id}/dpdp/readiness")
def get_dpdp_readiness(
    audit_id: UUID,
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db)
):
    """Retrieve complete 0-100 DPDP Act 2023 readiness evaluation, controls, and statutory ceilings (Step 10)."""
    from app.dpdp.readiness import DPDPReadinessEngine

    audit = db.query(AuditModel).filter(AuditModel.id == str(audit_id)).first()
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")
    if audit.session_id != session_id:
        raise HTTPException(status_code=403, detail="Access forbidden: audit belongs to another session")

    target_dir = settings.WORKTREE_STORAGE_DIR / str(audit_id)
    if not target_dir.exists():
        fixtures_dir = Path(__file__).resolve().parent.parent.parent.parent / "fixtures" / "dpdp-fixtures" / "identifiers_repo"
        target_dir = fixtures_dir if fixtures_dir.exists() else Path(".")

    profile = db.query(DpdpProfileModel).filter(DpdpProfileModel.audit_id == str(audit_id)).first()
    profile_answers = profile.answers if profile else {}

    report = DPDPReadinessEngine.evaluate_readiness(
        target_dir=target_dir,
        findings=[{"rule_id": f.rule_id, "severity": f.severity, "priority": getattr(f, "priority", "P2")} for f in audit.findings],
        profile_answers=profile_answers
    )
    return report.to_dict()

