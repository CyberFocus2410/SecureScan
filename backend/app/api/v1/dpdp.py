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
    from datetime import date
    from app.dpdp.readiness import DpdpReadinessEngine

    audit = db.query(AuditModel).filter(AuditModel.id == str(audit_id)).first()
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")
    if audit.session_id != session_id:
        raise HTTPException(status_code=403, detail="Access forbidden: audit belongs to another session")

    target_dir = settings.WORKTREE_STORAGE_DIR / str(audit_id)
    worktree = target_dir if target_dir.exists() else None

    profile = db.query(DpdpProfileModel).filter(DpdpProfileModel.audit_id == str(audit_id)).first()
    profile_answers = profile.answers if profile and profile.answers else {}

    sec_findings = [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "priority": getattr(f, "priority", "P2"),
            "file_path": f.file_path,
        }
        for f in (audit.findings or [])
    ]

    report = DpdpReadinessEngine.evaluate(
        worktree_dir=worktree,
        security_findings=sec_findings,
        questionnaire_answers=profile_answers,
        as_of_date=date.today(),
        is_sdf=bool(profile_answers.get("is_significant_data_fiduciary")),
        processes_children=bool(profile_answers.get("processes_children_data")),
    )

    # Format categories dict into a list conforming to DPDPReadinessReport
    categories_list = []
    if isinstance(report.get("categories"), dict):
        for cat_id, cat_info in report["categories"].items():
            total = cat_info.get("total_controls", 0)
            implemented = cat_info.get("verified_or_implemented", 0)
            upcoming = cat_info.get("upcoming", 0)
            partial = cat_info.get("partial", 0)

            if implemented == total and total > 0:
                cat_status = "Implemented"
            elif upcoming == total and total > 0:
                cat_status = "Upcoming"
            elif implemented > 0 or partial > 0:
                cat_status = "In Progress"
            elif upcoming > 0:
                cat_status = "Upcoming"
            else:
                cat_status = "Needs Action"

            categories_list.append({
                "category_id": cat_id,
                "title": cat_info.get("category_title", cat_id),
                "status": cat_status,
                "controls_count": total,
                "implemented_count": implemented,
            })
    elif isinstance(report.get("categories"), list):
        categories_list = report["categories"]

    # Format evaluated_controls list conforming to DPDPReadinessReport
    evaluated_controls = []
    for c in report.get("controls", []):
        cid = c.get("id") or c.get("control_id")
        evaluated_controls.append({
            "control_id": cid,
            "id": cid,
            "title": c.get("title", ""),
            "status": c.get("status", "Not detected"),
            "category": c.get("category_title", c.get("category", "")),
            "effective_date_status": c.get("commencement_status", c.get("effective_date_status", "")),
            "evidence_summary": c.get("evidence_summary", ""),
            "remediation": c.get("remediation", ""),
            "act_section": c.get("act_section", ""),
            "rules_ref": c.get("rules_ref", ""),
            "applies_to": c.get("applies_to", ""),
        })

    return {
        "readiness_score": report.get("readiness_score", 0),
        "raw_score": report.get("raw_score", report.get("readiness_score", 0)),
        "hard_cap_applied": report.get("hard_cap_applied", False),
        "hard_cap_reason": report.get("hard_cap_reason"),
        "as_of_date": report.get("as_of_date", str(date.today())),
        "categories": categories_list,
        "evaluated_controls": evaluated_controls,
        "controls": report.get("controls", []),
        "action_plan": report.get("action_plan", []),
        "statutory_penalties": report.get("statutory_penalties", []),
        "penalty_caveat": report.get("penalty_caveat", ""),
        "scoring_methodology": report.get("scoring_methodology", ""),
        "technical_findings_mapped": report.get("technical_findings_mapped", []),
        "legal_review_pending": report.get("legal_review_pending", []),
        "discovered_pii_count": report.get("discovered_pii_count", 0),
        "discovered_processors_count": report.get("discovered_processors_count", 0),
    }


