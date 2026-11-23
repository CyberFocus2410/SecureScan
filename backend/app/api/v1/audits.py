"""Audit initiation, status, and event streaming endpoints."""
import uuid
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, BackgroundTasks, Query, status
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.session import get_session_id
from app.core.config import settings
from app.core.errors import (
    RepoNotFoundError,
    AuditNotFoundError,
    UnauthorizedSessionError
)
from app.models.models import AuditModel, RepositoryModel, AuditEventModel, FindingModel
from app.schemas.audit import Audit, AuditCreate, AuditEvent
from app.workers.audit_worker import (
    check_session_quotas_and_dedupe,
    execute_import_pipeline,
    log_audit_event
)
from app.services.risk_intelligence import RiskIntelligenceEngine
from app.services.attack_chains import AttackChainCorrelator
from app.services.attack_surface import AttackSurfaceGenerator


router = APIRouter(prefix="/audits", tags=["Audits"])


@router.get("")
def list_session_audits(
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db)
):
    """List all audits belonging to the active session."""
    audits = db.query(AuditModel).filter(
        AuditModel.session_id == session_id
    ).order_by(AuditModel.created_at.desc()).all()

    res = []
    for a in audits:
        repo = db.query(RepositoryModel).filter(RepositoryModel.id == a.repository_id).first()
        res.append({
            "id": a.id,
            "repository_id": a.repository_id,
            "target_url": repo.canonical_url if repo else (repo.github_repo if repo else "Target"),
            "commit_sha": a.commit_sha,
            "scopes": a.scopes,
            "status": a.status,
            "current_stage": a.current_stage,
            "findings_count": len(a.findings),
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "completed_at": a.completed_at.isoformat() if a.completed_at else None,
        })
    return res


@router.post("", status_code=status.HTTP_202_ACCEPTED)
def start_audit(
    payload: AuditCreate,
    background_tasks: BackgroundTasks,
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db)
):
    """
    Queue a new audit for the specified repository (FR-AUD-01, D-11).
    Enforces per-session quotas and deduplication.
    """
    repo = db.query(RepositoryModel).filter(
        RepositoryModel.id == str(payload.repository_id)
    ).first()

    if not repo:
        raise RepoNotFoundError(f"Repository ID '{payload.repository_id}' does not exist.")

    # Enforce concurrency and deduplication quotas
    check_session_quotas_and_dedupe(
        db=db,
        session_id=session_id,
        repository_id=str(repo.id),
        commit_sha=payload.commit_sha
    )

    audit_id = str(uuid.uuid4())
    scopes = [s.value for s in payload.scopes]

    new_audit = AuditModel(
        id=audit_id,
        repository_id=repo.id,
        session_id=session_id,
        target_id=payload.target_id,
        commit_sha=payload.commit_sha,
        scopes=scopes,
        status="QUEUED",
        current_stage="QUEUED",
        coverage_json={},
        created_at=datetime.utcnow()
    )
    db.add(new_audit)
    db.commit()
    db.refresh(new_audit)

    log_audit_event(
        db,
        audit_id=audit_id,
        stage="QUEUED",
        state="IN_PROGRESS",
        message="Audit submitted and queued for ingestion."
    )

    # Dispatch async background worker pipeline (RQ if available, else BackgroundTasks)
    dispatched_to_rq = False
    if getattr(settings, "REDIS_URL", None):
        try:
            import redis
            from rq import Queue
            r = redis.from_url(settings.REDIS_URL, socket_connect_timeout=0.5)
            r.ping()
            q = Queue(settings.RQ_QUEUE_NAME, connection=r)
            q.enqueue(execute_import_pipeline, audit_id)
            dispatched_to_rq = True
        except Exception:
            dispatched_to_rq = False

    if not dispatched_to_rq:
        background_tasks.add_task(execute_import_pipeline, audit_id)

    return {
        "audit_id": audit_id,
        "status": "QUEUED",
        "created_at": new_audit.created_at.isoformat(),
        "poll_url": f"/api/v1/audits/{audit_id}"
    }


@router.get("/{audit_id}", response_model=Audit)
def get_audit(
    audit_id: str,
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db)
):
    """
    Retrieve audit lifecycle status and coverage summary (FR-ACC-01).
    Session-scoped: returns 403 on session mismatch.
    """
    audit = db.query(AuditModel).filter(AuditModel.id == audit_id).first()
    if not audit:
        raise AuditNotFoundError(f"Audit with ID '{audit_id}' not found.")

    if audit.session_id != session_id:
        raise UnauthorizedSessionError("Audit belongs to another session. Access denied.")

    return audit


@router.get("/{audit_id}/events", response_model=list[AuditEvent])
def get_audit_events(
    audit_id: str,
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db)
):
    """
    Retrieve ordered pipeline execution event stream for audit.
    Session-scoped: returns 403 on session mismatch.
    """
    audit = db.query(AuditModel).filter(AuditModel.id == audit_id).first()
    if not audit:
        raise AuditNotFoundError(f"Audit with ID '{audit_id}' not found.")

    if audit.session_id != session_id:
        raise UnauthorizedSessionError("Audit belongs to another session. Access denied.")

    events = db.query(AuditEventModel).filter(
        AuditEventModel.audit_id == audit_id
    ).order_by(AuditEventModel.timestamp.asc()).all()

    return events


@router.post("/{audit_id}/cancel")
def cancel_audit(
    audit_id: str,
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db)
):
    """Emergency kill-switch to cancel an active audit run."""
    audit = db.query(AuditModel).filter(AuditModel.id == audit_id).first()
    if not audit:
        raise AuditNotFoundError(f"Audit with ID '{audit_id}' not found.")

    if audit.session_id != session_id:
        raise UnauthorizedSessionError("Audit belongs to another session. Access denied.")

    if audit.status not in ("COMPLETED", "FAILED", "PARTIAL"):
        audit.status = "FAILED"
        audit.current_stage = "CANCELLED"
        db.commit()
        log_audit_event(
            db,
            audit_id=audit_id,
            stage="CANCELLED",
            state="FAILED",
            message="Audit pipeline aborted by user kill-switch."
        )

    return {"audit_id": audit_id, "status": audit.status, "message": "Audit cancelled."}


@router.get("/{audit_id}/risk-intelligence")
def get_audit_risk_intelligence(
    audit_id: str,
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db)
):
    """Retrieve multi-dimensional risk scores (Security, Privacy, Infra, Supply Chain, DPDP) and compound attack chains."""
    audit = db.query(AuditModel).filter(AuditModel.id == audit_id).first()
    if not audit:
        raise AuditNotFoundError(f"Audit with ID '{audit_id}' not found.")

    if audit.session_id != session_id:
        raise UnauthorizedSessionError("Audit belongs to another session. Access denied.")

    findings_raw = [
        {
            "id": f.id,
            "rule_id": f.rule_id,
            "title": f.title,
            "description": f.description,
            "severity": f.severity,
            "priority": getattr(f, "priority", None) or ("P0" if f.severity == "CRITICAL" else "P1" if f.severity == "HIGH" else "P2"),
            "confidence": f.confidence,
            "category": f.category,
            "scanner_name": f.scanner_name,
            "engine": f.scanner_name,
            "file_path": f.file_path,
            "start_line": f.start_line,
            "verified_state": getattr(f, "verified_state", None) or "UNVERIFIED"
        }
        for f in audit.findings
    ]

    report = RiskIntelligenceEngine.evaluate(findings_raw)
    chains = AttackChainCorrelator.correlate(findings_raw)
    surface = AttackSurfaceGenerator.generate(
        findings=findings_raw,
        repo_name=audit.repository.github_repo if audit.repository else None
    )

    return {
        "audit_id": audit_id,
        "priority_counts": report.priority_counts,
        "severity_counts": report.severity_counts,
        "scores": {
            "security_score": report.scores.security_score,
            "privacy_score": report.scores.privacy_score,
            "infrastructure_score": report.scores.infrastructure_score,
            "supply_chain_score": report.scores.supply_chain_score,
            "dpdp_readiness_score": report.scores.dpdp_readiness_score,
            "overall_rating": report.scores.overall_rating,
            "hard_cap_applied": report.scores.hard_cap_applied,
            "hard_cap_reasons": report.scores.hard_cap_reasons,
            "methodology": report.scores.methodology,
        },
        "attack_chains": [c.to_dict() for c in chains],
        "attack_surface": surface,
        "findings_count": report.findings_count,
        "confirmed_exploitable_count": report.confirmed_exploitable_count
    }


@router.get("/{audit_id}/attack-surface")
def get_attack_surface(
    audit_id: str,
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db)
):
    """Retrieve visual attack surface topology map (nodes and edges) for the audit."""
    audit = db.query(AuditModel).filter(AuditModel.id == audit_id).first()
    if not audit:
        raise AuditNotFoundError(f"Audit with ID '{audit_id}' does not exist.")
    if audit.session_id != session_id:
        raise AuditForbiddenError("Access forbidden: audit belongs to another session.")

    findings_raw = [
        {
            "id": f.id,
            "rule_id": f.rule_id,
            "title": f.title,
            "description": f.description,
            "severity": f.severity,
            "priority": getattr(f, "priority", "P2"),
            "category": f.category,
            "file_path": f.file_path,
        }
        for f in audit.findings
    ]
    return AttackSurfaceGenerator.generate(
        findings=findings_raw,
        repo_name=audit.repository.github_repo if audit.repository else None
    )



@router.get("/{audit_id}/compare")
def compare_audits(
    audit_id: str,
    base_audit_id: str = Query(..., description="ID of baseline audit to compare against"),
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db)
):
    """Compare two audit runs: identify new, fixed, unchanged, and regressed vulnerabilities."""
    curr_audit = db.query(AuditModel).filter(AuditModel.id == audit_id).first()
    if not curr_audit:
        raise AuditNotFoundError(f"Target audit '{audit_id}' not found.")
    if curr_audit.session_id != session_id:
        raise UnauthorizedSessionError("Target audit belongs to another session.")

    base_audit = db.query(AuditModel).filter(AuditModel.id == base_audit_id).first()
    if not base_audit:
        raise AuditNotFoundError(f"Base audit '{base_audit_id}' not found.")
    if base_audit.session_id != session_id:
        raise UnauthorizedSessionError("Base audit belongs to another session.")

    base_findings = db.query(FindingModel).filter(FindingModel.audit_id == base_audit_id).all()
    curr_findings = db.query(FindingModel).filter(FindingModel.audit_id == audit_id).all()

    base_fps = {f.fingerprint: f for f in base_findings}
    curr_fps = {f.fingerprint: f for f in curr_findings}

    fixed_findings = []
    new_findings = []
    unchanged_findings = []
    regressed_findings = []

    for fp, bf in base_fps.items():
        if fp not in curr_fps:
            fixed_findings.append({
                "id": bf.id,
                "rule_id": bf.rule_id,
                "title": bf.title,
                "severity": bf.severity,
                "priority": getattr(bf, "priority", None) or "P2",
                "file_path": bf.file_path,
            })
        else:
            cf = curr_fps[fp]
            if getattr(cf, "status", "open") == "regressed":
                regressed_findings.append({
                    "id": cf.id,
                    "rule_id": cf.rule_id,
                    "title": cf.title,
                    "severity": cf.severity,
                    "priority": getattr(cf, "priority", None) or "P2",
                    "file_path": cf.file_path,
                })
            else:
                unchanged_findings.append({
                    "id": cf.id,
                    "rule_id": cf.rule_id,
                    "title": cf.title,
                    "severity": cf.severity,
                    "priority": getattr(cf, "priority", None) or "P2",
                    "file_path": cf.file_path,
                })

    for fp, cf in curr_fps.items():
        if fp not in base_fps:
            new_findings.append({
                "id": cf.id,
                "rule_id": cf.rule_id,
                "title": cf.title,
                "severity": cf.severity,
                "priority": getattr(cf, "priority", None) or "P2",
                "file_path": cf.file_path,
            })

    # Scores comparison
    base_raw = [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "priority": getattr(f, "priority", "P2"),
            "category": f.category,
            "scanner_name": f.scanner_name,
            "file_path": f.file_path,
        }
        for f in base_findings
    ]
    curr_raw = [
        {
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "priority": getattr(f, "priority", "P2"),
            "category": f.category,
            "scanner_name": f.scanner_name,
            "file_path": f.file_path,
        }
        for f in curr_findings
    ]
    base_report = RiskIntelligenceEngine.evaluate(base_raw)
    curr_report = RiskIntelligenceEngine.evaluate(curr_raw)

    return {
        "current_audit_id": audit_id,
        "base_audit_id": base_audit_id,
        "summary": {
            "fixed_count": len(fixed_findings),
            "new_count": len(new_findings),
            "unchanged_count": len(unchanged_findings),
            "regressed_count": len(regressed_findings),
            "score_deltas": {
                "security_score_delta": curr_report.scores.security_score - base_report.scores.security_score,
                "privacy_score_delta": curr_report.scores.privacy_score - base_report.scores.privacy_score,
                "infrastructure_score_delta": curr_report.scores.infrastructure_score - base_report.scores.infrastructure_score,
                "supply_chain_score_delta": curr_report.scores.supply_chain_score - base_report.scores.supply_chain_score,
            }
        },
        "fixed_findings": fixed_findings,
        "new_findings": new_findings,
        "unchanged_findings": unchanged_findings,
        "regressed_findings": regressed_findings,
        "base_scores": {
            "security_score": base_report.scores.security_score,
            "overall_rating": base_report.scores.overall_rating
        },
        "current_scores": {
            "security_score": curr_report.scores.security_score,
            "overall_rating": curr_report.scores.overall_rating
        }
    }

