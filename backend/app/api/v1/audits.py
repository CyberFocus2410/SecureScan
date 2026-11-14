"""Audit initiation, status, and event streaming endpoints."""
import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, BackgroundTasks, status
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.session import get_session_id
from app.core.errors import (
    RepoNotFoundError,
    AuditNotFoundError,
    UnauthorizedSessionError
)
from app.models.models import AuditModel, RepositoryModel, AuditEventModel
from app.schemas.audit import Audit, AuditCreate, AuditEvent
from app.workers.audit_worker import (
    check_session_quotas_and_dedupe,
    execute_import_pipeline,
    log_audit_event
)

router = APIRouter(prefix="/audits", tags=["Audits"])


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

    # Dispatch async background worker pipeline
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

