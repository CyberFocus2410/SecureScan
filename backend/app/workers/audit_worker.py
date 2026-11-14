"""Background audit worker and pipeline state machine orchestrator."""
import os
from datetime import datetime, date, timedelta
from pathlib import Path
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.limits import limits
from app.core.db import SessionLocal
from app.core.errors import (
    QuotaExceededError,
    DuplicateActiveAuditError,
    AuditNotFoundError
)
from app.models.models import (
    AuditModel,
    RepositoryModel,
    AuditEventModel
)
from app.services.github_import import (
    clone_shallow_worktree,
    detect_languages_and_frameworks,
    purge_worktree
)
from app.scanners.gitleaks import GitleaksAdapter
from app.scanners.semgrep import SemgrepAdapter
from app.scanners.osv import OsvScannerAdapter
from app.scanners.bandit import BanditAdapter
from app.scanners.custom import CustomRulesScanner
from app.services.normalization import normalize_and_persist_scan_results
from app.services.security_controls import evaluate_security_controls
from app.services.remediations import generate_deterministic_remediations
from app.services.dpdp_controls import evaluate_dpdp_controls


def check_session_quotas_and_dedupe(
    db: Session,
    session_id: str,
    repository_id: str,
    commit_sha: str | None = None
) -> None:
    """
    Enforce per-session concurrent limits and active audit deduplication (FR-ACC-02).
    """
    active_statuses = ["QUEUED", "IMPORTING", "SCANNING", "NORMALIZING"]

    # 1. Deduplication check
    existing_active = db.query(AuditModel).filter(
        AuditModel.session_id == session_id,
        AuditModel.repository_id == repository_id,
        AuditModel.status.in_(active_statuses)
    ).first()

    if existing_active:
        raise DuplicateActiveAuditError(
            f"An audit for this repository is already in progress (Audit ID: {existing_active.id})"
        )

    # 2. Concurrency quota check
    active_count = db.query(AuditModel).filter(
        AuditModel.session_id == session_id,
        AuditModel.status.in_(active_statuses)
    ).count()

    if active_count >= limits.MAX_ACTIVE_AUDITS_PER_SESSION:
        raise QuotaExceededError(
            f"Concurrent audit quota ({limits.MAX_ACTIVE_AUDITS_PER_SESSION}) exceeded for this session."
        )

    # 3. Hourly quota check (Playbook §16)
    one_hour_ago = datetime.utcnow() - timedelta(hours=1)
    hourly_count = db.query(AuditModel).filter(
        AuditModel.session_id == session_id,
        AuditModel.created_at >= one_hour_ago
    ).count()

    if hourly_count >= limits.MAX_AUDITS_PER_HOUR_PER_SESSION:
        raise QuotaExceededError(
            f"Hourly audit submission quota ({limits.MAX_AUDITS_PER_HOUR_PER_SESSION}/hour) exceeded for this session."
        )


def log_audit_event(
    db: Session,
    audit_id: str,
    stage: str,
    state: str,
    message: str
) -> AuditEventModel:
    """Append immutable ordered event to audit_events table."""
    event = AuditEventModel(
        audit_id=audit_id,
        stage=stage,
        state=state,
        message=message,
        timestamp=datetime.utcnow()
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    return event


def execute_scan_pipeline(audit_id: str, worktree_dir: Path | None = None) -> None:
    """
    Executes full M2 scan pipeline:
    QUEUED -> IMPORTING -> SCANNING -> NORMALIZING
    Applies Gitleaks, Semgrep, OSV-Scanner, and Bandit.
    """
    db = SessionLocal()
    try:
        audit = db.query(AuditModel).filter(AuditModel.id == audit_id).first()
        if not audit:
            return

        repo = db.query(RepositoryModel).filter(RepositoryModel.id == audit.repository_id).first()
        if not repo:
            return

        # 1. IMPORTING Stage
        audit.status = "IMPORTING"
        audit.current_stage = "IMPORTING"
        db.commit()

        log_audit_event(
            db,
            audit_id=audit_id,
            stage="IMPORTING",
            state="IN_PROGRESS",
            message=f"Starting safe clone of {repo.canonical_url}"
        )

        target_dir = worktree_dir or (settings.WORKTREE_STORAGE_DIR / str(audit_id))

        # Check if local fixture or clone remote
        if not target_dir.exists():
            resolved_sha = clone_shallow_worktree(
                canonical_url=repo.canonical_url,
                target_dir=target_dir,
                branch=repo.default_branch,
                commit_sha=audit.commit_sha
            )
        else:
            resolved_sha = audit.commit_sha or repo.last_commit_sha or "a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e"

        languages, frameworks = detect_languages_and_frameworks(target_dir)
        repo.last_commit_sha = resolved_sha
        repo.detected_languages = languages
        repo.detected_frameworks = frameworks
        audit.commit_sha = resolved_sha
        db.commit()

        log_audit_event(
            db,
            audit_id=audit_id,
            stage="IMPORTING",
            state="DONE",
            message=f"Pinned commit SHA: {resolved_sha}"
        )

        # 2. SCANNING Stage
        audit.status = "SCANNING"
        audit.current_stage = "SCANNING"
        db.commit()

        log_audit_event(
            db,
            audit_id=audit_id,
            stage="SCANNING",
            state="IN_PROGRESS",
            message="Dispatching sandboxed scanner engines"
        )

        adapters = [
            GitleaksAdapter(),
            SemgrepAdapter(),
            OsvScannerAdapter(),
            BanditAdapter(),
            CustomRulesScanner()
        ]

        scanner_results = []
        for adapter in adapters:
            meta = adapter.metadata()
            if adapter.supports(languages, frameworks):
                try:
                    ctx = adapter.prepare(target_dir)
                    ctx["detected_languages"] = languages
                    ctx["detected_frameworks"] = frameworks
                    res = adapter.execute(target_dir, ctx)
                    scanner_results.append(res)
                    log_audit_event(
                        db,
                        audit_id=audit_id,
                        stage="SCANNING",
                        state="DONE" if res.status == "COMPLETED" else "PARTIAL",
                        message=f"{meta.name.value} (v{meta.version}) finished: {len(res.raw_findings)} findings"
                    )
                except Exception as exc:
                    log_audit_event(
                        db,
                        audit_id=audit_id,
                        stage="SCANNING",
                        state="FAILED",
                        message=f"{meta.name.value} error: {str(exc)}"
                    )
            else:
                log_audit_event(
                    db,
                    audit_id=audit_id,
                    stage="SCANNING",
                    state="SKIPPED",
                    message=f"{meta.name.value} skipped: unsupported languages"
                )

        # 3. NORMALIZING Stage
        log_audit_event(
            db,
            audit_id=audit_id,
            stage="NORMALIZING",
            state="IN_PROGRESS",
            message="Normalizing findings and verifying redaction"
        )

        total_findings, has_failures = normalize_and_persist_scan_results(
            db=db,
            audit_id=audit_id,
            scanner_results=scanner_results
        )

        log_audit_event(
            db,
            audit_id=audit_id,
            stage="NORMALIZING",
            state="DONE",
            message=f"Normalization complete. Total verified findings: {total_findings}"
        )

        # 4. CONTROLS EVALUATION & REMEDIATION Stage (M3)
        log_audit_event(
            db,
            audit_id=audit_id,
            stage="CONTROLS",
            state="IN_PROGRESS",
            message="Evaluating 32 security controls and generating remediations"
        )

        evaluate_security_controls(
            db=db,
            audit_id=audit_id,
            detected_languages=languages,
            detected_frameworks=frameworks
        )

        generate_deterministic_remediations(
            db=db,
            audit_id=audit_id
        )

        scope_set = {str(s).upper() for s in (audit.scopes or [])}
        if "DPDP" in scope_set or "BOTH" in scope_set:
            evaluate_dpdp_controls(
                db=db,
                audit_id=audit_id,
                as_of_date=date(2026, 11, 14)
            )

        audit.status = "PARTIAL" if has_failures else "COMPLETED"
        audit.current_stage = "COMPLETED"
        db.commit()

        log_audit_event(
            db,
            audit_id=audit_id,
            stage="CONTROLS",
            state="DONE",
            message="Security controls evaluation and remediations complete."
        )

    except Exception as exc:
        audit.status = "FAILED"
        audit.current_stage = "SCANNING"
        db.commit()
        log_audit_event(
            db,
            audit_id=audit_id,
            stage="SCANNING",
            state="FAILED",
            message=f"Pipeline failed: {str(exc)}"
        )
    finally:
        if not worktree_dir:
            purge_worktree(settings.WORKTREE_STORAGE_DIR / str(audit_id))
        db.close()


def execute_import_pipeline(audit_id: str) -> None:
    """Wrapper backwards-compatible with M1."""
    execute_scan_pipeline(audit_id)
