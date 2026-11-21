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
    AuditEventModel,
    ToolRunModel
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
from app.scanners.trufflehog import TruffleHogAdapter
from app.scanners.iac_config import IacConfigScanner
from app.scanners.database_static import DatabaseStaticScanner
from app.scanners.api_security import ApiSecurityScanner
from app.scanners.ai_security import AiSecurityScanner
from app.services.sbom import parse_lockfile_components, persist_sbom_components
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
            TruffleHogAdapter(),
            SemgrepAdapter(),
            OsvScannerAdapter(),
            BanditAdapter(),
            CustomRulesScanner(),
            IacConfigScanner(),
            DatabaseStaticScanner(),
            ApiSecurityScanner(),
            AiSecurityScanner()
        ]

        scanner_results = []
        for adapter in adapters:
            meta = adapter.metadata()
            tool_identifier = getattr(adapter, "tool_name", meta.name.value)
            if adapter.supports(languages, frameworks):
                try:
                    ctx = adapter.prepare(target_dir)
                    ctx["detected_languages"] = languages
                    ctx["detected_frameworks"] = frameworks
                    res = adapter.execute(target_dir, ctx)
                    scanner_results.append(res)

                    tool_run = ToolRunModel(
                        audit_id=audit_id,
                        tool=tool_identifier,
                        version=meta.version,
                        exit_status="COMPLETED" if res.status == "COMPLETED" else res.status,
                        duration_ms=res.duration_ms,
                        coverage_metrics={
                            "findings_count": len(res.raw_findings),
                            "supported_languages": meta.supported_languages,
                            "rules_version": getattr(meta, "rules_version", "")
                        },
                        stdout_preview=res.stdout[:500] if res.stdout else None,
                        stderr_preview=res.stderr[:500] if res.stderr else None,
                        created_at=datetime.utcnow()
                    )
                    db.add(tool_run)
                    db.commit()

                    log_audit_event(
                        db,
                        audit_id=audit_id,
                        stage="SCANNING",
                        state="DONE" if res.status == "COMPLETED" else "PARTIAL",
                        message=f"{tool_identifier} (v{meta.version}) finished: {len(res.raw_findings)} findings"
                    )
                except Exception as exc:
                    tool_run = ToolRunModel(
                        audit_id=audit_id,
                        tool=tool_identifier,
                        version=meta.version,
                        exit_status="FAILED",
                        duration_ms=0,
                        coverage_metrics={"error": str(exc)},
                        stderr_preview=str(exc)[:500],
                        created_at=datetime.utcnow()
                    )
                    db.add(tool_run)
                    db.commit()

                    log_audit_event(
                        db,
                        audit_id=audit_id,
                        stage="SCANNING",
                        state="FAILED",
                        message=f"{tool_identifier} error: {str(exc)}"
                    )
            else:
                tool_run = ToolRunModel(
                    audit_id=audit_id,
                    tool=tool_identifier,
                    version=meta.version,
                    exit_status="SKIPPED",
                    duration_ms=0,
                    coverage_metrics={"reason": "unsupported languages"},
                    created_at=datetime.utcnow()
                )
                db.add(tool_run)
                db.commit()

                log_audit_event(
                    db,
                    audit_id=audit_id,
                    stage="SCANNING",
                    state="SKIPPED",
                    message=f"{tool_identifier} skipped: unsupported languages"
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

        # 3b. SBOM Extraction & Persistence (Step 4, ADR-002)
        try:
            sbom_components = parse_lockfile_components(target_dir)
            persisted_count = persist_sbom_components(db, audit_id, sbom_components)
            if persisted_count > 0:
                log_audit_event(
                    db,
                    audit_id=audit_id,
                    stage="NORMALIZING",
                    state="DONE",
                    message=f"SBOM generated: cataloged {persisted_count} components across lockfiles."
                )
        except Exception as sbom_err:
            pass

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
            as_of_val = None
            if getattr(settings, "AS_OF_DATE", None):
                try:
                    as_of_val = datetime.strptime(str(settings.AS_OF_DATE)[:10], "%Y-%m-%d").date()
                except Exception:
                    pass
            evaluate_dpdp_controls(
                db=db,
                audit_id=audit_id,
                as_of_date=as_of_val or date.today()
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


def start_rq_worker() -> None:
    """Entrypoint to consume audit jobs from Redis queue using RQ (Step 2, ADR-002)."""
    import logging
    worker_logger = logging.getLogger("securescan.worker")
    try:
        import redis
        from rq import Worker, Queue, Connection
        conn = redis.from_url(settings.REDIS_URL)
        with Connection(conn):
            worker_logger.info("SecureScan RQ worker listening on queue '%s'...", settings.RQ_QUEUE_NAME)
            worker = Worker([Queue(settings.RQ_QUEUE_NAME)])
            worker.work()
    except Exception as exc:
        worker_logger.error("RQ worker startup failed: %s", exc)
        raise


if __name__ == "__main__":
    start_rq_worker()

