"""Report generation service (FR-RPT, FR-ACC)."""
import os
import uuid
from datetime import datetime, timedelta
from sqlalchemy.orm import Session

from app.models.models import AuditModel, RepositoryModel, ReportArtifactModel
from app.reporting.json_export import generate_json_report
from app.reporting.pdf_export import generate_pdf_report
from app.core.config import settings
from app.core.errors import (
    AuditNotFoundError,
    UnauthorizedSessionError,
    SecureScanException,
    ErrorCode
)


REPORTS_STORAGE_DIR = str(settings.REPORTS_STORAGE_DIR)


def create_or_run_report(audit_id: str, format_str: str, session_id: str, db: Session) -> ReportArtifactModel:
    """Generate and persist a report artifact (PDF or JSON) with 24-hour expiry."""
    audit = db.query(AuditModel).filter(AuditModel.id == audit_id).first()
    if not audit:
        raise AuditNotFoundError(f"Audit '{audit_id}' not found.")

    if audit.session_id != session_id:
        raise UnauthorizedSessionError("Unauthorized session access.")

    format_clean = format_str.lower().strip()
    if format_clean not in ("pdf", "json"):
        raise SecureScanException(
            code=ErrorCode.ERR_VALIDATION_ERROR,
            message="Invalid report format. Only 'pdf' and 'json' are supported.",
            status_code=400
        )

    report_id = str(uuid.uuid4())
    audit_reports_dir = os.path.join(REPORTS_STORAGE_DIR, audit_id)
    os.makedirs(audit_reports_dir, exist_ok=True)

    file_name = f"{report_id}.{format_clean}"
    storage_path = os.path.join(audit_reports_dir, file_name)

    # Generate content
    if format_clean == "json":
        content = generate_json_report(audit_id, db)
        with open(storage_path, "w", encoding="utf-8") as f:
            f.write(content)
    else:  # pdf
        pdf_bytes = generate_pdf_report(audit_id, db)
        with open(storage_path, "wb") as f:
            f.write(pdf_bytes)

    # Persist report record with 24h expiry
    now = datetime.utcnow()
    expires_at = now + timedelta(hours=24)

    report = ReportArtifactModel(
        id=report_id,
        audit_id=audit_id,
        format=format_clean,
        status="COMPLETED",
        safe_storage_key=storage_path,
        expires_at=expires_at,
        created_at=now
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    return report


def get_report_artifact(report_id: str, session_id: str, db: Session) -> tuple[ReportArtifactModel, str, str]:
    """Retrieve report artifact, checking session ownership and expiration. Returns (report, file_path, download_filename)."""
    report = db.query(ReportArtifactModel).filter(ReportArtifactModel.id == report_id).first()
    if not report:
        raise SecureScanException(
            code=ErrorCode.ERR_REPORT_NOT_FOUND,
            message=f"Report '{report_id}' not found.",
            status_code=404
        )

    # Check expiry
    if report.expires_at and datetime.utcnow() > report.expires_at:
        raise SecureScanException(
            code=ErrorCode.ERR_REPORT_NOT_FOUND,
            message=f"Report '{report_id}' has expired.",
            status_code=404
        )

    # Verify session
    audit = db.query(AuditModel).filter(AuditModel.id == report.audit_id).first()
    if not audit or audit.session_id != session_id:
        raise UnauthorizedSessionError("Unauthorized session access.")

    repo = db.query(RepositoryModel).filter(RepositoryModel.id == audit.repository_id).first()
    repo_clean = "repo"
    sha_short = "sha"
    if repo:
        url = getattr(repo, "canonical_url", "") or getattr(repo, "github_url", "")
        if url:
            parts = url.rstrip("/").split("/")
            if len(parts) >= 2:
                repo_clean = f"{parts[-2]}_{parts[-1]}"
        commit_sha = audit.commit_sha or getattr(repo, "last_commit_sha", "")
        if commit_sha:
            sha_short = commit_sha[:8]


    safe_filename = f"securescan_audit_report_{repo_clean}_{sha_short}.{report.format}"
    return report, report.safe_storage_key, safe_filename
