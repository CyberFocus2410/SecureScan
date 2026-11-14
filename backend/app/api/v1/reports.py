"""Reports API router (FR-RPT, FR-ACC)."""
import os
from fastapi import APIRouter, Depends, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.session import get_session_id
from app.schemas.report import ReportCreateRequest, ReportResponse
from app.services.reports import create_or_run_report, get_report_artifact

router = APIRouter(tags=["Reports"])


@router.post("/audits/{audit_id}/reports", status_code=status.HTTP_202_ACCEPTED)
def request_report_generation(
    audit_id: str,
    payload: ReportCreateRequest,
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db)
):
    """
    Generate an auditor-grade report artifact (PDF or JSON).
    Returns 202 Accepted with the report identifier.
    """
    report = create_or_run_report(
        audit_id=audit_id,
        format_str=payload.format,
        session_id=session_id,
        db=db
    )
    return {
        "report_id": report.id,
        "status": report.status,
        "format": report.format
    }


@router.get("/reports/{report_id}", response_model=ReportResponse)
def get_report_status(
    report_id: str,
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db)
):
    """Retrieve metadata, status, and download URL for a generated report."""
    report, _, _ = get_report_artifact(report_id=report_id, session_id=session_id, db=db)
    return ReportResponse(
        id=report.id,
        audit_id=report.audit_id,
        format=report.format,
        status=report.status,
        download_url=f"/api/v1/reports/{report.id}/download",
        expires_at=report.expires_at,
        created_at=report.created_at
    )


@router.get("/reports/{report_id}/download")
def download_report(
    report_id: str,
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db)
):
    """
    Download the generated report artifact.
    Enforces session capability ID and safe filename.
    """
    report, file_path, filename = get_report_artifact(report_id=report_id, session_id=session_id, db=db)
    media_type = "application/pdf" if report.format == "pdf" else "application/json"

    return FileResponse(
        path=file_path,
        media_type=media_type,
        filename=filename,
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "Content-Disposition": f'attachment; filename="{filename}"'
        }
    )

