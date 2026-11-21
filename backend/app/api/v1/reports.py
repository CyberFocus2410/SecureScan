"""Reports API router (FR-RPT, FR-ACC)."""
import os
from fastapi import APIRouter, Depends, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.session import get_session_id
from app.core.errors import AuditNotFoundError, UnauthorizedSessionError
from app.models.models import AuditModel, RepositoryModel, SbomComponentModel
from app.schemas.report import ReportCreateRequest, ReportResponse
from app.services.reports import create_or_run_report, get_report_artifact
from app.services.sbom import generate_cyclonedx_1_6_json, generate_spdx_2_3_json
from app.reporting.sarif_export import generate_sarif_report
from app.reporting.markdown_export import generate_markdown_report
from app.services.fix_pack import FixPackGenerator
from fastapi.responses import Response

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


@router.get("/audits/{audit_id}/sbom/cyclonedx")
def get_cyclonedx_sbom(
    audit_id: str,
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db)
):
    """Export standard CycloneDX 1.6 JSON Software Bill of Materials (SBOM)."""
    audit = db.query(AuditModel).filter(AuditModel.id == audit_id).first()
    if not audit:
        raise AuditNotFoundError(f"Audit '{audit_id}' not found.")
    if audit.session_id != session_id:
        raise UnauthorizedSessionError("Unauthorized session access.")

    repo = db.query(RepositoryModel).filter(RepositoryModel.id == audit.repository_id).first()
    repo_name = repo.github_repo if repo else "project"

    models = db.query(SbomComponentModel).filter(SbomComponentModel.audit_id == audit_id).all()
    components = [
        {
            "name": m.name,
            "version": m.version,
            "ecosystem": m.ecosystem,
            "purl": m.purl,
            "license": m.license,
            "is_direct": m.is_direct
        }
        for m in models
    ]
    return generate_cyclonedx_1_6_json(
        project_name=repo_name,
        project_version=audit.commit_sha or "1.0.0",
        components=components
    )


@router.get("/audits/{audit_id}/sbom/spdx")
def get_spdx_sbom(
    audit_id: str,
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db)
):
    """Export standard SPDX 2.3 JSON Software Bill of Materials (SBOM)."""
    audit = db.query(AuditModel).filter(AuditModel.id == audit_id).first()
    if not audit:
        raise AuditNotFoundError(f"Audit '{audit_id}' not found.")
    if audit.session_id != session_id:
        raise UnauthorizedSessionError("Unauthorized session access.")

    repo = db.query(RepositoryModel).filter(RepositoryModel.id == audit.repository_id).first()
    repo_name = repo.github_repo if repo else "project"

    models = db.query(SbomComponentModel).filter(SbomComponentModel.audit_id == audit_id).all()
    components = [
        {
            "name": m.name,
            "version": m.version,
            "ecosystem": m.ecosystem,
            "purl": m.purl,
            "license": m.license,
            "is_direct": m.is_direct
        }
        for m in models
    ]
    return generate_spdx_2_3_json(
        project_name=repo_name,
        project_version=audit.commit_sha or "1.0.0",
        components=components
    )


@router.get("/audits/{audit_id}/sarif")
def get_sarif_export(
    audit_id: str,
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db)
):
    """Export standard OASIS SARIF 2.1.0 JSON representation for GitHub Code Scanning."""
    audit = db.query(AuditModel).filter(AuditModel.id == audit_id).first()
    if not audit:
        raise AuditNotFoundError(f"Audit '{audit_id}' not found.")
    if audit.session_id != session_id:
        raise UnauthorizedSessionError("Unauthorized session access.")

    sarif_str = generate_sarif_report(audit_id=audit_id, db=db)
    return Response(content=sarif_str, media_type="application/sarif+json")


@router.get("/audits/{audit_id}/markdown")
def get_markdown_export(
    audit_id: str,
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db)
):
    """Export comprehensive Developer Markdown audit report."""
    audit = db.query(AuditModel).filter(AuditModel.id == audit_id).first()
    if not audit:
        raise AuditNotFoundError(f"Audit '{audit_id}' not found.")
    if audit.session_id != session_id:
        raise UnauthorizedSessionError("Unauthorized session access.")

    md_str = generate_markdown_report(audit_id=audit_id, db=db)
    return Response(content=md_str, media_type="text/markdown")


@router.get("/audits/{audit_id}/fix-pack")
def get_fix_pack_export(
    audit_id: str,
    format: str = "json",
    session_id: str = Depends(get_session_id),
    db: Session = Depends(get_db)
):
    """Export self-contained remediation Fix Pack (checklist, diffs, agent prompts)."""
    audit = db.query(AuditModel).filter(AuditModel.id == audit_id).first()
    if not audit:
        raise AuditNotFoundError(f"Audit '{audit_id}' not found.")
    if audit.session_id != session_id:
        raise UnauthorizedSessionError("Unauthorized session access.")

    repo = db.query(RepositoryModel).filter(RepositoryModel.id == audit.repository_id).first()
    target_name = repo.canonical_url if repo else "target"

    findings = [
        {
            "id": f.id,
            "rule_id": f.rule_id,
            "title": f.title,
            "file_path": f.file_path,
            "start_line": f.start_line,
        }
        for f in audit.findings
    ]
    pack = FixPackGenerator.generate_scan_fix_pack(scan_id=audit_id, target=target_name, findings=findings)

    if format.lower() == "markdown" or format.lower() == "md":
        return Response(content=pack.to_markdown(), media_type="text/markdown")

    return {
        "scan_id": pack.scan_id,
        "target": pack.target,
        "total_fixes": pack.total_fixes,
        "artifacts": [a.to_dict() for a in pack.artifacts]
    }


