"""AT-08: Scanner crash and timeout fail-safe tests (Partial-Failure Guarantee)."""
import uuid
from pathlib import Path
from fastapi.testclient import TestClient

from app.main import app
from app.core.db import SessionLocal
from app.models.models import AuditModel, RepositoryModel, ScannerRunModel
from app.schemas.enums import ScannerName
from app.scanners.base import ScannerExecutionResult, RawFinding
from app.services.normalization import normalize_and_persist_scan_results

client = TestClient(app)


def test_at08_scanner_crash_triggers_partial_audit_status():
    """
    AT-08: Kill a scanner or simulate a crash -> audit status becomes PARTIAL,
    never Pass or clean. Findings from successful scanners remain intact.
    """
    session_id = str(uuid.uuid4())
    headers = {"X-Session-ID": session_id}
    db = SessionLocal()

    try:
        repo_id = str(uuid.uuid4())
        repo = RepositoryModel(
            id=repo_id,
            github_owner="test-org",
            github_repo="crash-test-repo",
            canonical_url=f"https://github.com/test-org/crash-{session_id[:6]}",
            default_branch="main"
        )
        db.add(repo)

        audit_id = str(uuid.uuid4())
        audit = AuditModel(
            id=audit_id,
            repository_id=repo_id,
            session_id=session_id,
            scopes=["SECURITY"],
            status="SCANNING",
            current_stage="SCANNING"
        )
        db.add(audit)
        db.commit()

        # Simulate 2 scanner runs: Gitleaks succeeded, Semgrep crashed/timed out
        mock_results = [
            ScannerExecutionResult(
                scanner=ScannerName.GITLEAKS,
                version="8.21.2",
                status="COMPLETED",
                duration_ms=1200,
                raw_findings=[
                    RawFinding(
                        rule_id="test-token",
                        title="Dummy Token",
                        description="Secret in file",
                        category="secrets",
                        severity="HIGH",
                        confidence="CONFIRMED",
                        file_path="app.py",
                        start_line=1,
                        end_line=1,
                        raw_snippet="token = '[REDACTED:secret]'"
                    )
                ]
            ),
            ScannerExecutionResult(
                scanner=ScannerName.SEMGREP,
                version="1.102.0",
                status="FAILED",  # Scanner crashed!
                duration_ms=60000,
                raw_findings=[],
                error_code="ERR_SCANNER_EXECUTION_FAILED",
                error_message="Semgrep container killed: OOMKilled"
            )
        ]

        total_findings, has_failures = normalize_and_persist_scan_results(
            db=db,
            audit_id=audit_id,
            scanner_results=mock_results
        )

        assert has_failures is True
        assert total_findings == 1

        # 1. Audit status must be PARTIAL (never COMPLETED or PASS)
        updated_audit = db.query(AuditModel).filter(AuditModel.id == audit_id).first()
        assert updated_audit.status == "PARTIAL"

        # 2. Scanner runs endpoint reports the failure explicitly
        runs_res = client.get(f"/api/v1/audits/{audit_id}/scanner-runs", headers=headers)
        assert runs_res.status_code == 200
        runs_data = runs_res.json()
        assert len(runs_data) == 2

        semgrep_run = next(r for r in runs_data if r["scanner"] == "semgrep")
        assert semgrep_run["status"] == "FAILED"
        assert semgrep_run["error_code"] is not None

        # 3. Surviving findings from Gitleaks are still viewable
        findings_res = client.get(f"/api/v1/audits/{audit_id}/security/findings", headers=headers)
        assert findings_res.status_code == 200
        findings_data = findings_res.json()
        assert findings_data["total"] == 1
        assert findings_data["items"][0]["rule_id"] == "test-token"

    finally:
        db.close()

