"""AT-07: Known vulnerable dependency detection and honest NOT_VERIFIED for missing lockfiles."""
import uuid
from pathlib import Path
from fastapi.testclient import TestClient

from app.main import app
from app.core.db import SessionLocal
from app.models.models import AuditModel, RepositoryModel
from app.workers.audit_worker import execute_scan_pipeline
from app.scanners.osv import OsvScannerAdapter

client = TestClient(app)
ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
VULN_NODE_DIR = ROOT_DIR / "fixtures" / "vulnerable-node-api"


def test_at07_known_vulnerable_dependency_detected():
    """AT-07: Lockfile containing vulnerable dependency yields authentic CVE finding."""
    session_id = str(uuid.uuid4())
    headers = {"X-Session-ID": session_id}
    db = SessionLocal()

    try:
        repo_id = str(uuid.uuid4())
        repo = RepositoryModel(
            id=repo_id,
            github_owner="vulnerable-org",
            github_repo="vulnerable-node-api",
            canonical_url=f"https://github.com/vulnerable-org/node-cve-{session_id[:6]}",
            default_branch="main"
        )
        db.add(repo)

        audit_id = str(uuid.uuid4())
        audit = AuditModel(
            id=audit_id,
            repository_id=repo_id,
            session_id=session_id,
            scopes=["SECURITY"],
            status="QUEUED",
            current_stage="QUEUED"
        )
        db.add(audit)
        db.commit()

        execute_scan_pipeline(audit_id, worktree_dir=VULN_NODE_DIR)

        res = client.get(
            f"/api/v1/audits/{audit_id}/security/findings?category=dependency",
            headers=headers
        )
        assert res.status_code == 200
        data = res.json()
        assert data["total"] >= 1

        dep_finding = data["items"][0]
        assert "package-lock.json" in dep_finding["file_path"]
        assert "A06:2025" in dep_finding["owasp_refs"]
        assert "CVE-" in dep_finding["title"]
        assert dep_finding["remediation"] is not None

    finally:
        db.close()


def test_at07_missing_lockfile_yields_not_verified(tmp_path: Path):
    """
    FR-SCN-04: No recognized lockfile evaluates to NOT_VERIFIED.
    Never outputs '0 CVEs' or cleans status without verification.
    """
    empty_repo = tmp_path / "no_lockfile_repo"
    empty_repo.mkdir()
    (empty_repo / "server.py").write_text("print('hello')", encoding="utf-8")

    adapter = OsvScannerAdapter()
    ctx = adapter.prepare(empty_repo)
    result = adapter.execute(empty_repo, ctx)

    assert result.status == "NOT_VERIFIED"
    assert len(result.raw_findings) == 0
    assert "No recognized dependency lockfile found" in result.error_message

