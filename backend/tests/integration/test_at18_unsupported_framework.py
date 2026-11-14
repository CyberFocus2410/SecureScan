"""AT-18: Unsupported framework yields NOT_VERIFIED, never clean."""
import uuid
from pathlib import Path
from fastapi.testclient import TestClient

from app.main import app
from app.core.db import SessionLocal
from app.models.models import AuditModel, RepositoryModel
from app.workers.audit_worker import execute_scan_pipeline

client = TestClient(app)
ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
UNSUPPORTED_DIR = ROOT_DIR / "fixtures" / "unsupported-framework"


def test_at18_unsupported_framework_yields_not_verified():
    """
    AT-18: Repositories with unsupported frameworks/languages (e.g. Go)
    MUST yield NOT_VERIFIED for framework-dependent checks, NEVER PASS_EVIDENCED.
    """
    session_id = str(uuid.uuid4())
    headers = {"X-Session-ID": session_id}
    db = SessionLocal()

    try:
        repo_id = str(uuid.uuid4())
        repo = RepositoryModel(
            id=repo_id,
            github_owner="unsupported-org",
            github_repo="unsupported-framework-app",
            canonical_url=f"https://github.com/unsupported-org/go-app-{session_id[:6]}",
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

        execute_scan_pipeline(audit_id, worktree_dir=UNSUPPORTED_DIR)

        # Retrieve control results
        res = client.get(f"/api/v1/audits/{audit_id}/security/controls", headers=headers)
        assert res.status_code == 200
        controls = res.json()

        # Framework-dependent controls (SEC-004, SEC-005, SEC-007, SEC-020) must be NOT_VERIFIED
        framework_checks = ["SEC-004", "SEC-005", "SEC-007", "SEC-020"]
        for cid in framework_checks:
            ctrl = next((c for c in controls if c["control_id"] == cid), None)
            assert ctrl is not None, f"Control {cid} missing from output!"
            assert ctrl["state"] == "NOT_VERIFIED", f"Control {cid} was {ctrl['state']}, expected NOT_VERIFIED"
            assert "unsupported" in ctrl["rationale"].lower() or "not supported" in ctrl["rationale"].lower()

        # Coverage response check
        cov_res = client.get(f"/api/v1/audits/{audit_id}/security/coverage", headers=headers)
        assert cov_res.status_code == 200
        summary = cov_res.json()["summary"]
        assert summary["not_verified"] > 0
        # Evidenced controls should not falsely claim clean passes on framework checks
        assert summary["evidenced_pass"] < 10

    finally:
        db.close()
