"""AT-05: Missing rate limiting reported as POTENTIAL_GAP (conservative semantics)."""
import uuid
from pathlib import Path
from fastapi.testclient import TestClient

from app.main import app
from app.core.db import SessionLocal
from app.models.models import AuditModel, RepositoryModel, ControlResultModel
from app.workers.audit_worker import execute_scan_pipeline

client = TestClient(app)
ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
VULN_PYTHON_DIR = ROOT_DIR / "fixtures" / "vulnerable-python-api"


def test_at05_rate_limiting_yields_potential_gap():
    """
    AT-05: Endpoints lacking in-code rate limiting decorators MUST be reported
    as POTENTIAL_GAP (never confirmed failure), acknowledging upstream gateways/proxies.
    """
    session_id = str(uuid.uuid4())
    headers = {"X-Session-ID": session_id}
    db = SessionLocal()

    try:
        repo_id = str(uuid.uuid4())
        repo = RepositoryModel(
            id=repo_id,
            github_owner="vulnerable-org",
            github_repo="vulnerable-python-api",
            canonical_url=f"https://github.com/vulnerable-org/ratelimit-{session_id[:6]}",
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

        execute_scan_pipeline(audit_id, worktree_dir=VULN_PYTHON_DIR)

        # 1. Check control results via API
        res = client.get(f"/api/v1/audits/{audit_id}/security/controls", headers=headers)
        assert res.status_code == 200
        controls = res.json()

        sec_005 = next((c for c in controls if c["control_id"] == "SEC-005"), None)
        assert sec_005 is not None, "SEC-005 control result not generated!"
        assert sec_005["state"] == "POTENTIAL_GAP", f"Expected POTENTIAL_GAP, got {sec_005['state']}"
        assert "gateway" in sec_005["rationale"].lower() or "proxy" in sec_005["rationale"].lower()

        # 2. Check coverage endpoint exposes denominator
        cov_res = client.get(f"/api/v1/audits/{audit_id}/security/coverage", headers=headers)
        assert cov_res.status_code == 200
        cov_data = cov_res.json()
        assert cov_data["summary"]["denominator"] == 32
        assert cov_data["summary"]["potential_gap"] >= 1

    finally:
        db.close()

