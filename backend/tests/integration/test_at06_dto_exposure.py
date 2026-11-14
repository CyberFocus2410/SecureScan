"""AT-06: Sensitive field exposure in DTO / Serializer with unverified auth context."""
import uuid
from pathlib import Path
from fastapi.testclient import TestClient

from app.main import app
from app.core.db import SessionLocal
from app.models.models import AuditModel, RepositoryModel
from app.workers.audit_worker import execute_scan_pipeline

client = TestClient(app)
ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
VULN_PYTHON_DIR = ROOT_DIR / "fixtures" / "vulnerable-python-api"


def test_at06_dto_sensitive_field_exposure():
    """
    AT-06: Flag sensitive field exposure only when field appears in output schema/DTO,
    with auth context explicitly labelled unverified.
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
            canonical_url=f"https://github.com/vulnerable-org/dto-{session_id[:6]}",
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

        # 1. Verify finding exists via API
        res = client.get(
            f"/api/v1/audits/{audit_id}/security/findings?category=data_exposure",
            headers=headers
        )
        assert res.status_code == 200
        data = res.json()
        assert data["total"] >= 1

        dto_finding = next((f for f in data["items"] if "dto" in f["rule_id"].lower() or "dto" in f["title"].lower()), None)
        assert dto_finding is not None, "DTO sensitive exposure finding not found!"
        assert "unverified" in dto_finding["description"].lower()
        assert "password" in dto_finding["description"].lower() or "national_id" in dto_finding["description"].lower()
        assert "API3:2023" in dto_finding["owasp_refs"]

        # 2. Verify SEC-004 control evaluation
        ctrl_res = client.get(f"/api/v1/audits/{audit_id}/security/controls", headers=headers)
        assert ctrl_res.status_code == 200
        sec_004 = next((c for c in ctrl_res.json() if c["control_id"] == "SEC-004"), None)
        assert sec_004 is not None
        assert sec_004["state"] == "FAIL_EVIDENCED"

    finally:
        db.close()

