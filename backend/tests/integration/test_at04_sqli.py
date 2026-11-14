"""AT-04: Genuine SQL injection vulnerability detection with authentic file/line locator."""
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


def test_at04_sql_injection_with_real_locator():
    """
    AT-04: SQL injection fixture yields real file and line locator,
    with grounded CWE-89 and OWASP A05:2025 reference.
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
            canonical_url=f"https://github.com/vulnerable-org/sqli-{session_id[:6]}",
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

        res = client.get(
            f"/api/v1/audits/{audit_id}/security/findings?category=injection",
            headers=headers
        )
        assert res.status_code == 200
        data = res.json()
        assert data["total"] >= 1

        sqli_finding = None
        for item in data["items"]:
            if "sql" in item["rule_id"].lower() or "sql" in item["title"].lower():
                sqli_finding = item
                break

        assert sqli_finding is not None, "SQL Injection finding not discovered in fixture!"
        assert "users.py" in sqli_finding["file_path"]
        assert sqli_finding["start_line"] > 0
        assert sqli_finding["end_line"] >= sqli_finding["start_line"]
        assert "CWE-89" in sqli_finding["cwe_ids"]
        assert "A05:2025" in sqli_finding["owasp_refs"]
        assert sqli_finding["confidence"] == "CONFIRMED"
        assert sqli_finding["remediation"] is not None
        assert "parameterized" in sqli_finding["remediation"]["technical_fix"].lower()

    finally:
        db.close()

