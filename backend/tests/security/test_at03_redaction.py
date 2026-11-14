"""AT-03: Secret detection with absolute parser-level redaction verification.
Asserts that the raw secret literal string NEVER appears in the database,
API responses, evidence excerpts, or logs.
"""
import uuid
from pathlib import Path
from fastapi.testclient import TestClient

from app.main import app
from app.core.db import SessionLocal
from app.models.models import AuditModel, RepositoryModel, FindingModel, EvidenceModel
from app.workers.audit_worker import execute_scan_pipeline
from app.core.security import assert_no_raw_secret

client = TestClient(app)
ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
VULN_PYTHON_DIR = ROOT_DIR / "fixtures" / "vulnerable-python-api"

RAW_SECRET_TOKEN = "AKIAIOSFODNN7EXAMPLEFAKETOKEN"
RAW_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def test_at03_secret_redaction_and_absence_everywhere():
    """
    AT-03: Scan repo containing known secrets.
    1. Verify secret is found and reported.
    2. Grep database dump, evidence, and API responses for the raw literals.
    3. Assert raw literals are 100% ABSENT everywhere.
    """
    session_id = str(uuid.uuid4())
    headers = {"X-Session-ID": session_id}
    db = SessionLocal()

    try:
        # Create repository and audit
        repo_id = str(uuid.uuid4())
        repo = RepositoryModel(
            id=repo_id,
            github_owner="vulnerable-org",
            github_repo="vulnerable-python-api",
            canonical_url=f"https://github.com/vulnerable-org/vuln-py-{session_id[:6]}",
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

        # Execute scan pipeline on vulnerable fixture
        execute_scan_pipeline(audit_id, worktree_dir=VULN_PYTHON_DIR)

        # 1. Verify finding exists via API
        res = client.get(f"/api/v1/audits/{audit_id}/security/findings", headers=headers)
        assert res.status_code == 200
        findings_data = res.json()
        assert findings_data["total"] >= 1

        # Locate secret finding
        secret_findings = [f for f in findings_data["items"] if f["category"] == "secrets"]
        assert len(secret_findings) >= 1
        secret_finding = secret_findings[0]
        assert "[REDACTED:" in secret_finding["redacted_snippet"]

        # 2. Grep entire API response for raw secret literals
        response_text = res.text
        assert RAW_SECRET_TOKEN not in response_text
        assert RAW_SECRET_KEY not in response_text

        # 3. Inspect database rows directly
        db_findings = db.query(FindingModel).filter(FindingModel.audit_id == audit_id).all()
        for f in db_findings:
            assert RAW_SECRET_TOKEN not in (f.redacted_snippet or "")
            assert RAW_SECRET_KEY not in (f.redacted_snippet or "")
            assert RAW_SECRET_TOKEN not in f.title
            assert RAW_SECRET_TOKEN not in f.description

        db_evidence = db.query(EvidenceModel).filter(EvidenceModel.audit_id == audit_id).all()
        for ev in db_evidence:
            assert RAW_SECRET_TOKEN not in ev.redacted_excerpt
            assert RAW_SECRET_KEY not in ev.redacted_excerpt

        # 4. Use assert_no_raw_secret recursive helper
        assert_no_raw_secret(findings_data, RAW_SECRET_TOKEN)
        assert_no_raw_secret(findings_data, RAW_SECRET_KEY)

    finally:
        db.close()

