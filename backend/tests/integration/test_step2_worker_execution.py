"""Integration test for Step 2 worker execution with tool_runs persistence and fixture audits."""
import uuid
from pathlib import Path
from fastapi.testclient import TestClient

from app.main import app
from app.core.db import SessionLocal
from app.models.models import AuditModel, RepositoryModel, ToolRunModel, FindingModel
from app.workers.audit_worker import execute_scan_pipeline

client = TestClient(app)
ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
VULN_PYTHON_DIR = ROOT_DIR / "fixtures" / "vulnerable-python-api"
VULN_NODE_DIR = ROOT_DIR / "fixtures" / "vulnerable-node-api"


def test_step2_vulnerable_python_api_audit_and_tool_runs():
    """Verify full audit of vulnerable-python-api persists tool_runs and findings."""
    session_id = str(uuid.uuid4())
    db = SessionLocal()

    try:
        repo_id = str(uuid.uuid4())
        repo = RepositoryModel(
            id=repo_id,
            github_owner="test-org",
            github_repo="vulnerable-python-api",
            canonical_url=f"https://github.com/test-org/py-{session_id[:8]}",
            default_branch="main"
        )
        db.add(repo)

        audit_id = str(uuid.uuid4())
        audit = AuditModel(
            id=audit_id,
            repository_id=repo_id,
            session_id=session_id,
            scopes=["SECURITY", "DPDP"],
            status="QUEUED",
            current_stage="QUEUED"
        )
        db.add(audit)
        db.commit()

        # Run pipeline directly
        execute_scan_pipeline(audit_id, worktree_dir=VULN_PYTHON_DIR)

        # 1. Verify audit status
        audit_db = db.query(AuditModel).filter(AuditModel.id == audit_id).first()
        assert audit_db.status in ("COMPLETED", "PARTIAL")

        # 2. Verify tool_runs table entries
        tool_runs = db.query(ToolRunModel).filter(ToolRunModel.audit_id == audit_id).all()
        assert len(tool_runs) >= 4  # Gitleaks, Semgrep, OSV, Bandit, Custom
        tools_run_names = [tr.tool.lower() for tr in tool_runs]
        assert "gitleaks" in tools_run_names
        assert "semgrep" in tools_run_names
        assert "custom" in tools_run_names

        for tr in tool_runs:
            assert tr.exit_status in ("COMPLETED", "SKIPPED", "PARTIAL")
            assert tr.duration_ms >= 0

        # 3. Verify findings persisted
        findings = db.query(FindingModel).filter(FindingModel.audit_id == audit_id).all()
        assert len(findings) > 0

    finally:
        db.close()


def test_step2_vulnerable_node_api_audit_and_tool_runs():
    """Verify full audit of vulnerable-node-api persists tool_runs and findings."""
    session_id = str(uuid.uuid4())
    db = SessionLocal()

    try:
        repo_id = str(uuid.uuid4())
        repo = RepositoryModel(
            id=repo_id,
            github_owner="test-org",
            github_repo="vulnerable-node-api",
            canonical_url=f"https://github.com/test-org/node-{session_id[:8]}",
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

        # Run pipeline directly
        execute_scan_pipeline(audit_id, worktree_dir=VULN_NODE_DIR)

        # 1. Verify audit status
        audit_db = db.query(AuditModel).filter(AuditModel.id == audit_id).first()
        assert audit_db.status in ("COMPLETED", "PARTIAL")

        # 2. Verify tool_runs table entries
        tool_runs = db.query(ToolRunModel).filter(ToolRunModel.audit_id == audit_id).all()
        assert len(tool_runs) >= 4
        tools_run_names = [tr.tool.lower() for tr in tool_runs]
        assert "gitleaks" in tools_run_names
        assert "osv-scanner" in tools_run_names

        # 3. Verify findings persisted
        findings = db.query(FindingModel).filter(FindingModel.audit_id == audit_id).all()
        assert len(findings) > 0

    finally:
        db.close()
