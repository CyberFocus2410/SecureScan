"""Integration test for Step 8: End-to-end worker execution with API Security & Endpoint Inventory."""
import uuid
from pathlib import Path
import pytest
from app.core.db import SessionLocal
from app.models.models import AuditModel, RepositoryModel, FindingModel, ToolRunModel, AuditEventModel
from app.workers.audit_worker import execute_scan_pipeline
from app.services.api_discovery import ApiDiscoveryEngine
from app.services.api_inventory_exporter import ApiInventoryExporter

FIXTURE_DIR = Path(__file__).resolve().parent.parent.parent.parent / "fixtures" / "crapi-style-api"


def test_step8_end_to_end_worker_pipeline_with_api_security():
    """Verify that audit_worker executes api_security scanner, generates BOLA findings, and exports inventory."""
    db = SessionLocal()
    unique_suffix = uuid.uuid4().hex[:8]
    try:
        repo = RepositoryModel(
            id=f"r-crapi-{unique_suffix}",
            github_owner="CyberFocus2410",
            github_repo=f"crAPI-sample-{unique_suffix}",
            canonical_url=f"https://github.com/CyberFocus2410/crAPI-sample-{unique_suffix}",
            default_branch="main"
        )
        db.add(repo)

        audit = AuditModel(
            id=f"a-crapi-{unique_suffix}",
            session_id=f"s-step8-{unique_suffix}",
            repository_id=repo.id,
            scopes=["SECURITY"],
            status="QUEUED",
            current_stage="QUEUED",
            commit_sha="e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7"
        )
        db.add(audit)
        db.commit()

        # Execute full worker pipeline over the crapi fixture directory
        execute_scan_pipeline(audit_id=audit.id, worktree_dir=FIXTURE_DIR)

        db.refresh(audit)
        events = db.query(AuditEventModel).filter(AuditEventModel.audit_id == audit.id).all()
        print("AUDIT EVENTS:", [(e.stage, e.state, e.message) for e in events])
        assert audit.status in ("COMPLETED", "PARTIAL"), f"Audit failed: {audit.status}, events: {[(e.stage, e.message) for e in events]}"

        # Check ToolRunModel
        tool_runs = db.query(ToolRunModel).filter(ToolRunModel.audit_id == audit.id).all()
        tool_names = [tr.tool for tr in tool_runs]
        assert "api_security" in tool_names

        # Check findings
        findings = db.query(FindingModel).filter(FindingModel.audit_id == audit.id).all()
        rule_ids = [f.rule_id for f in findings]

        assert "api-bola-missing-object-level-authz" in rule_ids
        assert "api-broken-authentication-sensitive-endpoint" in rule_ids
        assert "api-inventory-shadow-endpoint-detected" in rule_ids

        # Discover endpoints and export inventory
        endpoints = ApiDiscoveryEngine.discover_from_repo(str(FIXTURE_DIR))
        assert len(endpoints) >= 4

        json_export = ApiInventoryExporter.to_json(endpoints)
        assert "endpoints" in json_export
        assert "total_count" in json_export

        csv_export = ApiInventoryExporter.to_csv(endpoints)
        assert "method,path,auth_required" in csv_export
    finally:
        db.close()
