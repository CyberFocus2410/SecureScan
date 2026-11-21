"""Unit tests for Step 13: Professional Multi-Format Reports (JSON, PDF, Markdown, SARIF 2.1.0, Fix Pack)."""
import json
import uuid
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.db import SessionLocal
from app.models.models import AuditModel, RepositoryModel, FindingModel
from app.reporting.sarif_export import generate_sarif_report
from app.reporting.markdown_export import generate_markdown_report
from app.reporting.json_export import generate_json_report
from app.reporting.pdf_export import generate_pdf_report


@pytest.fixture
def seeded_audit_db():
    session_id = str(uuid.uuid4())
    db = SessionLocal()
    audit_id = str(uuid.uuid4())
    repo_id = str(uuid.uuid4())

    repo = RepositoryModel(
        id=repo_id,
        github_owner="test-org",
        github_repo="vulnerable-python-api",
        canonical_url=f"https://github.com/test-org/py-{session_id[:8]}",
        default_branch="main"
    )
    db.add(repo)

    audit = AuditModel(
        id=audit_id,
        repository_id=repo_id,
        session_id=session_id,
        scopes=["SECURITY", "DPDP"],
        status="COMPLETED",
        current_stage="REPORT_READY",
        commit_sha="a1b2c3d4e5f678901234567890abcdef12345678"
    )
    db.add(audit)

    # Add representative findings
    findings = [
        FindingModel(
            id=str(uuid.uuid4()),
            audit_id=audit_id,
            fingerprint=f"fp-sql-{uuid.uuid4().hex[:8]}",
            scanner_name="semgrep",
            scanner_version="1.0.0",
            tool="semgrep",
            rule_id="sast-sql-injection",
            title="SQL Injection in Login Endpoint",
            description="User input directly concatenated into SQL query string.",
            severity="CRITICAL",
            confidence="CONFIRMED",
            category="sast",
            file_path="app/auth.py",
            start_line=25,
            end_line=28,
            priority="P0",
            cwe_ids=["CWE-89"],
            owasp_refs=["A03:2021-Injection"],
            how_to_fix="Parameterize all database queries using ORM or bind parameters.",
            how_to_verify_fix="Run pytest tests/test_auth.py to verify SQL parameters.",
        ),
        FindingModel(
            id=str(uuid.uuid4()),
            audit_id=audit_id,
            fingerprint=f"fp-sec-{uuid.uuid4().hex[:8]}",
            scanner_name="gitleaks",
            scanner_version="8.30.1",
            tool="gitleaks",
            rule_id="secret-aws-access-token",
            title="Exposed AWS Access Key Token",
            description="Static AWS credentials identified in source code.",
            severity="CRITICAL",
            confidence="CONFIRMED",
            category="secrets",
            file_path="config.py",
            start_line=12,
            end_line=12,
            priority="P0",
            cwe_ids=["CWE-798"],
            owasp_refs=["A07:2021-Identification and Authentication Failures"],
            how_to_fix="Rotate the exposed key and store credentials in environment variables.",
            how_to_verify_fix="Run gitleaks detect --source .",
        ),
    ]
    db.add_all(findings)
    db.commit()

    yield {"audit_id": audit_id, "session_id": session_id, "db": db}

    db.close()


def test_sarif_export_structure_and_schema(seeded_audit_db):
    """Validates SARIF 2.1.0 schema compliance and findings mapping."""
    audit_id = seeded_audit_db["audit_id"]
    db = seeded_audit_db["db"]

    sarif_raw = generate_sarif_report(audit_id=audit_id, db=db)
    sarif = json.loads(sarif_raw)

    assert sarif["version"] == "2.1.0"
    assert "sarif-spec" in sarif["$schema"]
    assert len(sarif["runs"]) == 1

    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "SecureScan"
    assert len(run["tool"]["driver"]["rules"]) >= 2
    assert len(run["results"]) == 2

    # Verify result fields
    res1 = run["results"][0]
    assert res1["level"] == "error"
    assert "artifactLocation" in res1["locations"][0]["physicalLocation"]
    assert res1["locations"][0]["physicalLocation"]["region"]["startLine"] > 0


def test_markdown_export_headers_and_caveat(seeded_audit_db):
    """Validates Developer Markdown export headers, disclaimer, priority table, and DPDP caveat."""
    audit_id = seeded_audit_db["audit_id"]
    db = seeded_audit_db["db"]

    md = generate_markdown_report(audit_id=audit_id, db=db)

    # 1. Mandatory running disclaimer notice
    assert "Developer-assistance report — not a security certificate or legal opinion." in md

    # 2. Priority table with P0 count
    assert "Findings Breakdown by Priority" in md
    assert "| **P0** | Critical |" in md

    # 3. Mandatory DPDP penalty caveat
    assert "Potential legal category; applicability and liability not determined." in md

    # 4. Appendix with pinned tools
    assert "Appendix: Pinned Tool Inventory" in md


def test_api_report_endpoints(seeded_audit_db):
    """Tests the /api/v1/audits/{id}/sarif, markdown, and fix-pack endpoints."""
    client = TestClient(app)
    audit_id = seeded_audit_db["audit_id"]
    session_id = seeded_audit_db["session_id"]
    headers = {"X-Session-ID": session_id}

    # 1. SARIF Endpoint
    res_sarif = client.get(f"/api/v1/audits/{audit_id}/sarif", headers=headers)
    assert res_sarif.status_code == 200
    assert "application/sarif+json" in res_sarif.headers["content-type"]
    sarif_data = res_sarif.json()
    assert sarif_data["version"] == "2.1.0"

    # 2. Markdown Endpoint
    res_md = client.get(f"/api/v1/audits/{audit_id}/markdown", headers=headers)
    assert res_md.status_code == 200
    assert "text/markdown" in res_md.headers["content-type"]
    assert "SecureScan 2.0" in res_md.text

    # 3. Fix-Pack JSON Endpoint
    res_fix = client.get(f"/api/v1/audits/{audit_id}/fix-pack", headers=headers)
    assert res_fix.status_code == 200
    fix_data = res_fix.json()
    assert fix_data["total_fixes"] == 2
    assert len(fix_data["artifacts"]) == 2

    # 4. Fix-Pack Markdown Endpoint
    res_fix_md = client.get(f"/api/v1/audits/{audit_id}/fix-pack?format=markdown", headers=headers)
    assert res_fix_md.status_code == 200
    assert "Remediation Fix Pack" in res_fix_md.text
