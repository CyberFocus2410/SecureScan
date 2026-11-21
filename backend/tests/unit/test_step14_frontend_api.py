"""Unit tests for Step 14 Frontend API endpoints: comparison, cancel, risk intel, PR generation (Step 14)."""
import uuid
from datetime import datetime
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.db import SessionLocal
from app.models.models import AuditModel, RepositoryModel, FindingModel

client = TestClient(app)


@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def test_list_audits_and_cancel_pipeline(db_session):
    session_id = str(uuid.uuid4())
    repo = RepositoryModel(
        id=str(uuid.uuid4()),
        github_owner="org",
        github_repo=f"app-list-{uuid.uuid4()}",
        canonical_url=f"https://github.com/org/app-list-{uuid.uuid4()}",
        default_branch="main"
    )
    db_session.add(repo)
    db_session.commit()

    audit = AuditModel(
        id=str(uuid.uuid4()),
        repository_id=repo.id,
        session_id=session_id,
        scopes=["SECURITY"],
        status="SCANNING",
        current_stage="SCANNING",
        created_at=datetime.utcnow()
    )
    db_session.add(audit)
    db_session.commit()

    # 1. List audits
    res = client.get("/api/v1/audits", headers={"X-Session-ID": session_id})
    assert res.status_code == 200
    audits = res.json()
    assert len(audits) >= 1
    assert audits[0]["id"] == audit.id

    # 2. Cancel audit
    cancel_res = client.post(f"/api/v1/audits/{audit.id}/cancel", headers={"X-Session-ID": session_id})
    assert cancel_res.status_code == 200
    assert cancel_res.json()["status"] == "FAILED"

    # Verify audit state updated
    db_session.refresh(audit)
    assert audit.status == "FAILED"
    assert audit.current_stage == "CANCELLED"


def test_risk_intelligence_endpoint(db_session):
    session_id = str(uuid.uuid4())
    repo = RepositoryModel(
        id=str(uuid.uuid4()),
        github_owner="org",
        github_repo=f"app-risk-{uuid.uuid4()}",
        canonical_url=f"https://github.com/org/app-risk-{uuid.uuid4()}",
        default_branch="main"
    )
    db_session.add(repo)

    audit = AuditModel(
        id=str(uuid.uuid4()),
        repository_id=repo.id,
        session_id=session_id,
        scopes=["SECURITY"],
        status="COMPLETED",
        created_at=datetime.utcnow()
    )
    db_session.add(audit)
    db_session.commit()

    f1 = FindingModel(
        id=str(uuid.uuid4()),
        audit_id=audit.id,
        fingerprint=f"fp-aws-{uuid.uuid4()}",
        scanner_name="custom",
        scanner_version="1.0.0",
        rule_id="SEC-AWS-001",
        title="AWS Key Exposure",
        description="AWS API secret key exposed in source code",
        category="secrets",
        severity="CRITICAL",
        confidence="CONFIRMED",
        priority="P0",
        file_path="config.py",
        start_line=10,
        end_line=10
    )
    f2 = FindingModel(
        id=str(uuid.uuid4()),
        audit_id=audit.id,
        fingerprint=f"fp-s3-{uuid.uuid4()}",
        scanner_name="custom",
        scanner_version="1.0.0",
        rule_id="INFRA-S3-001",
        title="Public S3 Bucket",
        description="S3 bucket allows public anonymous read/write access",
        category="infrastructure",
        severity="HIGH",
        confidence="CONFIRMED",
        priority="P1",
        file_path="infra.tf",
        start_line=20,
        end_line=25
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    res = client.get(f"/api/v1/audits/{audit.id}/risk-intelligence", headers={"X-Session-ID": session_id})
    assert res.status_code == 200
    data = res.json()
    assert data["audit_id"] == audit.id
    assert data["priority_counts"]["P0"] == 1
    assert data["priority_counts"]["P1"] == 1
    # Hard cap rule must be applied due to P0 finding
    assert data["scores"]["hard_cap_applied"] is True
    assert data["scores"]["security_score"] <= 60
    assert len(data["attack_chains"]) >= 1
    assert "Cloud Credential" in data["attack_chains"][0]["title"]


def test_compare_audits_endpoint(db_session):
    session_id = str(uuid.uuid4())
    repo = RepositoryModel(
        id=str(uuid.uuid4()),
        github_owner="org",
        github_repo=f"app-compare-{uuid.uuid4()}",
        canonical_url=f"https://github.com/org/app-compare-{uuid.uuid4()}",
        default_branch="main"
    )
    db_session.add(repo)

    base_audit = AuditModel(
        id=str(uuid.uuid4()),
        repository_id=repo.id,
        session_id=session_id,
        scopes=["SECURITY"],
        status="COMPLETED",
        created_at=datetime.utcnow()
    )
    curr_audit = AuditModel(
        id=str(uuid.uuid4()),
        repository_id=repo.id,
        session_id=session_id,
        scopes=["SECURITY"],
        status="COMPLETED",
        created_at=datetime.utcnow()
    )
    db_session.add_all([base_audit, curr_audit])
    db_session.commit()

    fp_shared = f"fp-shared-{uuid.uuid4()}"
    fp_old = f"fp-old-{uuid.uuid4()}"
    fp_new = f"fp-new-{uuid.uuid4()}"

    # Base findings: fp_shared, fp_old_fixed
    f_shared_base = FindingModel(
        id=str(uuid.uuid4()),
        audit_id=base_audit.id,
        fingerprint=fp_shared,
        scanner_name="semgrep",
        scanner_version="1.0.0",
        rule_id="RULE-SHARED",
        title="Persistent finding",
        description="Persistent code vulnerability",
        category="sast",
        severity="MEDIUM",
        confidence="CONFIRMED",
        file_path="app.py",
        start_line=5,
        end_line=5
    )
    f_old = FindingModel(
        id=str(uuid.uuid4()),
        audit_id=base_audit.id,
        fingerprint=fp_old,
        scanner_name="semgrep",
        scanner_version="1.0.0",
        rule_id="RULE-OLD",
        title="Old fixed vulnerability",
        description="Legacy flaw that has been remediated",
        category="sast",
        severity="HIGH",
        confidence="CONFIRMED",
        file_path="old.py",
        start_line=12,
        end_line=12
    )

    # Current findings: fp_shared, fp_new
    f_shared_curr = FindingModel(
        id=str(uuid.uuid4()),
        audit_id=curr_audit.id,
        fingerprint=fp_shared,
        scanner_name="semgrep",
        scanner_version="1.0.0",
        rule_id="RULE-SHARED",
        title="Persistent finding",
        description="Persistent code vulnerability",
        category="sast",
        severity="MEDIUM",
        confidence="CONFIRMED",
        file_path="app.py",
        start_line=5,
        end_line=5
    )
    f_new = FindingModel(
        id=str(uuid.uuid4()),
        audit_id=curr_audit.id,
        fingerprint=fp_new,
        scanner_name="semgrep",
        scanner_version="1.0.0",
        rule_id="RULE-NEW",
        title="Newly introduced finding",
        description="Newly introduced critical vulnerability",
        category="sast",
        severity="CRITICAL",
        confidence="CONFIRMED",
        file_path="new.py",
        start_line=1,
        end_line=2
    )
    db_session.add_all([f_shared_base, f_old, f_shared_curr, f_new])
    db_session.commit()

    res = client.get(
        f"/api/v1/audits/{curr_audit.id}/compare?base_audit_id={base_audit.id}",
        headers={"X-Session-ID": session_id}
    )
    assert res.status_code == 200
    data = res.json()
    assert data["summary"]["fixed_count"] == 1
    assert data["summary"]["new_count"] == 1
    assert data["summary"]["unchanged_count"] == 1
    assert data["fixed_findings"][0]["rule_id"] == "RULE-OLD"
    assert data["new_findings"][0]["rule_id"] == "RULE-NEW"
