"""Test AT-20: SHA consistency across Security and DPDP audits and generated reports."""
import json
import uuid
import pytest
from app.reporting.collector import collect_audit_report_data
from app.models.models import AuditModel, RepositoryModel, FindingModel, ControlResultModel
from app.schemas.enums import Severity, Confidence, ScannerName, ControlState, EvidenceTier


def test_at20_pinned_sha_consistency(db_session):
    """
    AT-20: Security and DPDP assessments and all report artifacts must bind
    to the identical pinned commit SHA without divergence or re-fetch.
    """
    unique_suffix = uuid.uuid4().hex[:8]
    expected_sha = "0123456789abcdef0123456789abcdef01234567"
    repo = RepositoryModel(
        github_owner="org",
        github_repo=f"consistent-repo-{unique_suffix}",
        canonical_url=f"https://github.com/org/consistent-{unique_suffix}",
        default_branch="main",
        last_commit_sha=expected_sha,
        detected_languages={"python": 100},
        detected_frameworks=["fastapi"]
    )
    db_session.add(repo)
    db_session.commit()

    audit = AuditModel(
        repository_id=repo.id,
        session_id="session-at20-test",
        commit_sha=expected_sha,
        status="REPORT_READY",
        current_stage="REPORT_READY",
        scopes=["security", "dpdp"]
    )
    db_session.add(audit)
    db_session.commit()

    # Security finding
    f = FindingModel(
        audit_id=audit.id,
        fingerprint="fp-at20-check",
        scanner_name=ScannerName.BANDIT.value,
        scanner_version="1.8.0",
        rule_id="B101",
        title="Assert used",
        description="Assert statement used in production",
        category="security",
        severity=Severity.LOW.value,
        confidence=Confidence.CONFIRMED.value,
        file_path="app/test.py",
        start_line=10,
        end_line=10,
        cwe_ids=["CWE-703"],
        owasp_refs=["A10:2025"]
    )
    db_session.add(f)

    # DPDP control result
    dpdp = ControlResultModel(
        audit_id=audit.id,
        control_id="DPDP-001",
        title="Notice Requirement",
        domain="DPDP",
        state="potential_gap",
        evidence_tier=EvidenceTier.E1_SOURCE_CODE.value,
        rationale="Notice check pending"
    )
    db_session.add(dpdp)
    db_session.commit()

    # Collect report data
    report_data = collect_audit_report_data(audit.id, db_session)

    # Assert repository SHA is exactly the expected SHA
    assert report_data["repository"]["commit_sha"] == expected_sha

    # Verify database model linkage
    fresh_audit = db_session.query(AuditModel).filter(AuditModel.id == audit.id).first()
    assert fresh_audit.commit_sha == expected_sha
    assert fresh_audit.repository.last_commit_sha == expected_sha
