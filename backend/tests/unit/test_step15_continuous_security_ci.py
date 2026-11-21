"""Unit and integration tests for Step 15 — Continuous Security, Scheduled Re-scans & CI Gate."""
import uuid
from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.db import SessionLocal
from app.models.models import AuditModel, FindingModel, RepositoryModel
from app.services.webhooks import WebhookService
from app.services.scheduler import ScheduledScanService
from app.services.github_pr_comment import GitHubPrCommentGenerator
from app.cli.ci_gate import CiGateEvaluator


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def test_finding_lifecycle_status_transitions(client, db_session):
    """Test updating finding status: open -> accepted-risk / false-positive with reason and validation."""
    session_id = str(uuid.uuid4())
    repo = RepositoryModel(
        id=str(uuid.uuid4()),
        canonical_url=f"https://github.com/org/repo-lifecycle-{uuid.uuid4()}",
        github_owner="org",
        github_repo="repo-lifecycle"
    )
    db_session.add(repo)
    db_session.commit()

    audit = AuditModel(
        id=str(uuid.uuid4()),
        repository_id=repo.id,
        commit_sha="abc12345",
        session_id=session_id,
        status="COMPLETED"
    )
    db_session.add(audit)
    db_session.commit()

    finding = FindingModel(
        id=str(uuid.uuid4()),
        audit_id=audit.id,
        fingerprint=f"fp-lifecycle-{uuid.uuid4()}",
        scanner_name="custom",
        scanner_version="1.0.0",
        rule_id="RULE_TEST_01",
        title="Test Flaw",
        description="Testing lifecycle transitions",
        category="injection",
        severity="HIGH",
        confidence="HIGH",
        priority="P1",
        file_path="app/views.py",
        start_line=10,
        end_line=12,
        status="open"
    )
    db_session.add(finding)
    db_session.commit()

    headers = {"X-Session-ID": session_id}

    # 1. Transition to accepted-risk without reason -> should fail with 422
    resp_fail = client.patch(
        f"/api/v1/findings/{finding.id}/status",
        headers=headers,
        json={"status": "accepted-risk", "reason": ""}
    )
    assert resp_fail.status_code == 422
    body = resp_fail.json()
    error_msg = body.get("error", {}).get("message") or str(body)
    assert "requires a justification reason" in error_msg

    # 2. Transition to invalid state -> should fail with 422
    resp_invalid = client.patch(
        f"/api/v1/findings/{finding.id}/status",
        headers=headers,
        json={"status": "not-a-valid-status"}
    )
    assert resp_invalid.status_code == 422

    # 3. Valid transition to accepted-risk with reason and expiry
    future_expiry = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    resp_ok = client.patch(
        f"/api/v1/findings/{finding.id}/status",
        headers=headers,
        json={
            "status": "accepted-risk",
            "reason": "Compensating firewall rule WAF-982 in place",
            "expires_at": future_expiry
        }
    )
    assert resp_ok.status_code == 200
    data = resp_ok.json()
    assert data["status"] == "accepted-risk"
    assert data["status_reason"] == "Compensating firewall rule WAF-982 in place"
    assert data["status_expires_at"] is not None


def test_scheduled_scan_change_detection_gate(db_session):
    """Step 15 Gate: Scheduled scan detects a newly introduced issue and reports it as 'new' in comparison."""
    session_id = str(uuid.uuid4())
    repo = RepositoryModel(
        id=str(uuid.uuid4()),
        canonical_url=f"https://github.com/org/repo-rescan-{uuid.uuid4()}",
        github_owner="org",
        github_repo="repo-rescan"
    )
    db_session.add(repo)
    db_session.commit()

    # Baseline audit with 1 finding
    audit_baseline = AuditModel(
        id=str(uuid.uuid4()),
        repository_id=repo.id,
        commit_sha="base1111",
        session_id=session_id,
        status="COMPLETED"
    )
    db_session.add(audit_baseline)
    db_session.commit()

    fp_existing = f"fp-existing-{uuid.uuid4()}"
    f_baseline = FindingModel(
        id=str(uuid.uuid4()),
        audit_id=audit_baseline.id,
        fingerprint=fp_existing,
        scanner_name="custom",
        scanner_version="1.0.0",
        rule_id="SEC_01",
        title="Existing Vulnerability",
        description="Found in baseline",
        category="injection",
        severity="HIGH",
        confidence="HIGH",
        priority="P1",
        file_path="app/api.py",
        start_line=15,
        end_line=18,
        status="open"
    )
    db_session.add(f_baseline)
    db_session.commit()

    # Scheduled re-scan audit (current) with existing finding + newly introduced flaw
    audit_current = AuditModel(
        id=str(uuid.uuid4()),
        repository_id=repo.id,
        commit_sha="current222",
        session_id=session_id,
        status="COMPLETED"
    )
    db_session.add(audit_current)
    db_session.commit()

    f_current_existing = FindingModel(
        id=str(uuid.uuid4()),
        audit_id=audit_current.id,
        fingerprint=fp_existing,
        scanner_name="custom",
        scanner_version="1.0.0",
        rule_id="SEC_01",
        title="Existing Vulnerability",
        description="Still present",
        category="injection",
        severity="HIGH",
        confidence="HIGH",
        priority="P1",
        file_path="app/api.py",
        start_line=15,
        end_line=18,
        status="open"
    )
    fp_new = f"fp-newly-introduced-{uuid.uuid4()}"
    f_current_new = FindingModel(
        id=str(uuid.uuid4()),
        audit_id=audit_current.id,
        fingerprint=fp_new,
        scanner_name="custom",
        scanner_version="1.0.0",
        rule_id="SEC_02_NEW_EXPLOIT",
        title="Newly Introduced BOLA Flaw",
        description="Freshly committed vulnerability in Lab",
        category="api",
        severity="CRITICAL",
        confidence="CONFIRMED",
        priority="P0",
        file_path="app/orders.py",
        start_line=45,
        end_line=50,
        status="open"
    )
    db_session.add_all([f_current_existing, f_current_new])
    db_session.commit()

    # Execute change detection
    result = ScheduledScanService.execute_scheduled_change_detection(
        current_audit_id=audit_current.id,
        baseline_audit_id=audit_baseline.id,
        target_id=repo.id,
        db=db_session
    )

    # Verify Gate: reports the newly introduced issue as "new"
    assert result.has_new_issues is True
    assert len(result.new_findings) == 1
    assert result.new_findings[0]["fingerprint"] == fp_new
    assert result.new_findings[0]["rule_id"] == "SEC_02_NEW_EXPLOIT"
    assert result.new_findings[0]["priority"] == "P0"
    assert len(result.unchanged_findings) == 1
    assert result.unchanged_findings[0]["fingerprint"] == fp_existing
    assert len(result.fixed_findings) == 0


def test_hmac_webhook_signing_and_verification():
    """Verify cryptographic HMAC-SHA256 webhook signatures and tampering detection."""
    secret = "test-cryptographic-secret-xyz123"
    payload = b'{"event":"audit.completed","target":"web-app","findings_count":4}'

    # Compute signature
    sig = WebhookService.compute_signature(payload, secret=secret)
    assert sig.startswith("sha256=")

    # Verify authentic payload
    assert WebhookService.verify_signature(payload, sig, secret=secret) is True

    # Verify tampered payload fails
    tampered_payload = b'{"event":"audit.completed","target":"web-app","findings_count":0}'
    assert WebhookService.verify_signature(tampered_payload, sig, secret=secret) is False

    # Verify wrong secret fails
    assert WebhookService.verify_signature(payload, sig, secret="wrong-secret") is False

    # Verify malformed header fails
    assert WebhookService.verify_signature(payload, "invalid_header", secret=secret) is False


def test_ci_gate_evaluator_pass_fail(db_session):
    """Test CI gate logic across P0-P3 thresholds, including accepted-risk handling."""
    session_id = str(uuid.uuid4())
    repo = RepositoryModel(
        id=str(uuid.uuid4()),
        canonical_url=f"https://github.com/org/repo-ci-{uuid.uuid4()}",
        github_owner="org",
        github_repo="repo-ci"
    )
    db_session.add(repo)
    db_session.commit()

    audit = AuditModel(
        id=str(uuid.uuid4()),
        repository_id=repo.id,
        commit_sha="ci111111",
        session_id=session_id,
        status="COMPLETED"
    )
    db_session.add(audit)
    db_session.commit()

    f_p0 = FindingModel(
        id=str(uuid.uuid4()),
        audit_id=audit.id,
        fingerprint=f"fp-p0-{uuid.uuid4()}",
        scanner_name="custom",
        scanner_version="1.0.0",
        rule_id="EMERGENCY_RCE",
        title="Remote Code Execution",
        description="P0 flaw",
        category="injection",
        severity="CRITICAL",
        confidence="CONFIRMED",
        priority="P0",
        file_path="app/exec.py",
        start_line=20,
        end_line=22,
        status="open"
    )
    db_session.add(f_p0)
    db_session.commit()

    # 1. Evaluating with --fail-on P0 -> MUST FAIL
    res_fail = CiGateEvaluator.evaluate(audit_id=audit.id, fail_on="P0", db=db_session)
    assert res_fail["passed"] is False
    assert res_fail["p_counts"]["P0"] == 1

    # 2. Accept the risk with valid future expiry
    f_p0.status = "accepted-risk"
    f_p0.status_reason = "Isolated behind private VPC with mTLS"
    f_p0.status_expires_at = datetime.now(timezone.utc) + timedelta(days=90)
    db_session.commit()

    # Evaluating again with --fail-on P0 -> MUST PASS now that risk is formally accepted!
    res_pass = CiGateEvaluator.evaluate(audit_id=audit.id, fail_on="P0", db=db_session)
    assert res_pass["passed"] is True
    assert res_pass["p_counts"]["P0"] == 0

    # 3. Test GitHub PR comment generation
    comment = GitHubPrCommentGenerator.generate_comment(
        audit_id=audit.id,
        gate_passed=True,
        fail_on_threshold="P0",
        findings=res_pass["active_findings"],
        dpdp_score=78,
        commit_sha="ci111111"
    )
    assert "✅ **SECURESCAN CI GATE: PASSED**" in comment
    assert "DPDP Readiness Score" in comment
    assert "Developer-assistance report" in comment
