"""Unit and integration tests for Step 5: Infrastructure, Docker, CI/CD, and Cloud Config (ADR-002, Step 5)."""
import uuid
from pathlib import Path
from sqlalchemy.orm import Session

from app.core.db import SessionLocal
from app.models.models import AuditModel, RepositoryModel, FindingModel, ControlResultModel, ToolRunModel
from app.schemas.enums import Severity, Confidence, ControlState
from app.scanners.iac_config import IacConfigScanner
from app.workers.audit_worker import execute_scan_pipeline

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
INSECURE_IAC_DIR = ROOT_DIR / "fixtures" / "insecure-iac"
CLEAN_IAC_DIR = ROOT_DIR / "fixtures" / "clean-iac"


def test_step5_dockerfile_and_compose_detectors():
    """Verify Dockerfile and Docker Compose detectors flag bad configs with remediation steps."""
    scanner = IacConfigScanner()
    res = scanner.execute(INSECURE_IAC_DIR, {})
    findings = res.raw_findings

    rule_ids = {f.rule_id for f in findings}

    # 1. Dockerfile Root user
    assert "iac-docker-root-user" in rule_ids
    root_finding = next(f for f in findings if f.rule_id == "iac-docker-root-user")
    assert root_finding.severity == Severity.HIGH
    assert "non-root" in root_finding.technical_fix.lower()

    # 2. Dockerfile Unpinned base image
    assert "iac-docker-unpinned-base-image" in rule_ids
    unpinned = next(f for f in findings if f.rule_id == "iac-docker-unpinned-base-image")
    assert unpinned.severity == Severity.MEDIUM
    assert "sha256" in unpinned.technical_fix.lower() or "version" in unpinned.technical_fix.lower()

    # 3. Dockerfile Secret in layer
    assert "iac-docker-secret-in-layer" in rule_ids
    secret_layer = next(f for f in findings if f.rule_id == "iac-docker-secret-in-layer")
    assert secret_layer.severity == Severity.CRITICAL
    assert "sk_live_test_insecure_secret_layer_12345" not in secret_layer.raw_snippet

    # 4. Compose Privileged mode
    assert "iac-compose-privileged-container" in rule_ids
    priv = next(f for f in findings if f.rule_id == "iac-compose-privileged-container")
    assert priv.severity == Severity.HIGH

    # 5. Compose Exposed DB port
    assert "iac-compose-exposed-db-port" in rule_ids
    exp_db = next(f for f in findings if f.rule_id == "iac-compose-exposed-db-port")
    assert exp_db.severity == Severity.HIGH
    assert "5432" in exp_db.description

    # 6. Compose Default credentials
    assert "iac-compose-default-credentials" in rule_ids
    creds = next(f for f in findings if f.rule_id == "iac-compose-default-credentials")
    assert creds.severity == Severity.HIGH


def test_step5_terraform_and_kubernetes_detectors():
    """Verify Terraform and Kubernetes detectors identify open security groups, public buckets, and wildcard IAM."""
    scanner = IacConfigScanner()
    res = scanner.execute(INSECURE_IAC_DIR, {})
    findings = res.raw_findings

    rule_ids = {f.rule_id for f in findings}

    # 1. Public S3 bucket
    assert "iac-tf-public-s3-bucket" in rule_ids
    pub_s3 = next(f for f in findings if f.rule_id == "iac-tf-public-s3-bucket")
    assert pub_s3.severity == Severity.CRITICAL
    assert "public_access_block" in pub_s3.technical_fix.lower()

    # 2. Open Security Group
    assert "iac-tf-open-security-group" in rule_ids
    sg = next(f for f in findings if f.rule_id == "iac-tf-open-security-group")
    assert sg.severity == Severity.HIGH
    assert "0.0.0.0/0" in sg.raw_snippet

    # 3. Wildcard IAM policy
    assert "iac-tf-wildcard-iam-policy" in rule_ids
    iam = next(f for f in findings if f.rule_id == "iac-tf-wildcard-iam-policy")
    assert iam.severity == Severity.HIGH

    # 4. Kubernetes privileged container and shared host network
    assert "iac-k8s-privileged-container" in rule_ids
    assert "iac-k8s-host-namespace-shared" in rule_ids


def test_step5_github_actions_ci_detectors():
    """Verify GitHub Actions detectors flag pull_request_target, script injection, and excessive permissions."""
    scanner = IacConfigScanner()
    res = scanner.execute(INSECURE_IAC_DIR, {})
    findings = res.raw_findings

    rule_ids = {f.rule_id for f in findings}

    # 1. pull_request_target misuse
    assert "ci-gha-pull-request-target-misuse" in rule_ids
    pr_target = next(f for f in findings if f.rule_id == "ci-gha-pull-request-target-misuse")
    assert pr_target.severity == Severity.HIGH

    # 2. Script injection via untrusted context
    assert "ci-gha-untrusted-script-injection" in rule_ids
    inj = next(f for f in findings if f.rule_id == "ci-gha-untrusted-script-injection")
    assert inj.severity == Severity.CRITICAL
    assert "environment variable" in inj.technical_fix.lower()

    # 3. Excessive permissions (write-all)
    assert "ci-gha-excessive-permissions-write-all" in rule_ids

    # 4. Unpinned third-party action
    assert "ci-gha-unpinned-third-party-action" in rule_ids
    unpinned = next(f for f in findings if f.rule_id == "ci-gha-unpinned-third-party-action")
    assert "actions/checkout@master" in unpinned.raw_snippet


def test_step5_cloud_paas_and_env_leak_detectors():
    """Verify Vercel, Firebase, and committed .env configurations are detected."""
    scanner = IacConfigScanner()
    res = scanner.execute(INSECURE_IAC_DIR, {})
    findings = res.raw_findings

    rule_ids = {f.rule_id for f in findings}

    # 1. Committed .env file
    assert "cloud-committed-env-file" in rule_ids
    env_finding = next(f for f in findings if f.rule_id == "cloud-committed-env-file")
    assert env_finding.severity == Severity.HIGH
    assert ".gitignore" in env_finding.technical_fix

    # 2. Vercel permissive CORS & debug rewrite
    assert "cloud-vercel-permissive-cors" in rule_ids
    assert "cloud-vercel-open-debug-rewrite" in rule_ids

    # 3. Firebase open security rules
    assert "cloud-firebase-open-security-rules" in rule_ids
    fb = next(f for f in findings if f.rule_id == "cloud-firebase-open-security-rules")
    assert fb.severity == Severity.CRITICAL


def test_step5_clean_fixtures_produce_pass_evidenced():
    """Verify clean fixtures produce zero critical/high findings and explicit PASS_EVIDENCED items."""
    scanner = IacConfigScanner()
    res = scanner.execute(CLEAN_IAC_DIR, {})
    findings = res.raw_findings
    passes = scanner.last_evidenced_passes

    # No Critical or High findings on clean configs
    crit_high = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    assert len(crit_high) == 0

    # Explicit PASS_EVIDENCED items exist
    assert len(passes) >= 4
    pass_checks = [p["check"] for p in passes]
    assert any("Non-Root" in c for c in pass_checks)
    assert any("Pinned Base" in c for c in pass_checks)
    assert any("S3" in c or "Encryption" in c for c in pass_checks)
    assert any("Hardened Permissions" in c for c in pass_checks)


def test_step5_end_to_end_worker_pipeline_with_iac():
    """Verify full scan pipeline processes IaC configurations and produces normalized findings."""
    session_id = str(uuid.uuid4())
    db = SessionLocal()

    try:
        repo_id = str(uuid.uuid4())
        repo = RepositoryModel(
            id=repo_id,
            github_owner="test-org",
            github_repo="insecure-iac",
            canonical_url=f"https://github.com/test-org/iac-{session_id[:8]}",
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

        execute_scan_pipeline(audit_id, worktree_dir=INSECURE_IAC_DIR)

        # 1. Audit status completed
        audit_db = db.query(AuditModel).filter(AuditModel.id == audit_id).first()
        assert audit_db.status in ("COMPLETED", "PARTIAL")

        # 2. ToolRun for iac_config recorded
        tool_runs = db.query(ToolRunModel).filter(ToolRunModel.audit_id == audit_id).all()
        tool_names = [tr.tool.lower() for tr in tool_runs]
        assert "iac_config" in tool_names

        # 3. Findings persisted with Section 6 fields
        findings = db.query(FindingModel).filter(FindingModel.audit_id == audit_id).all()
        assert len(findings) >= 5

        # Verify engine and tool mapping
        engines = {f.engine for f in findings if f.engine}
        assert any(e in ("iac", "container", "ci") for e in engines)

        # Verify control results link to IaC findings (e.g. SEC-024, SEC-028, SEC-002)
        ctrl_results = db.query(ControlResultModel).filter(ControlResultModel.audit_id == audit_id).all()
        sec_024 = next((c for c in ctrl_results if c.control_id == "SEC-024"), None)
        assert sec_024 is not None
        assert sec_024.state in (ControlState.POTENTIAL_GAP, ControlState.FAIL_EVIDENCED)

        sec_028 = next((c for c in ctrl_results if c.control_id == "SEC-028"), None)
        assert sec_028 is not None
        assert sec_028.state == ControlState.FAIL_EVIDENCED

    finally:
        db.close()
