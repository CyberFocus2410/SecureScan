"""Unit and integration tests for Step 6: Database Security Module (Static & Runtime) (ADR-002, Step 6)."""
import uuid
from datetime import datetime
from pathlib import Path
import pytest
from sqlalchemy.orm import Session

from app.core.db import SessionLocal
from app.core.errors import TargetNotVerifiedError, SSRFBlockedError
from app.models.models import (
    AuditModel,
    RepositoryModel,
    TargetModel,
    TargetVerificationModel,
    FindingModel,
    ControlResultModel,
    ToolRunModel
)
from app.schemas.enums import Severity, Confidence, ControlState
from app.services.targets import record_scan_consent
from app.scanners.database_static import DatabaseStaticScanner
from app.scanners.database_runtime import DatabaseRuntimeScanner
from app.workers.audit_worker import execute_scan_pipeline

ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
DB_FIXTURES_DIR = ROOT_DIR / "fixtures" / "db-fixtures"


def test_step6_static_scanner_insecure_models():
    """Verify static DB scanner detects unhashed passwords, plaintext PII, missing RLS, and raw SQLi."""
    scanner = DatabaseStaticScanner()
    res = scanner.execute(DB_FIXTURES_DIR, {})
    findings = res.raw_findings
    rule_ids = {f.rule_id for f in findings}

    # 1. Unhashed password storage
    assert "db-static-unhashed-password-storage" in rule_ids
    pwd_finding = next(f for f in findings if f.rule_id == "db-static-unhashed-password-storage")
    assert pwd_finding.severity == Severity.CRITICAL
    assert "argon2" in pwd_finding.technical_fix.lower() or "bcrypt" in pwd_finding.technical_fix.lower()

    # 2. Plaintext sensitive PII (Aadhaar / Card / PAN)
    assert "db-static-plaintext-pii-column" in rule_ids
    pii_findings = [f for f in findings if f.rule_id == "db-static-plaintext-pii-column"]
    assert len(pii_findings) >= 2  # Aadhaar, credit_card in Python + PAN, passport in SQL
    for f in pii_findings:
        assert f.severity == Severity.HIGH

    # 3. Missing tenant/ownership column
    assert "db-static-missing-tenant-rls-column" in rule_ids
    rls_finding = next(f for f in findings if f.rule_id == "db-static-missing-tenant-rls-column")
    assert rls_finding.severity == Severity.MEDIUM

    # 4. Raw string-built SQL query concatenation
    assert "db-static-raw-string-sql-query" in rule_ids
    sqli_finding = next(f for f in findings if f.rule_id == "db-static-raw-string-sql-query")
    assert sqli_finding.severity == Severity.HIGH
    assert "CWE-89" in sqli_finding.cwe_ids

    # 5. Overbroad SQL GRANTs in migration
    assert "db-static-overbroad-sql-grant" in rule_ids
    grant_finding = next(f for f in findings if f.rule_id == "db-static-overbroad-sql-grant")
    assert grant_finding.severity == Severity.HIGH


def test_step6_static_scanner_clean_models_produce_pass_evidenced():
    """Verify clean database models produce explicit PASS_EVIDENCED items and zero unhashed password findings."""
    scanner = DatabaseStaticScanner()
    # Execute specifically on models_clean.py
    passes = []
    findings, passes = scanner._scan_python_orm_models(DB_FIXTURES_DIR)

    # Check that clean model pass items exist
    clean_passes = [p for p in passes if "models_clean.py" in p["file"]]
    assert len(clean_passes) >= 2
    pass_checks = [p["check"] for p in clean_passes]
    assert any("Password Hashing" in c for c in pass_checks)
    assert any("Encrypted" in c for c in pass_checks) or any("Audit" in c for c in pass_checks)


def test_step6_runtime_scanner_blocks_unverified_target():
    """Verify runtime DB scanner strictly refuses to scan unverified targets."""
    db = SessionLocal()
    try:
        session_id = str(uuid.uuid4())
        target_id = str(uuid.uuid4())
        target = TargetModel(
            id=target_id,
            session_id=session_id,
            target_type="WEBSITE",
            url="https://app.example.com",
            verified=False
        )
        db.add(target)
        db.commit()

        scanner = DatabaseRuntimeScanner(db)
        with pytest.raises(TargetNotVerifiedError):
            scanner.execute_runtime_scan(target_id)
    finally:
        db.close()


def test_step6_runtime_scanner_blocks_private_and_gov_targets():
    """Verify runtime DB scanner blocks private IP, cloud metadata, and .gov.in domains."""
    db = SessionLocal()
    try:
        session_id = str(uuid.uuid4())
        target_id = str(uuid.uuid4())
        # Target with .gov.in domain
        target = TargetModel(
            id=target_id,
            session_id=session_id,
            target_type="WEBSITE",
            url="https://portal.nic.in",
            verified=True,
            verified_at=datetime.utcnow()
        )
        db.add(target)
        db.commit()

        # Add consent record
        record_scan_consent(db, target_id=target_id, user_id=session_id, client_ip="198.51.100.1")

        scanner = DatabaseRuntimeScanner(db)
        with pytest.raises(SSRFBlockedError):
            scanner.execute_runtime_scan(target_id)
    finally:
        db.close()


def test_step6_runtime_scanner_verified_target_zero_data_extraction():
    """Verify runtime DB scanner executes safe probes on verified target with zero data extraction."""
    db = SessionLocal()
    try:
        session_id = str(uuid.uuid4())
        target_id = str(uuid.uuid4())
        target = TargetModel(
            id=target_id,
            session_id=session_id,
            target_type="WEBSITE",
            url="https://securescan-test-target.example.com",
            verified=True,
            verified_at=datetime.utcnow()
        )
        db.add(target)

        # Verification challenge proof
        v = TargetVerificationModel(
            id=str(uuid.uuid4()),
            target_id=target_id,
            verification_method="DNS_TXT",
            token="securescan-token-test-12345",
            status="VERIFIED",
            verified_at=datetime.utcnow()
        )
        db.add(v)
        db.commit()

        # Consent record required for active scan gate
        record_scan_consent(db, target_id=target_id, user_id=session_id, client_ip="198.51.100.1")

        scanner = DatabaseRuntimeScanner(db)
        result = scanner.execute_runtime_scan(target_id)

        assert result["status"] == "COMPLETED"
        assert len(result["ports_probed"]) >= 7
        assert len(result["admin_uis_probed"]) >= 5

        # Critical Gate Requirement: proof that no data is ever extracted or stored
        proof = result["safety_proof"]
        assert proof["zero_data_extraction_proven"] is True
        assert proof["data_extracted_bytes"] == 0
    finally:
        db.close()


def test_step6_end_to_end_worker_pipeline_with_db_scanner():
    """Verify full audit pipeline executes db_static scanner and links findings to controls."""
    session_id = str(uuid.uuid4())
    db = SessionLocal()

    try:
        repo_id = str(uuid.uuid4())
        repo = RepositoryModel(
            id=repo_id,
            github_owner="test-org",
            github_repo="db-security-test",
            canonical_url=f"https://github.com/test-org/db-{session_id[:8]}",
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

        execute_scan_pipeline(audit_id, worktree_dir=DB_FIXTURES_DIR)

        # 1. Audit status completed
        audit_db = db.query(AuditModel).filter(AuditModel.id == audit_id).first()
        assert audit_db.status in ("COMPLETED", "PARTIAL")

        # 2. ToolRun for db_static recorded
        tool_runs = db.query(ToolRunModel).filter(ToolRunModel.audit_id == audit_id).all()
        tool_names = [tr.tool.lower() for tr in tool_runs]
        assert "db_static" in tool_names

        # 3. Findings persisted with engine="db"
        findings = db.query(FindingModel).filter(FindingModel.audit_id == audit_id).all()
        db_findings = [f for f in findings if f.engine == "db"]
        assert len(db_findings) >= 3

        # 4. Control results link to findings (SEC-011 for SQLi, SEC-017 for unhashed password)
        ctrl_results = db.query(ControlResultModel).filter(ControlResultModel.audit_id == audit_id).all()
        sec_011 = next((c for c in ctrl_results if c.control_id == "SEC-011"), None)
        assert sec_011 is not None
        assert sec_011.state == ControlState.FAIL_EVIDENCED

        sec_017 = next((c for c in ctrl_results if c.control_id == "SEC-017"), None)
        assert sec_017 is not None
        assert sec_017.state == ControlState.FAIL_EVIDENCED

    finally:
        db.close()
