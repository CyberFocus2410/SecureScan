"""Unit tests for Pydantic v2 schemas: valid and invalid validation."""
import uuid
import pytest
from pydantic import ValidationError
from app.schemas.enums import Severity, Confidence, ControlState, EvidenceTier, ScannerName, AuditStatus
from app.schemas.finding import Finding, FindingCreate, FindingRemediation
from app.schemas.evidence import Evidence, EvidenceCreate
from app.schemas.control import ControlResult, ControlResultCreate, StatutoryRef
from app.schemas.scanner_run import ScannerRun, ScannerRunCreate
from app.schemas.audit import Audit, Repository
from app.schemas.remediation import RemediationAction
from app.schemas.error import ErrorResponse, ErrorDetail


def test_evidence_schema_valid():
    aid = uuid.uuid4()
    ev = Evidence(
        audit_id=aid,
        tier=EvidenceTier.E1_SOURCE_CODE,
        path="backend/main.py",
        start_line=10,
        end_line=12,
        redacted_excerpt="api_key = '[REDACTED:secret]'",
        provenance="gitleaks:v8.21.2"
    )
    assert ev.tier == EvidenceTier.E1_SOURCE_CODE
    assert "[REDACTED:secret]" in ev.redacted_excerpt
    assert ev.audit_id == aid


def test_evidence_schema_invalid():
    # Missing required tier and redacted_excerpt
    with pytest.raises(ValidationError):
        Evidence.model_validate({
            "audit_id": str(uuid.uuid4()),
            "path": "backend/main.py"
        })


def test_finding_schema_valid():
    aid = uuid.uuid4()
    fid = uuid.uuid4()
    f = Finding(
        id=fid,
        audit_id=aid,
        fingerprint="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        scanner_name=ScannerName.SEMGREP,
        scanner_version="1.102.0",
        rule_id="python.lang.security.injection",
        title="SQL Injection Detected",
        description="Unsafe query format string",
        category="injection",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        file_path="app/api.py",
        start_line=45,
        end_line=45,
        cwe_ids=["CWE-89"],
        owasp_refs=["A05:2025"],
        remediation=FindingRemediation(
            technical_fix="Use parameterized queries",
            validation_steps="Run automated test suite"
        )
    )
    assert f.severity == Severity.HIGH
    assert f.confidence == Confidence.CONFIRMED
    assert f.rule_id == "python.lang.security.injection"


def test_finding_schema_invalid_severity():
    with pytest.raises(ValidationError):
        Finding.model_validate({
            "audit_id": str(uuid.uuid4()),
            "fingerprint": "12345",
            "scanner_name": "semgrep",
            "scanner_version": "1.0",
            "rule_id": "rule-1",
            "title": "Title",
            "description": "Desc",
            "category": "secrets",
            "severity": "SUPER_CRITICAL",  # invalid severity
            "confidence": "CONFIRMED",
            "file_path": "test.py",
            "start_line": 1,
            "end_line": 1
        })


def test_control_result_schema_valid():
    aid = uuid.uuid4()
    c = ControlResult(
        audit_id=aid,
        control_id="SEC-005",
        domain="SECURITY",
        title="API Rate Limiting",
        state=ControlState.POTENTIAL_GAP,
        rationale="No limiter in app code",
        evidence_tier=EvidenceTier.E1_SOURCE_CODE,
        statutory_ref=StatutoryRef(
            source_doc="DPDP Act 2023",
            clause="Section 8(5)",
            schedule_item=1,
            statutory_ceiling="Up to ₹250 crore"
        )
    )
    assert c.state == ControlState.POTENTIAL_GAP
    assert c.statutory_ref.statutory_ceiling == "Up to ₹250 crore"
    assert "applicability and liability not determined" in c.statutory_ref.mandatory_caveat


def test_control_result_invalid_state():
    with pytest.raises(ValidationError):
        ControlResult.model_validate({
            "audit_id": str(uuid.uuid4()),
            "control_id": "SEC-001",
            "domain": "SECURITY",
            "title": "Test",
            "state": "PASSED_WITH_WARNINGS",  # Invalid state
            "rationale": "Reason"
        })


def test_scanner_run_schema():
    sr = ScannerRun(
        audit_id=uuid.uuid4(),
        scanner=ScannerName.GITLEAKS,
        version="8.21.2",
        status="COMPLETED",
        duration_ms=1200,
        findings_count=3
    )
    assert sr.findings_count == 3
    assert sr.scanner == ScannerName.GITLEAKS


def test_error_response_schema():
    err = ErrorResponse(
        error=ErrorDetail(
            code="ERR_INVALID_REPO_URL",
            message="Only GitHub URLs are accepted",
            details={"submitted_url": "ftp://bad-url"}
        )
    )
    assert err.error.code == "ERR_INVALID_REPO_URL"

