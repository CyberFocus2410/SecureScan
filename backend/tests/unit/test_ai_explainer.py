"""Unit tests for AI explanation engine (schema validation & fallback)."""
import uuid
import pytest
from app.services.ai_explain import explain_finding, MockAIProvider
from app.models.models import AuditModel, RepositoryModel, FindingModel
from app.schemas.enums import Severity, Confidence, ScannerName


def test_ai_output_schema_rejection_falls_back(db_session):
    """
    Verify that if an AI provider returns invalid schema/malformed fields,
    the service rejects the response and falls back cleanly to the deterministic explanation.
    """
    unique_suffix = uuid.uuid4().hex[:8]
    repo = RepositoryModel(
        github_owner="org",
        github_repo=f"schema-test-{unique_suffix}",
        canonical_url=f"https://github.com/org/schema-{unique_suffix}",
        default_branch="main",
        last_commit_sha="11223344556677889900aabbccddeeff11223344"
    )
    db_session.add(repo)
    db_session.commit()

    audit = AuditModel(
        repository_id=repo.id,
        session_id="session-schema-test",
        commit_sha="11223344556677889900aabbccddeeff11223344",
        status="REPORT_READY",
        current_stage="REPORT_READY",
        scopes=["security"]
    )
    db_session.add(audit)
    db_session.commit()

    finding = FindingModel(
        audit_id=audit.id,
        fingerprint="fp-malformed-schema-test",
        scanner_name=ScannerName.SEMGREP.value,
        scanner_version="1.102.0",
        rule_id="python.security.sql-injection",
        title="SQL Injection vulnerability",
        description="SQL injection detected in database query",
        category="injection",
        severity=Severity.HIGH.value,
        confidence=Confidence.CONFIRMED.value,
        file_path="app/db.py",
        start_line=25,
        end_line=25,
        cwe_ids=["CWE-89"],
        owasp_refs=["A03:2025"],
        redacted_snippet="db.execute(f'SELECT * FROM users WHERE id = {user_id}')"
    )
    db_session.add(finding)
    db_session.commit()

    # Provider returns malformed schema
    provider = MockAIProvider(malformed_json=True)
    explanation = explain_finding(
        finding_id=finding.id,
        include_risk_context=True,
        provider=provider,
        db=db_session
    )

    # Must fall back to deterministic provider cleanly
    assert explanation.ai_generated is False
    assert explanation.provider == "deterministic_fallback"
    assert "SQL query constructed dynamically" in explanation.root_cause
    assert len(explanation.validation_steps) > 0


def test_ai_provider_down_graceful_fallback(db_session):
    """
    Verify that when AI provider throws network/API exception,
    the system logs the warning and returns deterministic fallback without crashing.
    """
    unique_suffix = uuid.uuid4().hex[:8]
    repo = RepositoryModel(
        github_owner="org",
        github_repo=f"provider-down-test-{unique_suffix}",
        canonical_url=f"https://github.com/org/provider-down-{unique_suffix}",
        default_branch="main",
        last_commit_sha="aabbccddeeff00112233445566778899aabbccdd"
    )
    db_session.add(repo)
    db_session.commit()

    audit = AuditModel(
        repository_id=repo.id,
        session_id="session-down-test",
        commit_sha="aabbccddeeff00112233445566778899aabbccdd",
        status="REPORT_READY",
        current_stage="REPORT_READY",
        scopes=["security"]
    )
    db_session.add(audit)
    db_session.commit()

    finding = FindingModel(
        audit_id=audit.id,
        fingerprint="fp-down-test",
        scanner_name=ScannerName.GITLEAKS.value,
        scanner_version="8.21.2",
        rule_id="aws-access-key",
        title="AWS Access Key Exposed",
        description="Plaintext AWS access key found in source code",
        category="secrets",
        severity=Severity.CRITICAL.value,
        confidence=Confidence.CONFIRMED.value,
        file_path="config.py",
        start_line=5,
        end_line=5,
        cwe_ids=["CWE-798"],
        owasp_refs=["A07:2025"],
        redacted_snippet="AWS_KEY = '[REDACTED:aws-token]'"
    )
    db_session.add(finding)
    db_session.commit()

    # Provider crashes
    provider = MockAIProvider(should_fail=True)
    explanation = explain_finding(
        finding_id=finding.id,
        include_risk_context=True,
        provider=provider,
        db=db_session
    )

    # Must fall back gracefully
    assert explanation.ai_generated is False
    assert explanation.provider == "deterministic_fallback"
    assert "Hardcoded secret" in explanation.root_cause
    assert len(explanation.validation_steps) >= 2
