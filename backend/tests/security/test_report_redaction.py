"""Security test: Secret-literal absence scan across generated PDF and JSON reports (AT-03)."""
import json
import uuid
import pytest
from app.reporting.json_export import generate_json_report
from app.reporting.pdf_export import generate_pdf_report
from app.core.security import assert_no_raw_secret, redact_text
from app.models.models import AuditModel, RepositoryModel, FindingModel, EvidenceModel
from app.schemas.enums import Severity, Confidence, ScannerName, EvidenceTier


def test_secret_literal_absence_in_pdf_and_json_reports(db_session):
    """
    AT-03: Verify that a secret literal found during a scan is redacted at the parser
    boundary and NEVER appears in the generated JSON export or PDF report bytes/text.
    """
    unique_suffix = uuid.uuid4().hex[:8]
    raw_secret_literal = "AKIAIMNO7V3WWDDEP7CQ"  # Authentic AWS key format

    repo = RepositoryModel(
        github_owner="org",
        github_repo=f"secret-repo-{unique_suffix}",
        canonical_url=f"https://github.com/org/secret-{unique_suffix}",
        default_branch="main",
        last_commit_sha="99887766554433221100aabbccddeeff99887766"
    )
    db_session.add(repo)
    db_session.commit()

    audit = AuditModel(
        repository_id=repo.id,
        session_id="session-redaction-report-test",
        commit_sha="99887766554433221100aabbccddeeff99887766",
        status="REPORT_READY",
        current_stage="REPORT_READY",
        scopes=["security"]
    )
    db_session.add(audit)
    db_session.commit()

    # The finding MUST only hold redacted snippets (rules.md §6)
    snippet_before_redaction = f'AWS_ACCESS_KEY_ID = "{raw_secret_literal}"'
    redacted_snippet = redact_text(snippet_before_redaction)

    assert raw_secret_literal not in redacted_snippet
    assert "[REDACTED:" in redacted_snippet

    finding = FindingModel(
        audit_id=audit.id,
        fingerprint="fp-secret-test-report",
        scanner_name=ScannerName.GITLEAKS.value,
        scanner_version="8.21.2",
        rule_id="aws-access-token",
        title="AWS Access Key exposed",
        description="AWS access key token detected in code",
        category="secrets",
        severity=Severity.CRITICAL.value,
        confidence=Confidence.CONFIRMED.value,
        file_path="backend/config.py",
        start_line=12,
        end_line=12,
        cwe_ids=["CWE-798"],
        owasp_refs=["A07:2025"],
        redacted_snippet=redacted_snippet,
        technical_fix="Revoke key in AWS IAM immediately.",
        validation_steps="Verify with Gitleaks."
    )
    db_session.add(finding)

    ev = EvidenceModel(
        audit_id=audit.id,
        finding_id=finding.id,
        tier=EvidenceTier.E1_SOURCE_CODE.value,
        path="backend/config.py",
        start_line=12,
        end_line=12,
        redacted_excerpt=redacted_snippet,
        provenance="gitleaks:8.21.2"
    )
    db_session.add(ev)
    db_session.commit()

    # 1. Check JSON report export
    json_export = generate_json_report(audit.id, db_session)
    # Strict assertion helper
    assert_no_raw_secret(json_export, raw_secret_literal)
    assert raw_secret_literal not in json_export
    assert "[REDACTED:aws-access-key]" in json_export

    # 2. Check PDF report export
    pdf_bytes = generate_pdf_report(audit.id, db_session)
    assert raw_secret_literal.encode("utf-8") not in pdf_bytes
    assert_no_raw_secret(pdf_bytes, raw_secret_literal)
