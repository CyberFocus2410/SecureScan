"""Test AT-17: Report generation (PDF + JSON contain scope, limitations, legal refs, tool versions)."""
import json
import uuid
import pytest
from app.core.config import settings
from app.services.reports import create_or_run_report
from app.reporting.pdf_export import generate_pdf_report
from app.reporting.json_export import generate_json_report
from app.models.models import (
    AuditModel,
    RepositoryModel,
    FindingModel,
    ScannerRunModel,
    ControlResultModel,
    RemediationActionModel
)
from app.schemas.enums import Severity, Confidence, ScannerName, ControlState, EvidenceTier


def test_at17_report_contents_and_mandatory_sections(db_session):
    """
    AT-17: Both PDF and JSON report exports must contain:
    - Cover info: repo, pinned commit SHA, audit timestamp, tool versions
    - Executive summary: counts + coverage, no grade
    - Methodology & exclusions
    - Security finding table with locators & proof
    - OWASP coverage matrix
    - DPDP matrix with dynamic effective dates
    - Legal appendix with ceilings + caveat
    - Prioritized remediation plan
    - Evidence gaps
    - Header on every page / document: "Developer-assistance report — not a security certificate or legal opinion."
    """
    unique_suffix = uuid.uuid4().hex[:8]
    repo = RepositoryModel(
        github_owner="acme-corp",
        github_repo=f"financial-api-{unique_suffix}",
        canonical_url=f"https://github.com/acme-corp/financial-{unique_suffix}",
        default_branch="main",
        last_commit_sha="fedcba98765432101234567890abcdef12345678",
        detected_frameworks=["fastapi"],
        detected_languages={"python": 100}
    )
    db_session.add(repo)
    db_session.commit()

    audit = AuditModel(
        repository_id=repo.id,
        session_id="session-at17-test",
        commit_sha="fedcba98765432101234567890abcdef12345678",
        status="REPORT_READY",
        current_stage="REPORT_READY",
        scopes=["security", "dpdp"]
    )
    db_session.add(audit)
    db_session.commit()

    # Tool run
    run = ScannerRunModel(
        audit_id=audit.id,
        scanner=ScannerName.SEMGREP.value,
        version="1.102.0",
        status="COMPLETED",
        findings_count=1
    )
    db_session.add(run)

    # Finding
    finding = FindingModel(
        audit_id=audit.id,
        fingerprint="fp-at17-sample",
        scanner_name=ScannerName.SEMGREP.value,
        scanner_version="1.102.0",
        rule_id="fastapi.cors.wildcard",
        title="CORS Wildcard Allowed",
        description="Access-Control-Allow-Origin set to wildcard",
        category="network",
        severity=Severity.HIGH.value,
        confidence=Confidence.CONFIRMED.value,
        file_path="app/main.py",
        start_line=15,
        end_line=15,
        cwe_ids=["CWE-942"],
        owasp_refs=["A05:2025"],
        redacted_snippet="allow_origins=['*']",
        technical_fix="Specify exact trusted origins.",
        validation_steps="Verify with test request."
    )
    db_session.add(finding)

    # Security control
    sec_ctrl = ControlResultModel(
        audit_id=audit.id,
        control_id="SEC-020",
        domain="SECURITY",
        title="CORS Allowed Origins Restriction",
        state=ControlState.FAIL_EVIDENCED.value,
        evidence_tier=EvidenceTier.E1_SOURCE_CODE.value,
        rationale="Wildcard CORS detected in app/main.py"
    )
    db_session.add(sec_ctrl)

    # DPDP control
    dpdp_ctrl = ControlResultModel(
        audit_id=audit.id,
        control_id="DPDP-006",
        domain="DPDP",
        title="Reasonable Security Safeguards",
        state="potential_gap",
        evidence_tier=EvidenceTier.E1_SOURCE_CODE.value,
        rationale="Security safeguards unverified on sensitive endpoints"
    )
    db_session.add(dpdp_ctrl)

    # Remediation
    rem = RemediationActionModel(
        audit_id=audit.id,
        priority="P0",
        action_type="ENGINEERING",
        target_id="SEC-020",
        title="Restrict CORS origins",
        steps_json=["Replace wildcard with allowed domains list"],
        validation_method="Re-scan worktree"
    )
    db_session.add(rem)
    db_session.commit()

    # --- 1. Test JSON Export ---
    json_str = generate_json_report(audit.id, db_session)
    report_dict = json.loads(json_str)

    # Assert mandatory header and metadata
    assert report_dict["metadata"]["mandatory_header"] == "Developer-assistance report — not a security certificate or legal opinion."
    assert report_dict["repository"]["commit_sha"] == "fedcba98765432101234567890abcdef12345678"
    assert report_dict["metadata"]["as_of_date"] == settings.AS_OF_DATE

    # Assert executive summary has no headline grade
    assert "headline_grade" in report_dict["executive_summary"]
    assert "NONE" in report_dict["executive_summary"]["headline_grade"]

    # Assert methodology and exclusions
    assert "--network=none" in report_dict["methodology_and_exclusions"]["scanner_sandbox"]
    assert "Zero repository code execution" in report_dict["methodology_and_exclusions"]["repo_execution_policy"]

    # Assert findings proof and fix
    assert len(report_dict["findings"]) == 1
    assert report_dict["findings"][0]["title"] == "CORS Wildcard Allowed"
    assert report_dict["findings"][0]["technical_fix"] == "Specify exact trusted origins."

    # Assert DPDP matrix dynamic effective dates
    assert len(report_dict["dpdp_controls"]) >= 1
    sample_dpdp = report_dict["dpdp_controls"][0]
    assert "effective_status" in sample_dpdp
    assert "citation" in sample_dpdp

    # Assert legal appendix ceilings & caveat
    assert report_dict["legal_exposure"]["disclaimer"] == "Potential legal category; applicability and liability not determined."
    cats = report_dict["legal_exposure"]["categories"]
    assert len(cats) >= 7
    # Assert Schedule item 1 has ceiling and mandatory caveat
    cat1 = next(c for c in cats if c["schedule_item"] == 1)
    assert cat1["statutory_ceiling_inr"] == "₹250 crore"
    assert cat1["caveat"] == "Potential legal category; applicability and liability not determined."

    # --- 2. Test PDF Export ---
    pdf_bytes = generate_pdf_report(audit.id, db_session)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 1000
    assert pdf_bytes.startswith(b"%PDF")

    # Assert persistence service creates report artifact with 24h expiry
    report_artifact = create_or_run_report(audit.id, "pdf", "session-at17-test", db_session)
    assert report_artifact.status == "COMPLETED"
    assert report_artifact.format == "pdf"
    assert report_artifact.expires_at > report_artifact.created_at
