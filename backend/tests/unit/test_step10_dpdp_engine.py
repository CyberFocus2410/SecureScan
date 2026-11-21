"""Unit tests for Step 10: DPDP Act 2023 Privacy & Compliance Engine."""
from datetime import date
from pathlib import Path
import pytest

from app.dpdp.pii_detector import PiiDetector, validate_verhoeff, validate_luhn
from app.dpdp.processor_inventory import ProcessorInventoryScanner
from app.dpdp.consent_policy_audit import ConsentPolicyAuditor
from app.dpdp.retention_erasure import RetentionErasureAuditor
from app.dpdp.readiness import DpdpReadinessEngine, MANDATORY_PENALTY_CAVEAT
from app.dpdp.commencement import compute_effective_date_status
from app.schemas.enums import EffectiveDateStatus


FIXTURES_DIR = Path(__file__).parent.parent.parent.parent / "fixtures" / "dpdp-fixtures"
SDK_REPO_DIR = FIXTURES_DIR / "sdks_repo"


def test_verhoeff_and_pii_checksum_validation():
    """Validates that mathematical checksums identify valid Aadhaar/PAN/GSTIN and reject invalid candidates."""
    # 1. Aadhaar Verhoeff Checksum
    valid_aadhaar = "234567890124"
    invalid_aadhaar_sum = "234567890125"
    invalid_aadhaar_zero = "012345678901"

    assert validate_verhoeff(valid_aadhaar) is True
    assert validate_verhoeff(invalid_aadhaar_sum) is False
    assert validate_verhoeff(invalid_aadhaar_zero) is False

    # 2. Luhn Checksum for Card numbers
    assert validate_luhn("4532015112830366") is True
    assert validate_luhn("4532015112830367") is False

    # 3. PiiDetector finds valid identifiers and masks them
    sample_text = f"""
    User details:
    Aadhaar: {valid_aadhaar}
    Fake Aadhaar: {invalid_aadhaar_sum}
    PAN: ABCPE1234F
    GSTIN: 27ABCPE1234F1Z5
    IFSC: HDFC0001234
    UPI: merchant@okhdfcbank
    Phone: +91-9876543210
    Health: biopsy results and prescription
    """
    detected = PiiDetector.scan_text(sample_text, file_path="users/profile.py")

    types_found = [d["identifier_type"] for d in detected]
    assert "Aadhaar" in types_found
    assert "PAN" in types_found
    assert "GSTIN" in types_found
    assert "IFSC" in types_found
    assert "UPI ID" in types_found
    assert "Indian Phone" in types_found
    assert "Health Data" in types_found

    # Verify zero raw Aadhaar leak (redacted/masked)
    for d in detected:
        if d["identifier_type"] == "Aadhaar":
            assert valid_aadhaar not in d["masked_value"]
            assert d["masked_value"] == "XXXX-XXXX-0124"


def test_processor_inventory_detection():
    """Validates third-party SDK and data processor discovery and cross-border risk tagging."""
    processors = ProcessorInventoryScanner.scan_worktree(SDK_REPO_DIR)
    proc_names = [p.name for p in processors]

    assert "Razorpay" in proc_names
    assert "Amazon Web Services (AWS)" in proc_names
    assert "Mixpanel" in proc_names
    assert "OpenAI" in proc_names

    # Verify cross-border risk tagging
    rzp = next(p for p in processors if p.name == "Razorpay")
    assert rzp.cross_border_risk is False
    assert rzp.country == "India"

    openai_proc = next(p for p in processors if p.name == "OpenAI")
    assert openai_proc.cross_border_risk is True
    assert openai_proc.country == "United States"


def test_consent_and_grievance_policy_audit():
    """Audits notice transparency, grievance officer publication, and consent UI dark patterns."""
    report = ConsentPolicyAuditor.audit_worktree(SDK_REPO_DIR)

    # 1. Notice & Grievance Officer details
    assert report.notice_transparency.privacy_policy_found is True
    assert report.grievance_officer.detected is True
    assert report.grievance_officer.email_contact == "grievance@securescan-test.in"
    assert report.grievance_officer.postal_address_present is True
    assert report.notice_transparency.board_complaint_mechanism_mentioned is True

    # 2. Consent UI Dark Pattern (pre-ticked checkbox in Signup.tsx)
    assert report.consent_ui.pre_ticked_checkboxes_detected >= 1
    assert any(f["rule_id"] == "dpdp-consent-pre-ticked-checkbox" for f in report.findings)


def test_retention_and_erasure_audit():
    """Audits storage limitation, automated retention cleanup, and user erasure routes."""
    report = RetentionErasureAuditor.audit_worktree(SDK_REPO_DIR)

    assert len(report.personal_data_models) >= 1
    user_model = report.personal_data_models[0]
    assert user_model.model_name == "UserModel"
    assert user_model.has_soft_delete is True

    # Erasure route in api.py is detected
    assert report.erasure_api_found is True
    assert report.export_portability_api_found is True


def test_phased_commencement_at_three_dates():
    """Tests dynamic statutory commencement status at three distinct time horizons."""
    # Date 1: Prior to Phase 1 (e.g. October 2025)
    st1, _, _ = compute_effective_date_status("Rule 1", as_of_date=date(2025, 10, 1))
    assert st1 == EffectiveDateStatus.UPCOMING

    # Date 2: Phase 2 Active, Phase 3 Upcoming (e.g. 14 November 2026)
    st2_p1, _, _ = compute_effective_date_status("Rule 1", as_of_date=date(2026, 11, 14))
    st2_p2, _, _ = compute_effective_date_status("Rule 4", as_of_date=date(2026, 11, 14))
    st2_p3, _, _ = compute_effective_date_status("Section 8(5)", as_of_date=date(2026, 11, 14))

    assert st2_p1 == EffectiveDateStatus.IN_FORCE
    assert st2_p2 == EffectiveDateStatus.IN_FORCE
    assert st2_p3 == EffectiveDateStatus.UPCOMING

    # Date 3: All Phases Active (e.g. June 2027)
    st3_p3, _, _ = compute_effective_date_status("Section 8(5)", as_of_date=date(2027, 6, 1))
    assert st3_p3 == EffectiveDateStatus.IN_FORCE


def test_dpdp_readiness_engine_and_hard_cap_rule():
    """Tests comprehensive readiness evaluation, scoring, hard-cap rule, and penalty ceilings."""
    # 1. Clean run without security findings
    clean_result = DpdpReadinessEngine.evaluate(
        worktree_dir=SDK_REPO_DIR,
        security_findings=[],
        as_of_date=date(2026, 11, 14),
    )

    assert len(clean_result["controls"]) == 18
    assert clean_result["hard_cap_applied"] is False
    assert clean_result["penalty_caveat"] == MANDATORY_PENALTY_CAVEAT
    assert len(clean_result["statutory_penalties"]) == 7
    assert len(clean_result["legal_review_pending"]) >= 1

    # 2. Run with a critical security finding (breaches Section 8(5)) -> triggers Hard Cap at 60
    security_findings = [{
        "title": "SQL Injection in User Authentication",
        "severity": "CRITICAL",
        "priority": "P0",
        "file_path": "backend/auth.py",
    }]
    capped_result = DpdpReadinessEngine.evaluate(
        worktree_dir=SDK_REPO_DIR,
        security_findings=security_findings,
        as_of_date=date(2026, 11, 14),
    )

    assert capped_result["hard_cap_applied"] is True
    assert capped_result["readiness_score"] <= 60
    assert any(m["impacted_dpdp_control"] in ("DPDP-006", "DPDP-018") for m in capped_result["technical_findings_mapped"])


def test_no_forbidden_compliant_strings_in_dpdp_engine_output():
    """Repo-wide contract: Engine never outputs 'compliant' or 'non-compliant' verdicts."""
    result = DpdpReadinessEngine.evaluate(
        worktree_dir=SDK_REPO_DIR,
        security_findings=[],
        as_of_date=date(2026, 11, 14),
    )

    # Check controls statuses
    for ctrl in result["controls"]:
        status = ctrl["status"].lower()
        assert "non-compliant" not in status
        assert status != "compliant"

    # Check categories
    for cat_name, cat in result["categories"].items():
        assert "compliant" not in cat_name.lower()
