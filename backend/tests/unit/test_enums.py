"""Unit tests verifying enum completeness matching frozen contracts."""
from app.schemas.enums import (
    ControlState,
    Severity,
    Confidence,
    EvidenceTier,
    AuditStatus,
    EffectiveDateStatus,
    ScannerName
)


def test_control_state_enum_has_all_six_states():
    expected_states = {
        "PASS_EVIDENCED",
        "FAIL_EVIDENCED",
        "POTENTIAL_GAP",
        "NOT_VERIFIED",
        "NOT_APPLICABLE",
        "ERROR"
    }
    actual_states = {s.value for s in ControlState}
    assert actual_states == expected_states
    assert len(ControlState) == 6


def test_severity_enum_completeness():
    expected_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
    assert {s.value for s in Severity} == expected_severities
    assert len(Severity) == 5


def test_confidence_enum_completeness():
    expected_confidences = {"CONFIRMED", "HIGH", "MEDIUM", "LOW", "EXPERIMENTAL"}
    assert {c.value for c in Confidence} == expected_confidences
    assert len(Confidence) == 5


def test_evidence_tier_completeness():
    expected_tiers = {
        "E1_SOURCE_CODE",
        "E2_CONFIG_MANIFEST",
        "E3_SUPPLIED_DOCS",
        "E4_ORG_ATTESTATION",
        "E5_RUNTIME_TEST"
    }
    assert {t.value for t in EvidenceTier} == expected_tiers
    assert len(EvidenceTier) == 5


def test_audit_status_enum_completeness():
    expected_statuses = {
        "QUEUED",
        "IMPORTING",
        "SCANNING",
        "NORMALIZING",
        "SECURITY_MAPPING",
        "DPDP_MAPPING",
        "REPORT_READY",
        "COMPLETED",
        "PARTIAL",
        "FAILED"
    }
    assert {s.value for s in AuditStatus} == expected_statuses


def test_effective_date_status_enum():
    assert {s.value for s in EffectiveDateStatus} == {"IN_FORCE", "UPCOMING", "NOT_DETERMINED"}


def test_scanner_name_enum():
    assert {s.value for s in ScannerName} == {"semgrep", "gitleaks", "osv-scanner", "bandit", "custom"}

