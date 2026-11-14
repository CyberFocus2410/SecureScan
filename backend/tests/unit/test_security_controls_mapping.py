"""Unit tests for security control definitions and OWASP mappings completeness."""
from app.services.policy_loader import get_policy_bundle
from app.services.security_controls import calculate_security_coverage
from app.models.models import ControlResultModel


def test_all_32_security_controls_have_valid_mappings():
    bundle = get_policy_bundle()
    controls = bundle.security_controls.controls
    mappings = bundle.owasp_mappings.mappings

    assert len(controls) == 32, f"Expected 32 controls, found {len(controls)}"

    mapped_control_ids = {m.internal_control_id for m in mappings}

    for c in controls:
        # Every control must have at least one mapping or explicitly documented rationale
        assert c.id in mapped_control_ids or c.owasp_refs, f"Control {c.id} has no mapped external references!"
        assert c.evidence_class in ("S", "D", "O"), f"Control {c.id} invalid evidence class: {c.evidence_class}"
        assert c.mvp_priority in ("P0", "P1", "P2"), f"Control {c.id} invalid priority: {c.mvp_priority}"


def test_coverage_calculation_denominator():
    # Mock control results
    controls = [
        ControlResultModel(id="1", audit_id="a", control_id="SEC-001", domain="SECURITY", state="PASS_EVIDENCED"),
        ControlResultModel(id="2", audit_id="a", control_id="SEC-002", domain="SECURITY", state="FAIL_EVIDENCED"),
        ControlResultModel(id="3", audit_id="a", control_id="SEC-003", domain="SECURITY", state="POTENTIAL_GAP"),
        ControlResultModel(id="4", audit_id="a", control_id="SEC-004", domain="SECURITY", state="NOT_VERIFIED"),
        ControlResultModel(id="5", audit_id="a", control_id="SEC-005", domain="SECURITY", state="NOT_APPLICABLE"),
    ]

    summary = calculate_security_coverage(controls)
    assert summary.total_controls == 5
    assert summary.applicable_controls == 4  # 5 - 1 NA
    assert summary.evidenced_controls == 2   # 1 PASS + 1 FAIL
    assert summary.coverage_ratio == 0.5     # 2 / 4 = 0.5
    assert summary.not_applicable_count == 1
