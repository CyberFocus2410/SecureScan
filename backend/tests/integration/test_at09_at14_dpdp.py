"""Acceptance tests for M4: AT-09 through AT-14 (DPDP & Legal Exposure)."""
import uuid
from datetime import date
from pathlib import Path
from fastapi.testclient import TestClient

from app.main import app
from app.core.db import SessionLocal
from app.models.models import AuditModel, RepositoryModel
from app.workers.audit_worker import execute_scan_pipeline
from app.dpdp.commencement import compute_effective_date_status
from app.dpdp.applicability import evaluate_dpdp_applicability
from app.dpdp.evidence import extract_data_flows_from_worktree
from app.schemas.enums import EffectiveDateStatus
from app.services.policy_loader import get_policy_bundle

client = TestClient(app)
ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent
VULN_PYTHON_DIR = ROOT_DIR / "fixtures" / "vulnerable-python-api"


# -----------------------------------------------------------------------------
# AT-09: Candidate personal data asset & data-flow extraction
# -----------------------------------------------------------------------------
def test_at09_candidate_personal_data_extraction_unknown_purpose():
    """
    AT-09: Candidate personal-data extraction identifies personal data fields (e.g. email, national_id),
    while purpose, processor, and retention period strictly remain 'unknown' (FR-DPD-04).
    """
    flows = extract_data_flows_from_worktree(VULN_PYTHON_DIR)
    assert len(flows) >= 1

    field_names = [f.field_name for f in flows]
    assert any("email" in fn for fn in field_names) or any("national_id" in fn for fn in field_names)

    for flow in flows:
        assert flow.purpose == "unknown", "Purpose must stay unknown until evidenced!"
        assert flow.processor == "unknown", "Processor must stay unknown until evidenced!"
        assert flow.retention_period == "unknown", "Retention period must stay unknown until evidenced!"


# -----------------------------------------------------------------------------
# AT-10: Applicability questionnaire handling
# -----------------------------------------------------------------------------
def test_at10_applicability_questionnaire_handling():
    """
    AT-10: Unanswered questions remain UNKNOWN.
    No nexus with India => NOT_APPLICABLE.
    India personal data => APPLICABLE.
    """
    # 1. Unanswered questionnaire => UNKNOWN
    unanswered_res = evaluate_dpdp_applicability({})
    assert unanswered_res.status == "UNKNOWN"
    assert len(unanswered_res.unanswered_questions) > 0

    # 2. No personal data & no India targeting => NOT_APPLICABLE
    not_app_res = evaluate_dpdp_applicability({
        "processes_personal_data": False,
        "in_territory_of_india": False,
        "targeting_data_principals_in_india": False
    })
    assert not_app_res.status == "NOT_APPLICABLE"

    # 3. Personal data in India => APPLICABLE
    app_res = evaluate_dpdp_applicability({
        "processes_personal_data": True,
        "in_territory_of_india": True
    })
    assert app_res.status == "APPLICABLE"


# -----------------------------------------------------------------------------
# AT-11: DPDP-018 exposure linkage to DPDP-006 without declaring breach
# -----------------------------------------------------------------------------
def test_at11_personal_data_exposure_linkage_no_breach():
    """
    AT-11: Link SEC-002/003/004/026 to DPDP-006 via DPDP-018.
    Must evaluate as technical safeguard gaps without declaring a statutory breach.
    """
    session_id = str(uuid.uuid4())
    headers = {"X-Session-ID": session_id}
    db = SessionLocal()

    try:
        repo_id = str(uuid.uuid4())
        repo = RepositoryModel(
            id=repo_id,
            github_owner="vulnerable-org",
            github_repo="vulnerable-python-api",
            canonical_url=f"https://github.com/vulnerable-org/dpdp-{session_id[:6]}",
            default_branch="main"
        )
        db.add(repo)

        audit_id = str(uuid.uuid4())
        audit = AuditModel(
            id=audit_id,
            repository_id=repo_id,
            session_id=session_id,
            scopes=["SECURITY", "DPDP"],
            status="QUEUED",
            current_stage="QUEUED"
        )
        db.add(audit)
        db.commit()

        execute_scan_pipeline(audit_id, worktree_dir=VULN_PYTHON_DIR)

        res = client.get(f"/api/v1/audits/{audit_id}/dpdp/controls", headers=headers)
        assert res.status_code == 200
        controls = res.json()

        dpdp_018 = next((c for c in controls if c["control_id"] == "DPDP-018"), None)
        assert dpdp_018 is not None
        assert dpdp_018["state"] == "POTENTIAL_GAP"
        assert "SEC-00" in dpdp_018["rationale"] or "SEC-026" in dpdp_018["rationale"] or "security finding" in dpdp_018["rationale"]
        assert "without declaring a breach" in dpdp_018["rationale"].lower() or "not a statutory declaration" in dpdp_018["rationale"].lower()

        dpdp_006 = next((c for c in controls if c["control_id"] == "DPDP-006"), None)
        assert dpdp_006 is not None
        assert dpdp_006["state"] == "POTENTIAL_GAP"

    finally:
        db.close()


# -----------------------------------------------------------------------------
# AT-12: Dynamic commencement calculation relative to as_of_date
# -----------------------------------------------------------------------------
def test_at12_dynamic_commencement_calculation():
    """
    AT-12: Verify commencement calculation dynamically derived from as_of_date.
    Expected as of 2026-11-14:
    - Rule 4, §6(9), §27(1)(d) = IN_FORCE
    - Act §§3-5, most of §6, §§7-17, Rules 3, 5-16 = UPCOMING (13 May 2027)
    As of 2027-05-14:
    - General provisions = IN_FORCE
    """
    as_of_2026 = date(2026, 11, 14)
    as_of_2027 = date(2027, 5, 14)

    # 1. Rule 4 (Consent Managers) as of 14 Nov 2026
    st_r4, d_r4, _ = compute_effective_date_status("Rule 4", as_of_2026)
    assert st_r4 == EffectiveDateStatus.IN_FORCE
    assert d_r4 == date(2026, 11, 13)

    # 2. Section 6(9) as of 14 Nov 2026
    st_s69, d_s69, _ = compute_effective_date_status("Section 6(9)", as_of_2026)
    assert st_s69 == EffectiveDateStatus.IN_FORCE

    # 3. Section 8(5) (Security Safeguards) as of 14 Nov 2026 -> UPCOMING
    st_s85, d_s85, _ = compute_effective_date_status("Section 8(5)", as_of_2026)
    assert st_s85 == EffectiveDateStatus.UPCOMING
    assert d_s85 == date(2027, 5, 13)

    # 4. Section 8(5) as of 14 May 2027 -> IN_FORCE
    st_s85_27, _, _ = compute_effective_date_status("Section 8(5)", as_of_2027)
    assert st_s85_27 == EffectiveDateStatus.IN_FORCE


# -----------------------------------------------------------------------------
# AT-13: Statutory penalty ceilings & prohibited phrases check
# -----------------------------------------------------------------------------
def test_at13_penalty_schedule_ceilings_and_prohibited_phrases():
    """
    AT-13: Penalties indicate maximum ceilings only with mandatory caveat.
    Responses must NEVER sum fines or contain prohibited phrases:
    'expected fine', 'will be fined', 'non-compliant', 'DPDP compliant'.
    """
    session_id = str(uuid.uuid4())
    headers = {"X-Session-ID": session_id}
    db = SessionLocal()

    try:
        repo_id = str(uuid.uuid4())
        repo = RepositoryModel(
            id=repo_id,
            github_owner="vulnerable-org",
            github_repo="vulnerable-python-api",
            canonical_url=f"https://github.com/vulnerable-org/pen-{session_id[:6]}",
            default_branch="main"
        )
        db.add(repo)

        audit_id = str(uuid.uuid4())
        audit = AuditModel(
            id=audit_id,
            repository_id=repo_id,
            session_id=session_id,
            scopes=["SECURITY", "DPDP"],
            status="QUEUED",
            current_stage="QUEUED"
        )
        db.add(audit)
        db.commit()

        execute_scan_pipeline(audit_id, worktree_dir=VULN_PYTHON_DIR)

        res = client.get(f"/api/v1/audits/{audit_id}/legal-exposure", headers=headers)
        assert res.status_code == 200
        data = res.json()

        assert len(data["items"]) >= 1

        # Check every item for mandatory caveat and ceilings
        for item in data["items"]:
            assert item["mandatory_caveat"] == "Potential legal category; applicability and liability not determined."
            assert "crore" in item["statutory_ceiling"].lower() or "₹" in item["statutory_ceiling"]
            assert item["legal_determination_required"] is True

        # Global copy audit against prohibited phrases
        response_text = res.text.lower()
        prohibited = [
            "expected fine",
            "will be fined",
            "non-compliant",
            "dpdp compliant",
            "total fine",
            "aggregate fine"
        ]
        for p in prohibited:
            assert p not in response_text, f"Prohibited phrase '{p}' found in legal exposure response!"

    finally:
        db.close()


# -----------------------------------------------------------------------------
# AT-14: Primary citation completeness
# -----------------------------------------------------------------------------
def test_at14_citation_completeness_on_all_dpdp_controls():
    """
    AT-14: Every displayed DPDP control has a primary legal source citation
    with document, clause, gazette_id, and reviewed_at.
    """
    bundle = get_policy_bundle()
    controls = bundle.dpdp_controls.controls

    assert len(controls) == 18, f"Expected 18 DPDP controls, found {len(controls)}"

    for c in controls:
        assert c.legal_source is not None, f"Control {c.id} missing legal_source citation!"
        assert c.legal_source.get("document") in ("Digital Personal Data Protection Act 2023", "Digital Personal Data Protection Rules 2025")
        assert c.legal_source.get("clause") is not None
        assert c.legal_source.get("gazette_id") in ("G.S.R. 843(E)", "G.S.R. 846(E)")
        assert c.legal_source.get("reviewed_at") is not None

