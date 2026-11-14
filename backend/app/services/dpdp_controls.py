"""DPDP controls evaluation engine (FR-DPD, D-07, D-08, D-09, rules.md)."""
import uuid
from datetime import date
from typing import Any, List, Optional
from sqlalchemy.orm import Session

from app.schemas.enums import ControlState, EvidenceTier, EffectiveDateStatus
from app.models.models import AuditModel, ControlResultModel, FindingModel, DpdpProfileModel
from app.services.policy_loader import get_policy_bundle
from app.dpdp.commencement import compute_effective_date_status
from app.dpdp.applicability import evaluate_dpdp_applicability


def evaluate_dpdp_controls(
    db: Session,
    audit_id: str,
    as_of_date: date | str | None = None,
    profile_answers: dict[str, Any] | None = None
) -> list[ControlResultModel]:
    """
    Evaluates all 18 DPDP controls against repository findings, evidence,
    and applicability profile answers.

    Guarantees:
    - Never declares a 'breach' or 'non-compliance'.
    - Links SEC-002/003/004/026 to DPDP-006 via DPDP-018 without declaring a breach.
    - Effective-date status is computed dynamically from as_of_date.
    - Readiness labels: evidence_supports / potential_gap / needs_documents / not_applicable / requires_legal_review.
    """
    bundle = get_policy_bundle()
    dpdp_policy = bundle.dpdp_controls.controls

    # Retrieve existing security findings and controls
    sec_findings = db.query(FindingModel).filter(FindingModel.audit_id == audit_id).all()
    sec_controls = db.query(ControlResultModel).filter(
        ControlResultModel.audit_id == audit_id,
        ControlResultModel.domain == "SECURITY"
    ).all()
    sec_ctrl_map = {c.control_id: c for c in sec_controls}

    # Retrieve profile answers from DB if not provided directly
    if profile_answers is None:
        prof = db.query(DpdpProfileModel).filter(DpdpProfileModel.audit_id == audit_id).first()
        profile_answers = prof.answers if prof and prof.answers else {}

    applicability = evaluate_dpdp_applicability(profile_answers)

    # Clear previous DPDP results for this audit
    db.query(ControlResultModel).filter(
        ControlResultModel.audit_id == audit_id,
        ControlResultModel.domain == "DPDP"
    ).delete()

    # Track relevant security findings for DPDP-018 linkage
    linkage_sec_ids = {"SEC-002", "SEC-003", "SEC-004", "SEC-026"}
    linked_sec_findings: list[FindingModel] = []
    for f in sec_findings:
        if any(sec_id.lower() in f.rule_id.lower() for sec_id in linkage_sec_ids) or f.category in ("secrets", "data_exposure"):
            linked_sec_findings.append(f)

    has_safeguard_gaps = any(
        sec_ctrl_map.get(sid) and sec_ctrl_map[sid].state in (ControlState.FAIL_EVIDENCED.value, ControlState.POTENTIAL_GAP.value)
        for sid in linkage_sec_ids
    ) or bool(linked_sec_findings)

    dpdp_results: list[ControlResultModel] = []

    for ctrl in dpdp_policy:
        ctrl_id = ctrl.id
        title = ctrl.title
        act_section = ctrl.act_section
        rules_ref = ctrl.rules_ref
        tier_str = ctrl.evidence_tier

        # 1. Compute dynamic effective date status
        eff_status, eff_date, eff_rationale = compute_effective_date_status(
            provision=f"{act_section} {rules_ref}",
            as_of_date=as_of_date
        )

        state = ControlState.NOT_VERIFIED
        readiness = "needs_documents"
        rationale = "Requires organizational policy or documentation review."
        evidence_tier = EvidenceTier.E3_SUPPLIED_DOCS

        # 2. Control Specific Predicates
        if ctrl_id == "DPDP-001":  # Scope & Applicability
            if applicability.status == "APPLICABLE":
                state = ControlState.PASS_EVIDENCED
                readiness = "evidence_supports"
                rationale = "Questionnaire confirms applicability under Section 3 (digital personal data processed with India nexus)."
            elif applicability.status == "NOT_APPLICABLE":
                state = ControlState.NOT_APPLICABLE
                readiness = "not_applicable"
                rationale = "Questionnaire indicates no digital personal data processing with India nexus."
            else:
                state = ControlState.NOT_VERIFIED
                readiness = "needs_documents"
                rationale = f"Applicability undetermined: {len(applicability.unanswered_questions)} question(s) remain unanswered."

        elif ctrl_id == "DPDP-004":  # Consent withdrawal mechanism
            # Check if source code has consent withdrawal or delete account routes
            has_withdrawal_route = any("withdraw" in f.file_path.lower() or "consent" in f.file_path.lower() for f in sec_findings)
            if has_withdrawal_route:
                state = ControlState.PASS_EVIDENCED
                readiness = "evidence_supports"
                rationale = "Identified endpoint or interface associated with consent management."
            else:
                state = ControlState.POTENTIAL_GAP
                readiness = "potential_gap"
                rationale = "No explicit consent withdrawal mechanism identified in surveyed API routes. Requires UI/UX verification."

        elif ctrl_id == "DPDP-006":  # Reasonable security safeguards
            if has_safeguard_gaps:
                state = ControlState.POTENTIAL_GAP
                readiness = "potential_gap"
                rationale = (
                    "Security assessment identified vulnerabilities or potential gaps in access control, "
                    "secret management, or data exposure (referenced via DPDP-018). "
                    "Evaluated as potential technical safeguard gap; not a statutory declaration of breach."
                )
            else:
                state = ControlState.PASS_EVIDENCED
                readiness = "evidence_supports"
                rationale = "Static checks observed baseline technical security safeguards across surveyed codebase."

        elif ctrl_id == "DPDP-011":  # Children's Data
            if profile_answers.get("processes_children_data") is False:
                state = ControlState.NOT_APPLICABLE
                readiness = "not_applicable"
                rationale = "Organizational profile attests application does not target or process children's personal data."
            elif profile_answers.get("processes_children_data") is True:
                state = ControlState.POTENTIAL_GAP
                readiness = "potential_gap"
                rationale = "Processing children's data confirmed. Verifiable parental consent mechanism must be established under Section 9."
            else:
                state = ControlState.NOT_VERIFIED
                readiness = "requires_legal_review"
                rationale = "Children's personal data applicability not specified in questionnaire. Status unknown."

        elif ctrl_id == "DPDP-013":  # Significant Data Fiduciary (SDF)
            if profile_answers.get("is_significant_data_fiduciary") is False:
                state = ControlState.NOT_APPLICABLE
                readiness = "not_applicable"
                rationale = "Entity is not notified as a Significant Data Fiduciary under Section 10."
            elif profile_answers.get("is_significant_data_fiduciary") is True:
                state = ControlState.NOT_VERIFIED
                readiness = "requires_legal_review"
                rationale = "SDF designation applicable. Requires appointment of DPO, Data Protection Impact Assessment (DPIA), and independent audit."
            else:
                state = ControlState.NOT_VERIFIED
                readiness = "requires_legal_review"
                rationale = "SDF notification status not answered in profile. Status unknown."

        elif ctrl_id == "DPDP-015":  # Cross-border transfers
            if profile_answers.get("cross_border_transfers") is False:
                state = ControlState.PASS_EVIDENCED
                readiness = "evidence_supports"
                rationale = "Attestation confirms personal data is not transferred outside India."
            else:
                state = ControlState.NOT_VERIFIED
                readiness = "requires_legal_review"
                rationale = "Cross-border data flows require legal review against notified restricted jurisdictions under Section 16."

        elif ctrl_id == "DPDP-018":  # Personal Data Exposure Linkage
            if linked_sec_findings:
                state = ControlState.POTENTIAL_GAP
                readiness = "potential_gap"
                rationale = (
                    f"Linked {len(linked_sec_findings)} technical security finding(s) (SEC-002/003/004/026) "
                    "involving credential or personal data fields. Correlated to Section 8(5) safeguards without declaring a breach."
                )
            else:
                state = ControlState.PASS_EVIDENCED
                readiness = "evidence_supports"
                rationale = "No direct personal data exposure or credential leaks identified in surveyed endpoints."

        else:
            state = ControlState.NOT_VERIFIED
            readiness = "needs_documents"
            rationale = "Governance control: requires formal documentation or legal review (beyond automated static source inspection)."

        # Map tier
        if "E1" in tier_str:
            evidence_tier = EvidenceTier.E1_SOURCE_CODE
        elif "E2" in tier_str:
            evidence_tier = EvidenceTier.E2_CONFIG_MANIFEST
        elif "E3" in tier_str:
            evidence_tier = EvidenceTier.E3_SUPPLIED_DOCS
        elif "E4" in tier_str:
            evidence_tier = EvidenceTier.E4_ORG_ATTESTATION

        model = ControlResultModel(
            id=str(uuid.uuid4()),
            audit_id=audit_id,
            control_id=ctrl_id,
            domain="DPDP",
            title=title,
            state=state.value,
            readiness_label=readiness,
            effective_date_status=eff_status.value,
            effective_date=eff_date,
            rationale=rationale,
            evidence_tier=evidence_tier.value
        )
        db.add(model)
        dpdp_results.append(model)

    db.commit()
    return dpdp_results
