"""DPDP statutory penalty reference engine (PEN-01..06, D-08, rules.md)."""
from typing import Any, List, Optional
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.services.policy_loader import get_policy_bundle
from app.models.models import ControlResultModel, FindingModel, DpdpProfileModel


MANDATORY_CAVEAT = "Potential legal category; applicability and liability not determined."


class PenaltyReferenceItem(BaseModel):
    schedule_item: int
    breach_description: str
    related_act_section: str
    statutory_ceiling: str
    mandatory_caveat: str = MANDATORY_CAVEAT
    engineering_priority: str
    legal_determination_required: bool = True
    plausibility_rationale: str
    human_override: Optional[dict[str, Any]] = None


class LegalExposureResponse(BaseModel):
    items: list[PenaltyReferenceItem]
    mandatory_disclaimer: str = (
        "Statutory penalty reference amounts indicate maximum statutory ceilings specified in the Schedule "
        "to the Digital Personal Data Protection Act, 2023. These references do not constitute legal advice, "
        "do not represent a fine prediction, and must never be summed. Applicability and liability require "
        "independent legal determination by qualified legal counsel."
    )


def evaluate_penalty_exposure(
    db: Session,
    audit_id: str,
    profile_answers: dict[str, Any] | None = None
) -> list[PenaltyReferenceItem]:
    """
    Maps only plausibly relevant Schedule categories based on findings and controls.

    Strict Rules (PEN-01..06):
    - Show statutory maximum ceiling only.
    - NEVER sum or aggregate amounts.
    - NEVER predict a fine or use 'expected fine', 'will be fined', 'non-compliant', or 'DPDP compliant'.
    - Mandatory caveat attached to every item.
    - Separate engineering priority from legal exposure reference.
    """
    bundle = get_policy_bundle()
    schedule_items = bundle.penalty_schedule.items

    dpdp_controls = db.query(ControlResultModel).filter(
        ControlResultModel.audit_id == audit_id,
        ControlResultModel.domain == "DPDP"
    ).all()
    ctrl_map = {c.control_id: c for c in dpdp_controls}

    findings = db.query(FindingModel).filter(FindingModel.audit_id == audit_id).all()

    if profile_answers is None:
        prof = db.query(DpdpProfileModel).filter(DpdpProfileModel.audit_id == audit_id).first()
        profile_answers = prof.answers if prof and prof.answers else {}

    plausible_items: list[PenaltyReferenceItem] = []

    for item in schedule_items:
        s_num = item.schedule_item
        is_plausible = False
        priority = "P1"
        rationale = ""

        if s_num == 1:  # Section 8(5) Security safeguards
            dpdp_006 = ctrl_map.get("DPDP-006")
            has_sec_flaws = any(f.severity in ("CRITICAL", "HIGH") for f in findings)
            if (dpdp_006 and dpdp_006.state in ("FAIL_EVIDENCED", "POTENTIAL_GAP")) or has_sec_flaws:
                is_plausible = True
                priority = "P0"
                rationale = "Technical security flaws or data exposure indicators observed in codebase (relevant to Section 8(5) safeguards)."

        elif s_num == 2:  # Section 8(6) Breach notification
            dpdp_007 = ctrl_map.get("DPDP-007")
            if dpdp_007 and dpdp_007.state == "NOT_VERIFIED":
                is_plausible = True
                priority = "P1"
                rationale = "Breach response and reporting runbook documentation not verified in repository files."

        elif s_num == 3:  # Section 9 Children
            if profile_answers.get("processes_children_data") is True:
                is_plausible = True
                priority = "P0"
                rationale = "Questionnaire confirms processing of children's data; Section 9 obligations operative."

        elif s_num == 4:  # Section 10 Significant Data Fiduciary
            if profile_answers.get("is_significant_data_fiduciary") is True:
                is_plausible = True
                priority = "P1"
                rationale = "Significant Data Fiduciary designation indicated in profile."

        elif s_num == 7:  # Residual provisions
            # Only include if general governance gaps exist
            if any(c.state == "POTENTIAL_GAP" for c in dpdp_controls):
                is_plausible = True
                priority = "P2"
                rationale = "Residual statutory ceiling for general rule non-observance where no specific category applies."

        if is_plausible:
            plausible_items.append(PenaltyReferenceItem(
                schedule_item=s_num,
                breach_description=item.breach,
                related_act_section=item.related_act_section,
                statutory_ceiling=item.ceiling_inr,
                mandatory_caveat=MANDATORY_CAVEAT,
                engineering_priority=priority,
                legal_determination_required=True,
                plausibility_rationale=rationale,
                human_override=None
            ))

    return plausible_items

