"""DPDP Applicability questionnaire and profile management (FR-DPD-01, FR-DPD-10)."""
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class DpdpQuestionnaire(BaseModel):
    processes_personal_data: Optional[bool] = None
    in_territory_of_india: Optional[bool] = None
    targeting_data_principals_in_india: Optional[bool] = None
    processes_children_data: Optional[bool] = None
    is_significant_data_fiduciary: Optional[bool] = None
    has_external_data_processors: Optional[bool] = None
    cross_border_transfers: Optional[bool] = None
    consent_manager_integration: Optional[bool] = None


class DpdpApplicabilityResult(BaseModel):
    status: str  # APPLICABLE, NOT_APPLICABLE, UNKNOWN, CONDITIONAL
    rationale: str
    is_sdf: bool
    processes_children: bool
    unanswered_questions: list[str]


def evaluate_dpdp_applicability(answers: dict[str, Any] | None) -> DpdpApplicabilityResult:
    """
    Evaluates applicability of DPDP Act 2023 based on user answers.
    Conservative Rule: Unanswered questions remain UNKNOWN.
    Never assume Yes or No.
    """
    if not answers:
        answers = {}

    unanswered = []
    expected_fields = [
        ("processes_personal_data", "Processing of digital personal data"),
        ("in_territory_of_india", "Processing within the territory of India"),
        ("targeting_data_principals_in_india", "Offering goods or services to Data Principals in India"),
        ("processes_children_data", "Processing personal data belonging to children (<18)"),
        ("is_significant_data_fiduciary", "Designated as Significant Data Fiduciary by Central Government"),
        ("has_external_data_processors", "Engagement of third-party Data Processors"),
        ("cross_border_transfers", "Transfer of personal data outside India"),
        ("consent_manager_integration", "Interoperability with registered Consent Managers")
    ]

    for key, desc in expected_fields:
        if key not in answers or answers[key] is None:
            unanswered.append(desc)

    personal_data = answers.get("processes_personal_data")
    territory_india = answers.get("in_territory_of_india")
    targeting_india = answers.get("targeting_data_principals_in_india")
    children_data = bool(answers.get("processes_children_data"))
    sdf = bool(answers.get("is_significant_data_fiduciary"))

    if personal_data is False and territory_india is False and targeting_india is False:
        return DpdpApplicabilityResult(
            status="NOT_APPLICABLE",
            rationale="Questionnaire indicates no digital personal data processing and no nexus with India under Section 3.",
            is_sdf=False,
            processes_children=False,
            unanswered_questions=unanswered
        )

    if personal_data is True and (territory_india is True or targeting_india is True):
        return DpdpApplicabilityResult(
            status="APPLICABLE",
            rationale="Activity falls within scope of Section 3: digital personal data processed in India or in connection with offering goods/services to Data Principals in India.",
            is_sdf=sdf,
            processes_children=children_data,
            unanswered_questions=unanswered
        )

    return DpdpApplicabilityResult(
        status="UNKNOWN",
        rationale=f"Applicability cannot be determined definitively. {len(unanswered)} questionnaire item(s) remain unanswered.",
        is_sdf=sdf,
        processes_children=children_data,
        unanswered_questions=unanswered
    )

