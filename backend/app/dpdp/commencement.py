"""DPDP commencement and effective date calculation engine (D-07, FR-DPD-02)."""
from datetime import date, datetime
from typing import Tuple, Optional
from app.core.config import settings
from app.schemas.enums import EffectiveDateStatus


# Pinned gazetted commencement dates from G.S.R. 843(E) and G.S.R. 846(E)
DATE_PHASE_1 = date(2025, 11, 13)  # Rules 1, 2, 17-21, Board machinery
DATE_PHASE_2 = date(2026, 11, 13)  # Rule 4, §6(9), §27(1)(d)
DATE_PHASE_3 = date(2027, 5, 13)   # General duties: §§3-5, 6(1)-(8), 7-17, Rules 3, 5-16, 22, 23


PHASE_1_PROVISIONS = {
    "rule 1", "rule 2", "rule 17", "rule 18", "rule 19", "rule 20", "rule 21",
    "board machinery", "section 18", "section 19", "section 20"
}

PHASE_2_PROVISIONS = {
    "rule 4", "consent manager", "section 6(9)", "section 27(1)(d)"
}

PHASE_3_PROVISIONS = {
    "section 3", "section 4", "section 5", "section 6", "section 6(1)", "section 6(4)",
    "section 7", "section 8", "section 8(2)", "section 8(3)", "section 8(5)",
    "section 8(6)", "section 8(7)", "section 8(8)", "section 8(9)",
    "section 9", "section 9(3)", "section 10", "section 11", "section 12",
    "section 13", "section 14", "section 15", "section 16", "section 17",
    "rule 3", "rule 5", "rule 6", "rule 7", "rule 8", "rule 9", "rule 10",
    "rule 11", "rule 12", "rule 13", "rule 14", "rule 15", "rule 16", "rule 22", "rule 23"
}


def parse_date(d: date | str | None) -> date:
    if d is None:
        if getattr(settings, "AS_OF_DATE", None):
            try:
                return datetime.strptime(str(settings.AS_OF_DATE)[:10], "%Y-%m-%d").date()
            except Exception:
                pass
        return date.today()
    if isinstance(d, date):
        return d
    return datetime.strptime(str(d)[:10], "%Y-%m-%d").date()


def compute_effective_date_status(
    provision: str,
    as_of_date: date | str | None = None
) -> tuple[EffectiveDateStatus, Optional[date], str]:
    """
    Computes whether a statutory section or rule is In Force, Upcoming, or Not Yet Determined
    relative to a provided as_of_date.

    Returns: (EffectiveDateStatus, effective_date, rationale)
    """
    current_date = parse_date(as_of_date)
    prov_norm = provision.lower().strip()

    # Match Phase 2 first (Rule 4, §6(9), §27(1)(d))
    is_p2 = any(p in prov_norm for p in PHASE_2_PROVISIONS)
    if is_p2:
        if current_date >= DATE_PHASE_2:
            return (
                EffectiveDateStatus.IN_FORCE,
                DATE_PHASE_2,
                f"In force since 13 November 2026 (G.S.R. 843(E) / G.S.R. 846(E))."
            )
        else:
            return (
                EffectiveDateStatus.UPCOMING,
                DATE_PHASE_2,
                f"Upcoming on 13 November 2026."
            )

    # Match Phase 1 (Rules 1, 2, 17-21, Board machinery)
    is_p1 = any(p in prov_norm for p in PHASE_1_PROVISIONS)
    if is_p1:
        if current_date >= DATE_PHASE_1:
            return (
                EffectiveDateStatus.IN_FORCE,
                DATE_PHASE_1,
                "In force since 13 November 2025 (G.S.R. 843(E))."
            )
        else:
            return (
                EffectiveDateStatus.UPCOMING,
                DATE_PHASE_1,
                "Upcoming on 13 November 2025."
            )

    # Match Phase 3 (General duties: Act §§3-5, most of §6, §§7-17, Rules 3, 5-16)
    is_p3 = any(p in prov_norm for p in PHASE_3_PROVISIONS)
    if is_p3:
        if current_date >= DATE_PHASE_3:
            return (
                EffectiveDateStatus.IN_FORCE,
                DATE_PHASE_3,
                f"In force since 13 May 2027 (G.S.R. 846(E) / Rule 1)."
            )
        else:
            return (
                EffectiveDateStatus.UPCOMING,
                DATE_PHASE_3,
                f"Upcoming on 13 May 2027 (operative under phased commencement)."
            )

    return (
        EffectiveDateStatus.NOT_DETERMINED,
        None,
        "Commencement date not yet notified in Official Gazette."
    )

