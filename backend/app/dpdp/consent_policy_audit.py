"""Consent and Privacy Policy Audit Engine (Step 10, DPDP Act 2023 §5, §6, §8(9))."""
from dataclasses import dataclass, field
import logging
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class GrievanceOfficerAudit:
    detected: bool = False
    officer_title: Optional[str] = None
    email_contact: Optional[str] = None
    postal_address_present: bool = False
    turnaround_time_mentioned: bool = False
    details: List[str] = field(default_factory=list)


@dataclass
class NoticeTransparencyAudit:
    privacy_policy_found: bool = False
    policy_path: Optional[str] = None
    itemized_categories_found: bool = False
    specified_purposes_found: bool = False
    board_complaint_mechanism_mentioned: bool = False
    eighth_schedule_languages_mentioned: bool = False
    details: List[str] = field(default_factory=list)


@dataclass
class ConsentUiAudit:
    pre_ticked_checkboxes_detected: int = 0
    bundled_consent_detected: int = 0
    withdrawal_mechanism_found: bool = False
    dark_patterns: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ConsentPolicyAuditReport:
    grievance_officer: GrievanceOfficerAudit
    notice_transparency: NoticeTransparencyAudit
    consent_ui: ConsentUiAudit
    findings: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "grievance_officer": {
                "detected": self.grievance_officer.detected,
                "officer_title": self.grievance_officer.officer_title,
                "email_contact": self.grievance_officer.email_contact,
                "postal_address_present": self.grievance_officer.postal_address_present,
                "turnaround_time_mentioned": self.grievance_officer.turnaround_time_mentioned,
                "details": self.grievance_officer.details,
            },
            "notice_transparency": {
                "privacy_policy_found": self.notice_transparency.privacy_policy_found,
                "policy_path": self.notice_transparency.policy_path,
                "itemized_categories_found": self.notice_transparency.itemized_categories_found,
                "specified_purposes_found": self.notice_transparency.specified_purposes_found,
                "board_complaint_mechanism_mentioned": self.notice_transparency.board_complaint_mechanism_mentioned,
                "eighth_schedule_languages_mentioned": self.notice_transparency.eighth_schedule_languages_mentioned,
                "details": self.notice_transparency.details,
            },
            "consent_ui": {
                "pre_ticked_checkboxes_detected": self.consent_ui.pre_ticked_checkboxes_detected,
                "bundled_consent_detected": self.consent_ui.bundled_consent_detected,
                "withdrawal_mechanism_found": self.consent_ui.withdrawal_mechanism_found,
                "dark_patterns": self.consent_ui.dark_patterns,
            },
            "findings": self.findings,
        }


class ConsentPolicyAuditor:
    """Audits repository privacy notices, grievance redressal details, and consent UI patterns."""

    GRIEVANCE_KEYWORDS = re.compile(r"""\b(?:grievance\s*officer|data\s*protection\s*officer|dpo|nodal\s*officer)\b""", re.IGNORECASE)
    EMAIL_REGEX = re.compile(r"""\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b""")
    POSTAL_REGEX = re.compile(r"""\b(?:postal\s*address|office\s*address|registered\s*office|pincode|pin\s*code|pin\s*-\s*[1-9][0-9]{5})\b""", re.IGNORECASE)
    BOARD_COMPLAINT_REGEX = re.compile(r"""\b(?:data\s*protection\s*board|dpbi|complaint\s*to\s*the\s*board)\b""", re.IGNORECASE)
    PURPOSE_REGEX = re.compile(r"""\b(?:purposes?\s*of\s*processing|why\s*we\s*collect|how\s*we\s*use\s*your\s*data|data\s*collected)\b""", re.IGNORECASE)
    LANGUAGES_REGEX = re.compile(r"""\b(?:eighth\s*schedule|22\s*languages|hindi|english|tamil|telugu|bengali|marathi|gujarati|kannada|malayalam)\b""", re.IGNORECASE)
    WITHDRAW_REGEX = re.compile(r"""\b(?:withdraw\s*consent|revoke\s*consent|opt\s*out|manage\s*preferences)\b""", re.IGNORECASE)

    # Dark patterns in UI code (React / HTML / Vue)
    PRE_TICKED_REGEX = re.compile(r"""<(?:input|Checkbox)[^>]*?(?:defaultChecked|checked\s*=\s*[{"]true[}"]|checked\b(?!\s*=\s*[{"]false[}"]))[^>]*?(?:consent|terms|newsletter|marketing|agree|policy)""", re.IGNORECASE)
    BUNDLED_REGEX = re.compile(r"""(?:terms\s*(?:and|&)\s*conditions|terms\s*of\s*service)[^<]{1,80}(?:privacy\s*policy|marketing|promotional|partner\s*offers)""", re.IGNORECASE)

    @classmethod
    def audit_worktree(cls, worktree_dir: Path) -> ConsentPolicyAuditReport:
        grievance = GrievanceOfficerAudit()
        notice = NoticeTransparencyAudit()
        consent_ui = ConsentUiAudit()
        findings: List[Dict[str, Any]] = []

        policy_candidates = [
            "privacy.md", "privacy-policy.md", "privacy_policy.md",
            "privacy.html", "privacy-policy.html", "privacy_policy.html",
            "privacy.txt", "legal.md", "terms-and-privacy.md",
        ]

        # Scan for policy files and examine text
        for root, _, files in os.walk(worktree_dir):
            if ".git" in root or "node_modules" in root or "venv" in root:
                continue

            for fname in files:
                fpath = Path(root) / fname
                rel_path = str(fpath.resolve().relative_to(Path(worktree_dir).resolve())).replace("\\", "/")
                fl_lower = fname.lower()

                # Check if file looks like a privacy notice
                if any(cand in fl_lower for cand in policy_candidates) or "privacy" in fl_lower:
                    try:
                        content = fpath.read_text(encoding="utf-8", errors="ignore")
                    except Exception:
                        continue

                    notice.privacy_policy_found = True
                    notice.policy_path = rel_path

                    # Check grievance details
                    if cls.GRIEVANCE_KEYWORDS.search(content):
                        grievance.detected = True
                        m = cls.GRIEVANCE_KEYWORDS.search(content)
                        grievance.officer_title = m.group(0) if m else "Grievance Officer"
                        grievance.details.append(f"Grievance officer referenced in {rel_path}")

                    # Check email
                    for em in cls.EMAIL_REGEX.finditer(content):
                        email_str = em.group(0).lower()
                        if any(kw in email_str for kw in ["grievance", "dpo", "privacy", "nodal", "compliance"]):
                            grievance.email_contact = email_str
                            break

                    # Check postal address
                    if cls.POSTAL_REGEX.search(content):
                        grievance.postal_address_present = True
                        grievance.details.append(f"Postal/office address mentioned in {rel_path}")

                    # Check board complaint mention (§5(1)(ii))
                    if cls.BOARD_COMPLAINT_REGEX.search(content):
                        notice.board_complaint_mechanism_mentioned = True
                        notice.details.append("Mentions right to lodge complaint with the Data Protection Board")

                    # Check specified purposes
                    if cls.PURPOSE_REGEX.search(content):
                        notice.specified_purposes_found = True
                        notice.itemized_categories_found = True
                        notice.details.append("Itemized data categories and processing purposes detailed")

                    # Check 8th schedule languages mention
                    if cls.LANGUAGES_REGEX.search(content):
                        notice.eighth_schedule_languages_mentioned = True
                        notice.details.append("Mentions multi-language access or Eighth Schedule languages")

                # Scan UI code for consent patterns and dark patterns
                if fname.endswith((".tsx", ".jsx", ".html", ".vue", ".js", ".ts")):
                    try:
                        content = fpath.read_text(encoding="utf-8", errors="ignore")
                    except Exception:
                        continue

                    # Pre-ticked checkbox check (DPDP Act §6: Consent must be unconditional & explicit)
                    pre_ticks = cls.PRE_TICKED_REGEX.findall(content)
                    if pre_ticks:
                        consent_ui.pre_ticked_checkboxes_detected += len(pre_ticks)
                        consent_ui.dark_patterns.append({
                            "type": "PRE_TICKED_CONSENT",
                            "file": rel_path,
                            "count": len(pre_ticks),
                            "remediation": "DPDP Act 2023 Section 6 requires consent to be free, specific, and unambiguous. Remove defaultChecked/checked attributes on consent checkboxes."
                        })
                        findings.append({
                            "rule_id": "dpdp-consent-pre-ticked-checkbox",
                            "file_path": rel_path,
                            "title": "Pre-ticked consent checkbox violates Section 6(1)",
                            "severity": "HIGH",
                            "dpdp_section": "Section 6(1) / DPDP-003",
                        })

                    # Check withdrawal mechanism
                    if cls.WITHDRAW_REGEX.search(content):
                        consent_ui.withdrawal_mechanism_found = True

        # Check for missing grievance officer if policy was found
        if notice.privacy_policy_found and not grievance.detected:
            findings.append({
                "rule_id": "dpdp-notice-missing-grievance-officer",
                "file_path": notice.policy_path or "privacy-policy",
                "title": "Missing Grievance Redressal / Officer contact details under Section 8(9)",
                "severity": "HIGH",
                "dpdp_section": "Section 8(9) / DPDP-017",
            })

        return ConsentPolicyAuditReport(
            grievance_officer=grievance,
            notice_transparency=notice,
            consent_ui=consent_ui,
            findings=findings,
        )
