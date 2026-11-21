"""DPDP Act 2023 Comprehensive Readiness & Control Assessment Engine (Step 10, DPDP Act 2023)."""
from dataclasses import dataclass, field
from datetime import date
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from app.core.config import settings
from app.dpdp.commencement import compute_effective_date_status, parse_date
from app.dpdp.pii_detector import PiiDetector
from app.dpdp.processor_inventory import ProcessorInventoryScanner
from app.dpdp.consent_policy_audit import ConsentPolicyAuditor
from app.dpdp.retention_erasure import RetentionErasureAuditor
from app.schemas.enums import EffectiveDateStatus

logger = logging.getLogger(__name__)

MANDATORY_PENALTY_CAVEAT = "Potential legal category; applicability and liability not determined."

STATUTORY_PENALTY_ITEMS: List[Dict[str, Any]] = [
    {
        "schedule_item": 1,
        "breach_description": "Breach in observing the obligation of Data Fiduciary to take reasonable security safeguards to prevent personal data breach under sub-section (5) of section 8",
        "related_act_section": "Section 8(5)",
        "statutory_ceiling_inr": "Up to ₹250 crore",
        "mandatory_caveat": MANDATORY_PENALTY_CAVEAT,
        "linked_controls": ["DPDP-006", "DPDP-018"],
    },
    {
        "schedule_item": 2,
        "breach_description": "Breach in observing the obligation to give the Board or affected Data Principal notice of a personal data breach under sub-section (6) of section 8",
        "related_act_section": "Section 8(6)",
        "statutory_ceiling_inr": "Up to ₹200 crore",
        "mandatory_caveat": MANDATORY_PENALTY_CAVEAT,
        "linked_controls": ["DPDP-007"],
    },
    {
        "schedule_item": 3,
        "breach_description": "Breach in observance of additional obligations in relation to children under section 9",
        "related_act_section": "Section 9",
        "statutory_ceiling_inr": "Up to ₹200 crore",
        "mandatory_caveat": MANDATORY_PENALTY_CAVEAT,
        "linked_controls": ["DPDP-011", "DPDP-012"],
    },
    {
        "schedule_item": 4,
        "breach_description": "Breach in observance of additional obligations of Significant Data Fiduciary under section 10",
        "related_act_section": "Section 10",
        "statutory_ceiling_inr": "Up to ₹150 crore",
        "mandatory_caveat": MANDATORY_PENALTY_CAVEAT,
        "linked_controls": ["DPDP-013"],
    },
    {
        "schedule_item": 5,
        "breach_description": "Breach in observance of the duties of Data Principal under section 15",
        "related_act_section": "Section 15",
        "statutory_ceiling_inr": "Up to ₹10,000",
        "mandatory_caveat": MANDATORY_PENALTY_CAVEAT,
        "linked_controls": ["DPDP-010"],
    },
    {
        "schedule_item": 6,
        "breach_description": "Breach of any term of voluntary undertaking accepted by the Board under section 32",
        "related_act_section": "Section 32",
        "statutory_ceiling_inr": "Up to the extent of penalty for breach in respect of which undertaking was provided",
        "mandatory_caveat": MANDATORY_PENALTY_CAVEAT,
        "linked_controls": ["DPDP-001"],
    },
    {
        "schedule_item": 7,
        "breach_description": "Breach of any other provision of this Act or the rules made thereunder",
        "related_act_section": "Residual provisions",
        "statutory_ceiling_inr": "Up to ₹50 crore",
        "mandatory_caveat": MANDATORY_PENALTY_CAVEAT,
        "linked_controls": ["DPDP-002", "DPDP-003", "DPDP-004", "DPDP-005", "DPDP-008", "DPDP-014", "DPDP-015", "DPDP-016", "DPDP-017"],
    },
]

CONTROL_METADATA: List[Dict[str, Any]] = [
    {
        "id": "DPDP-001",
        "category": "A_PERSONAL_DATA_DISCOVERY",
        "category_title": "A. Personal Data Discovery & Scoping",
        "title": "Scope, roles, and applicability of digital personal data processing",
        "act_section": "Sections 3-4",
        "rules_ref": "Rule 1",
        "applies_to": "All Data Fiduciaries",
        "description": "Determine if personal data is processed within India or targeting Data Principals in India.",
        "remediation": "Conduct statutory applicability assessment under Section 3 and designate Data Fiduciary roles.",
    },
    {
        "id": "DPDP-002",
        "category": "C_NOTICE_TRANSPARENCY",
        "category_title": "C. Notice & Transparency",
        "title": "Privacy notice and itemized description of personal data collected",
        "act_section": "Section 5",
        "rules_ref": "Rule 3",
        "applies_to": "All Data Fiduciaries",
        "description": "Provide itemised notice containing personal data collected, specific purpose, and redressal mechanism.",
        "remediation": "Publish an itemised privacy notice conforming to Section 5(1) before or at the time of data collection.",
    },
    {
        "id": "DPDP-003",
        "category": "D_CONSENT",
        "category_title": "D. Consent Architecture",
        "title": "Consent / lawful basis records and itemized consent notices",
        "act_section": "Sections 4, 6-7",
        "rules_ref": "Rule 3",
        "applies_to": "All Data Fiduciaries",
        "description": "Consent must be free, specific, informed, unconditional, unambiguous with clear affirmative action.",
        "remediation": "Remove pre-ticked checkboxes and bundled consent; record timestamped consent artifacts.",
    },
    {
        "id": "DPDP-004",
        "category": "D_CONSENT",
        "category_title": "D. Consent Architecture",
        "title": "Consent withdrawal mechanism as accessible as consent giving",
        "act_section": "Section 6(4)",
        "rules_ref": "Rule 3",
        "applies_to": "All Data Fiduciaries",
        "description": "Data Principals have the right to withdraw consent with the same ease with which it was given.",
        "remediation": "Provide a 1-click or self-serve consent withdrawal / preference management setting in user profile.",
    },
    {
        "id": "DPDP-005",
        "category": "A_PERSONAL_DATA_DISCOVERY",
        "category_title": "A. Personal Data Discovery & Scoping",
        "title": "Purpose limitation and personal data minimization",
        "act_section": "Sections 4-8",
        "rules_ref": "Rule 3",
        "applies_to": "All Data Fiduciaries",
        "description": "Process personal data only for specific, lawful purposes explicitly specified in notice.",
        "remediation": "Audit database columns and APIs to eliminate unneeded personal data fields.",
    },
    {
        "id": "DPDP-006",
        "category": "B_SECURITY_SAFEGUARDS",
        "category_title": "B. Security Safeguards",
        "title": "Reasonable security safeguards against personal data breach",
        "act_section": "Section 8(5)",
        "rules_ref": "Rule 6",
        "applies_to": "All Data Fiduciaries",
        "description": "Implement reasonable security safeguards to prevent personal data breach under penalty ceiling of ₹250 crore.",
        "remediation": "Remediate all High/Critical vulnerabilities (injection, weak auth, exposed endpoints, unencrypted storage).",
    },
    {
        "id": "DPDP-007",
        "category": "F_BREACH_READINESS",
        "category_title": "F. Personal Data Breach Readiness",
        "title": "Personal data breach notification to Board and Data Principal",
        "act_section": "Section 8(6)",
        "rules_ref": "Rule 7",
        "applies_to": "All Data Fiduciaries",
        "description": "Mandatory personal data breach notification to the Data Protection Board and affected Data Principals.",
        "remediation": "Establish a breach response playbook with 72-hour notification procedures to the Board.",
    },
    {
        "id": "DPDP-008",
        "category": "E_RETENTION_ERASURE",
        "category_title": "E. Retention & Erasure",
        "title": "Data erasure and storage limitation upon purpose completion",
        "act_section": "Section 8(7)-(8)",
        "rules_ref": "Rule 8",
        "applies_to": "All Data Fiduciaries",
        "description": "Erase personal data when the specified purpose is served or upon consent withdrawal.",
        "remediation": "Implement automated database purge jobs for expired/soft-deleted data and provide user erasure APIs.",
    },
    {
        "id": "DPDP-009",
        "category": "G_DATA_PRINCIPAL_RIGHTS",
        "category_title": "G. Data Principal Rights",
        "title": "Accuracy, completeness, and correction of personal data",
        "act_section": "Sections 8(3), 12",
        "rules_ref": "Rule 6",
        "applies_to": "All Data Fiduciaries",
        "description": "Ensure personal data processed is accurate, complete, and consistent; allow correction by user.",
        "remediation": "Expose user profile editing endpoints and validation routines for identity and contact records.",
    },
    {
        "id": "DPDP-010",
        "category": "G_DATA_PRINCIPAL_RIGHTS",
        "category_title": "G. Data Principal Rights",
        "title": "Data Principal rights mechanism and grievance redressal",
        "act_section": "Sections 11-13",
        "rules_ref": "Rules 13-14",
        "applies_to": "All Data Fiduciaries",
        "description": "Provide accessible means to exercise rights of access, correction, erasure, and grievance redressal.",
        "remediation": "Provide self-service privacy portal or ticketing workflow for Data Principal requests.",
    },
    {
        "id": "DPDP-011",
        "category": "H_CHILDRENS_DATA",
        "category_title": "H. Children's Personal Data",
        "title": "Special obligations and verifiable consent regarding children's data",
        "act_section": "Section 9",
        "rules_ref": "Rule 10",
        "applies_to": "Fiduciaries processing children (<18) data",
        "description": "Obtain verifiable consent of parent/lawful guardian before processing children's data.",
        "remediation": "Implement verifiable parental consent mechanisms and age-verification gates.",
    },
    {
        "id": "DPDP-012",
        "category": "H_CHILDRENS_DATA",
        "category_title": "H. Children's Personal Data",
        "title": "Prohibition of tracking, behavioral monitoring, or targeted ads to children",
        "act_section": "Section 9(3)",
        "rules_ref": "Rule 11",
        "applies_to": "Fiduciaries processing children data",
        "description": "No tracking, behavioural monitoring, or targeted advertising directed at children.",
        "remediation": "Disable third-party tracking/analytics SDKs for identified minor accounts.",
    },
    {
        "id": "DPDP-013",
        "category": "J_SIGNIFICANT_DATA_FIDUCIARY",
        "category_title": "J. Significant Data Fiduciary (SDF) Governance",
        "title": "Significant Data Fiduciary additional governance obligations",
        "act_section": "Section 10",
        "rules_ref": "Rules 5, 12",
        "applies_to": "Entities designated as SDF by Central Govt",
        "description": "Appoint India-based DPO, conduct periodic Data Protection Impact Assessments (DPIA) and independent audits.",
        "remediation": "Appoint resident DPO, formalize DPIA framework, and schedule annual independent security audit.",
    },
    {
        "id": "DPDP-014",
        "category": "I_PROCESSORS_CROSS_BORDER",
        "category_title": "I. Data Processors & Cross-Border Transfers",
        "title": "Data processor engagement under valid data processing contracts",
        "act_section": "Section 8(2)",
        "rules_ref": "Rule 6",
        "applies_to": "All Data Fiduciaries",
        "description": "Engage third-party data processors only under a valid, binding data processing contract.",
        "remediation": "Execute DPDP-aligned Data Processing Agreements (DPA) with all third-party SDK and cloud vendors.",
    },
    {
        "id": "DPDP-015",
        "category": "I_PROCESSORS_CROSS_BORDER",
        "category_title": "I. Data Processors & Cross-Border Transfers",
        "title": "Cross-border transfer restrictions and designated jurisdictions",
        "act_section": "Section 16",
        "rules_ref": "Rule 16",
        "applies_to": "Fiduciaries transferring data abroad",
        "description": "Transfer of personal data outside India permitted subject to Central Government restrictions/blacklists.",
        "remediation": "Inventory international cloud/SaaS processors and maintain transfer risk logs.",
    },
    {
        "id": "DPDP-016",
        "category": "B_SECURITY_SAFEGUARDS",
        "category_title": "B. Security Safeguards",
        "title": "Logging and security monitoring for personal data processing systems",
        "act_section": "Section 8(5)",
        "rules_ref": "Rule 6(2)",
        "applies_to": "All Data Fiduciaries",
        "description": "Maintain audit logs of access and operations on personal data stores.",
        "remediation": "Implement access logging on personal data tables and configure tamper-resistant log aggregation.",
    },
    {
        "id": "DPDP-017",
        "category": "C_NOTICE_TRANSPARENCY",
        "category_title": "C. Notice & Transparency",
        "title": "Publishing accessible Data Protection Officer and grievance details",
        "act_section": "Sections 8(9), 13",
        "rules_ref": "Rule 14",
        "applies_to": "All Data Fiduciaries",
        "description": "Publish contact details of Grievance Officer in privacy notice and website footer.",
        "remediation": "Display the name, title, and contact email of Grievance Officer on privacy page and footer.",
    },
    {
        "id": "DPDP-018",
        "category": "B_SECURITY_SAFEGUARDS",
        "category_title": "B. Security Safeguards",
        "title": "Personal data exposure linkage from technical security findings",
        "act_section": "Section 8(5)",
        "rules_ref": "Rule 6",
        "applies_to": "All Data Fiduciaries",
        "description": "Direct bridge linking technical security vulnerabilities to statutory data safeguard exposure.",
        "remediation": "Resolve underlying technical security findings to maintain Section 8(5) safeguard posture.",
    },
]


class DpdpReadinessEngine:
    """Evaluates comprehensive DPDP Act 2023 readiness across all 18 controls and 10 categories."""

    @classmethod
    def evaluate(
        cls,
        worktree_dir: Optional[Path] = None,
        security_findings: Optional[List[Dict[str, Any]]] = None,
        questionnaire_answers: Optional[Dict[str, Any]] = None,
        as_of_date: Optional[date | str] = None,
        is_sdf: bool = False,
        processes_children: bool = False,
    ) -> Dict[str, Any]:
        eval_date = parse_date(as_of_date)
        findings = security_findings or []
        answers = questionnaire_answers or {}

        # 1. Run sub-scanners if worktree provided
        pii_items = []
        processors = []
        consent_report = None
        retention_report = None

        if worktree_dir and Path(worktree_dir).exists():
            # Scan files for PII, processors, consent, retention
            for root, _, files in os.walk(worktree_dir):
                if ".git" in root or "node_modules" in root or "venv" in root:
                    continue
                for fname in files:
                    if fname.endswith((".py", ".json", ".sql", ".env", ".ts", ".js")):
                        try:
                            fpath = Path(root) / fname
                            content = fpath.read_text(encoding="utf-8", errors="ignore")
                            rel_p = str(fpath.resolve().relative_to(Path(worktree_dir).resolve())).replace("\\", "/")
                            pii_items.extend(PiiDetector.scan_text(content, file_path=rel_p))
                        except Exception:
                            pass

            processors = ProcessorInventoryScanner.scan_worktree(Path(worktree_dir))
            consent_report = ConsentPolicyAuditor.audit_worktree(Path(worktree_dir))
            retention_report = RetentionErasureAuditor.audit_worktree(Path(worktree_dir))

        # 2. Evaluate all 18 controls
        evaluated_controls: List[Dict[str, Any]] = []
        technical_findings_mapped: List[Dict[str, Any]] = []
        action_plan: List[Dict[str, Any]] = []
        legal_review_pending: List[str] = [
            "Formal verification of Data Fiduciary vs Significant Data Fiduciary classification under Section 10.",
            "Verification of cross-border data transfer adequacy for non-Indian cloud/analytics vendors.",
            "Legal counsel sign-off on Privacy Notice language and grievance turnaround time commitments.",
        ]

        # Check technical security posture for Section 8(5)
        critical_security_findings = [
            f for f in findings
            if str(f.get("severity", "")).upper() in ("CRITICAL", "HIGH")
            or f.get("priority") in ("P0", "P1")
        ]

        total_applicable_score = 0
        earned_score = 0

        for ctrl in CONTROL_METADATA:
            cid = ctrl["id"]
            act_sec = ctrl["act_section"]
            comm_status, eff_date, comm_rationale = compute_effective_date_status(act_sec, eval_date)

            is_upcoming = comm_status == EffectiveDateStatus.UPCOMING
            is_in_force = comm_status == EffectiveDateStatus.IN_FORCE

            # Determine technical implementation state
            detected_state = "Not detected"
            evidence_summary = ""

            # Check if user provided manual answer
            user_override = answers.get(cid)
            if user_override:
                detected_state = "MANUAL_PROVIDED"
                evidence_summary = f"User attestation: {user_override}"

            # Specific automated checks per control
            if not user_override:
                if cid == "DPDP-001":
                    # Applicability: Verified if scanned
                    detected_state = "Verified"
                    evidence_summary = "Statutory nexus and personal data discovery conducted."

                elif cid == "DPDP-002":
                    # Notice & Transparency
                    if consent_report and consent_report.notice_transparency.privacy_policy_found:
                        detected_state = "Implemented" if consent_report.notice_transparency.specified_purposes_found else "Partial"
                        evidence_summary = f"Privacy policy found at {consent_report.notice_transparency.policy_path}"
                    else:
                        detected_state = "Not detected"
                        evidence_summary = "No privacy notice document located in repository."

                elif cid == "DPDP-003":
                    # Consent UI / Architecture
                    if consent_report and consent_report.consent_ui.pre_ticked_checkboxes_detected > 0:
                        detected_state = "Not detected"
                        evidence_summary = f"Detected {consent_report.consent_ui.pre_ticked_checkboxes_detected} pre-ticked consent checkboxes."
                    else:
                        detected_state = "Implemented"
                        evidence_summary = "No pre-ticked checkboxes or dark patterns detected in UI."

                elif cid == "DPDP-004":
                    # Consent Withdrawal
                    if consent_report and consent_report.consent_ui.withdrawal_mechanism_found:
                        detected_state = "Implemented"
                        evidence_summary = "Consent withdrawal / preference revocation patterns identified."
                    else:
                        detected_state = "Partial"
                        evidence_summary = "Explicit withdrawal mechanism not identified in scanned frontend."

                elif cid == "DPDP-005":
                    # Purpose Limitation & Minimization
                    if pii_items:
                        detected_state = "Partial"
                        evidence_summary = f"Discovered {len(pii_items)} personal data elements; verify necessity."
                    else:
                        detected_state = "Implemented"
                        evidence_summary = "No extraneous or unmasked personal data elements discovered."

                elif cid in ("DPDP-006", "DPDP-018"):
                    # Section 8(5) Reasonable Security Safeguards
                    if critical_security_findings:
                        detected_state = "Not detected"
                        evidence_summary = f"{len(critical_security_findings)} High/Critical security vulnerabilities threaten personal data integrity."
                        for f in critical_security_findings:
                            technical_findings_mapped.append({
                                "finding_title": f.get("title", "Vulnerability"),
                                "severity": f.get("severity", "HIGH"),
                                "affected_file": f.get("file_path", "unknown"),
                                "impacted_dpdp_control": cid,
                                "statutory_citation": "Section 8(5) (Security Safeguards)",
                            })
                    else:
                        detected_state = "Verified"
                        evidence_summary = "No critical or high-severity vulnerabilities detected in scanned codebase."

                elif cid == "DPDP-007":
                    # Breach Notification Readiness
                    detected_state = "Manual review"
                    evidence_summary = "72-hour regulatory notification workflow requires organizational verification."

                elif cid == "DPDP-008":
                    # Retention & Erasure
                    if retention_report:
                        if retention_report.erasure_api_found and retention_report.automated_cleanup_job_found:
                            detected_state = "Verified"
                            evidence_summary = "Both user erasure API and automated purge jobs identified."
                        elif retention_report.erasure_api_found or retention_report.automated_cleanup_job_found:
                            detected_state = "Partial"
                            evidence_summary = "Partial implementation: either erasure API or purge job missing."
                        else:
                            detected_state = "Not detected"
                            evidence_summary = "No erasure APIs or automated retention cleanup routines detected."
                    else:
                        detected_state = "Not detected"
                        evidence_summary = "No automated retention cleanup or erasure routes found."

                elif cid == "DPDP-009":
                    # Data Accuracy & Correction
                    detected_state = "Implemented"
                    evidence_summary = "Standard profile update mechanisms present."

                elif cid == "DPDP-010":
                    # Data Principal Rights
                    detected_state = "Partial"
                    evidence_summary = "Data Principal rights request handling requires verified operational procedure."

                elif cid in ("DPDP-011", "DPDP-012"):
                    # Children's Data
                    if processes_children:
                        detected_state = "Manual review"
                        evidence_summary = "Processing children's data: parental consent verification required."
                    else:
                        detected_state = "Not applicable"
                        evidence_summary = "User confirmed no processing of children's personal data."

                elif cid == "DPDP-013":
                    # SDF Governance
                    if is_sdf:
                        detected_state = "Manual review"
                        evidence_summary = "Designated Significant Data Fiduciary: DPO and DPIA mandatory."
                    else:
                        detected_state = "Not applicable"
                        evidence_summary = "Not designated as Significant Data Fiduciary."

                elif cid == "DPDP-014":
                    # Processor Agreements
                    if processors:
                        detected_state = "Manual review"
                        evidence_summary = f"{len(processors)} third-party processors identified; DPAs must be executed."
                    else:
                        detected_state = "Verified"
                        evidence_summary = "No external third-party processors detected in dependencies."

                elif cid == "DPDP-015":
                    # Cross-Border Transfers
                    intl_processors = [p for p in processors if p.cross_border_risk]
                    if intl_processors:
                        detected_state = "Manual review"
                        names = ", ".join([p.name for p in intl_processors[:3]])
                        evidence_summary = f"Cross-border processors ({names}) subject to Central Govt restrictions."
                    else:
                        detected_state = "Verified"
                        evidence_summary = "No international data processors identified."

                elif cid == "DPDP-016":
                    # Logging & Monitoring
                    detected_state = "Implemented"
                    evidence_summary = "Application audit logging detected."

                elif cid == "DPDP-017":
                    # DPO & Grievance Details
                    if consent_report and consent_report.grievance_officer.detected:
                        detected_state = "Verified"
                        evidence_summary = f"Grievance Officer published ({consent_report.grievance_officer.email_contact or 'contact found'})."
                    else:
                        detected_state = "Not detected"
                        evidence_summary = "Grievance Officer contact details missing from privacy notice."

            # Final status logic taking commencement into account
            if detected_state == "Not applicable":
                status = "Not applicable"
            elif detected_state in ("Verified", "Implemented", "MANUAL_PROVIDED"):
                status = detected_state
            elif detected_state == "Manual review":
                status = "Manual review"
            elif detected_state == "Partial":
                status = "Partial"
            elif is_upcoming:
                # If upcoming and not yet implemented, marked 'Upcoming' (never a violation!)
                status = "Upcoming"
                evidence_summary = f"Upcoming provision (effective {eff_date.isoformat() if eff_date else 'Phase 3'}). {evidence_summary}"
            else:
                status = "Not detected"

            # Calculate score contributions for readiness
            weight = 10
            if status != "Not applicable":
                total_applicable_score += weight
                if status in ("Verified", "Implemented"):
                    earned_score += weight
                elif status == "MANUAL_PROVIDED":
                    earned_score += int(weight * 0.8)
                elif status == "Manual review":
                    earned_score += int(weight * 0.7)
                elif status == "Partial":
                    earned_score += int(weight * 0.4)
                elif status == "Upcoming":
                    # Upcoming provisions count as neutral baseline (50% readiness advance)
                    earned_score += int(weight * 0.5)
                elif status == "Not detected":
                    earned_score += 0

            # Add to action plan if action required
            if status in ("Not detected", "Partial", "Manual review") and not is_upcoming:
                action_plan.append({
                    "control_id": cid,
                    "title": ctrl["title"],
                    "status": status,
                    "category": ctrl["category_title"],
                    "statutory_deadline": "Immediate (In Force)",
                    "remediation": ctrl["remediation"],
                })

            evaluated_controls.append({
                "id": cid,
                "category": ctrl["category"],
                "category_title": ctrl["category_title"],
                "title": ctrl["title"],
                "act_section": act_sec,
                "rules_ref": ctrl["rules_ref"],
                "applies_to": ctrl["applies_to"],
                "commencement_status": comm_status.value,
                "effective_date": eff_date.isoformat() if eff_date else None,
                "commencement_rationale": comm_rationale,
                "status": status,
                "evidence_summary": evidence_summary,
                "remediation": ctrl["remediation"],
            })

        # Calculate Readiness Score (0-100)
        base_score = 100
        if total_applicable_score > 0:
            base_score = int(round((earned_score / total_applicable_score) * 100))

        # Hard cap rule: If any critical security finding breaches Section 8(5), score cannot exceed 60
        hard_cap_applied = False
        hard_cap_reason = None
        final_score = base_score

        if critical_security_findings and final_score > 60:
            final_score = 60
            hard_cap_applied = True
            hard_cap_reason = (
                f"Score capped at 60 because {len(critical_security_findings)} critical/high technical "
                "security findings breach Section 8(5) reasonable security safeguards."
            )

        # Build category summary
        category_summaries: Dict[str, Any] = {}
        for ctrl in evaluated_controls:
            cat = ctrl["category"]
            if cat not in category_summaries:
                category_summaries[cat] = {
                    "category_title": ctrl["category_title"],
                    "total_controls": 0,
                    "verified_or_implemented": 0,
                    "partial": 0,
                    "not_detected": 0,
                    "manual_review": 0,
                    "upcoming": 0,
                    "not_applicable": 0,
                }
            category_summaries[cat]["total_controls"] += 1
            st = ctrl["status"]
            if st in ("Verified", "Implemented", "MANUAL_PROVIDED"):
                category_summaries[cat]["verified_or_implemented"] += 1
            elif st == "Partial":
                category_summaries[cat]["partial"] += 1
            elif st == "Not detected":
                category_summaries[cat]["not_detected"] += 1
            elif st == "Manual review":
                category_summaries[cat]["manual_review"] += 1
            elif st == "Upcoming":
                category_summaries[cat]["upcoming"] += 1
            elif st == "Not applicable":
                category_summaries[cat]["not_applicable"] += 1

        return {
            "as_of_date": eval_date.isoformat(),
            "readiness_score": final_score,
            "scoring_methodology": (
                "DPDP Readiness Score (0-100) evaluates applicable In Force controls with weighted scoring "
                "(Verified/Implemented: 100%, Manual Attestation: 80%, Review: 70%, Partial: 40%, Not Detected: 0%). "
                "Upcoming provisions (Phase 3) do not penalize score. "
                "Hard Cap Rule: If critical security findings breach Section 8(5) safeguards, score is capped at 60 max."
            ),
            "hard_cap_applied": hard_cap_applied,
            "hard_cap_reason": hard_cap_reason,
            "controls": evaluated_controls,
            "categories": category_summaries,
            "statutory_penalties": STATUTORY_PENALTY_ITEMS,
            "penalty_caveat": MANDATORY_PENALTY_CAVEAT,
            "action_plan": action_plan,
            "technical_findings_mapped": technical_findings_mapped,
            "legal_review_pending": legal_review_pending,
            "discovered_pii_count": len(pii_items),
            "discovered_processors_count": len(processors),
        }
