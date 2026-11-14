"""Report context collector (FR-RPT, Design §12).

Gathers all data for an audit from database tables and policy definitions,
structuring it deterministically without raw secrets or predicted fines.
"""
from typing import Any
from datetime import datetime
from sqlalchemy.orm import Session

from app.models.models import (
    AuditModel,
    RepositoryModel,
    FindingModel,
    EvidenceModel,
    ScannerRunModel,
    ControlResultModel,
    RemediationActionModel,
    LegalSourceModel,
    PenaltyCategoryModel
)
from app.services.policy_loader import load_and_validate_policies
from app.dpdp.commencement import compute_effective_date_status, parse_date

AS_OF_DATE_DEFAULT = parse_date(None)


def collect_audit_report_data(audit_id: str, db: Session) -> dict[str, Any]:
    """Compile comprehensive, structured audit report context for PDF and JSON generation."""
    audit = db.query(AuditModel).filter(AuditModel.id == audit_id).first()
    if not audit:
        raise ValueError(f"Audit '{audit_id}' not found.")

    repo = db.query(RepositoryModel).filter(RepositoryModel.id == audit.repository_id).first()

    # Load scanner runs and versions
    runs = db.query(ScannerRunModel).filter(ScannerRunModel.audit_id == audit_id).all()
    scanner_runs_data = [
        {
            "scanner": getattr(r, "scanner", None) or getattr(r, "scanner_name", ""),
            "version": getattr(r, "version", None) or getattr(r, "scanner_version", ""),
            "status": r.status,
            "duration_ms": r.duration_ms,
            "findings_count": r.findings_count,
            "error_code": getattr(r, "error_code", None)
        }
        for r in runs
    ]

    # Load findings with evidence
    findings = db.query(FindingModel).filter(FindingModel.audit_id == audit_id).order_by(FindingModel.start_line.asc()).all()
    findings_data = []
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    confirmed_count = 0
    potential_count = 0

    for f in findings:
        sev = f.severity.upper() if f.severity else "INFO"
        if sev in severity_counts:
            severity_counts[sev] += 1

        conf = f.confidence.upper() if f.confidence else "LOW"
        if conf == "CONFIRMED":
            confirmed_count += 1
        else:
            potential_count += 1

        ev = db.query(EvidenceModel).filter(EvidenceModel.finding_id == f.id).first()
        evidence_dict = None
        if ev:
            evidence_dict = {
                "tier": ev.tier,
                "path": ev.path,
                "start_line": ev.start_line,
                "end_line": ev.end_line,
                "redacted_excerpt": ev.redacted_excerpt,
                "provenance": ev.provenance
            }

        findings_data.append({
            "id": f.id,
            "fingerprint": f.fingerprint,
            "rule_id": f.rule_id,
            "scanner_name": f.scanner_name,
            "scanner_version": f.scanner_version,
            "title": f.title,
            "description": f.description,
            "category": f.category,
            "severity": f.severity,
            "confidence": f.confidence,
            "file_path": f.file_path,
            "start_line": f.start_line,
            "end_line": f.end_line,
            "cwe_ids": f.cwe_ids or [],
            "owasp_refs": f.owasp_refs or [],
            "redacted_snippet": f.redacted_snippet,
            "technical_fix": f.technical_fix or "Review code configuration and apply defensive controls.",
            "validation_steps": f.validation_steps or "Re-run scan to verify finding clearance.",
            "evidence": evidence_dict
        })

    # Load security controls
    sec_controls_db = db.query(ControlResultModel).filter(
        ControlResultModel.audit_id == audit_id,
        ControlResultModel.domain == "SECURITY"
    ).all()

    sec_summary = {
        "total_controls": 32,
        "evidenced_pass": 0,
        "evidenced_fail": 0,
        "potential_gap": 0,
        "not_verified": 0,
        "not_applicable": 0,
        "error": 0
    }
    sec_controls_list = []
    evidence_gaps = []

    for sc in sec_controls_db:
        st = sc.state.upper()
        if st == "PASS_EVIDENCED":
            sec_summary["evidenced_pass"] += 1
        elif st == "FAIL_EVIDENCED":
            sec_summary["evidenced_fail"] += 1
        elif st == "POTENTIAL_GAP":
            sec_summary["potential_gap"] += 1
            evidence_gaps.append({
                "control_id": sc.control_id,
                "domain": "SECURITY",
                "state": "POTENTIAL_GAP",
                "rationale": sc.rationale
            })
        elif st == "NOT_VERIFIED":
            sec_summary["not_verified"] += 1
            evidence_gaps.append({
                "control_id": sc.control_id,
                "domain": "SECURITY",
                "state": "NOT_VERIFIED",
                "rationale": sc.rationale
            })
        elif st == "NOT_APPLICABLE":
            sec_summary["not_applicable"] += 1
        elif st == "ERROR":
            sec_summary["error"] += 1

        sec_controls_list.append({
            "control_id": sc.control_id,
            "domain": sc.domain,
            "state": sc.state,
            "rationale": sc.rationale,
            "evidence_tier": sc.evidence_tier
        })

    evidenced_controls = sec_summary["evidenced_pass"] + sec_summary["evidenced_fail"]
    applicable_controls = 32 - sec_summary["not_applicable"]
    coverage_ratio_str = f"{evidenced_controls}/{applicable_controls}" if applicable_controls > 0 else "0/32"

    # Load DPDP controls and dynamic commencement
    dpdp_controls_db = db.query(ControlResultModel).filter(
        ControlResultModel.audit_id == audit_id,
        ControlResultModel.domain == "DPDP"
    ).all()

    bundle = load_and_validate_policies()

    dpdp_controls_list = []
    for dc in dpdp_controls_db:
        ctrl_def = next((c for c in bundle.dpdp_controls.controls if c.id == dc.control_id), None)
        prov = f"{ctrl_def.act_section} {ctrl_def.rules_ref}" if ctrl_def else dc.control_id
        eff_status_enum, eff_date_obj, eff_rationale = compute_effective_date_status(prov, AS_OF_DATE_DEFAULT)
        eff_status = eff_status_enum.value
        eff_date = eff_date_obj.strftime("%d %B %Y") if eff_date_obj else "Date not yet notified"
        if ctrl_def and ctrl_def.legal_source:
            ls = ctrl_def.legal_source
            doc = ls.get("document") if isinstance(ls, dict) else getattr(ls, "document", "DPDP Act 2023")
            clause = ls.get("clause") if isinstance(ls, dict) else getattr(ls, "clause", "")
            gazette = ls.get("gazette_id") if isinstance(ls, dict) else getattr(ls, "gazette_id", "")
            cit = f"{doc} ({clause}, {gazette})" if gazette else f"{doc} ({clause})"
        else:
            cit = "DPDP Act 2023"

        dpdp_controls_list.append({
            "control_id": dc.control_id,
            "title": ctrl_def.title if ctrl_def else dc.control_id,
            "state": dc.state,
            "rationale": dc.rationale,
            "effective_status": eff_status,
            "effective_date": eff_date,
            "citation": cit
        })

    # Load Legal Exposure & Penalty Reference (strictly statutory ceilings + caveat)
    penalty_categories = [
        {
            "schedule_item": 1,
            "related_act_section": "Section 8(5)",
            "statutory_ceiling_inr": "₹250 crore",
            "obligation": "Breach in observing reasonable security safeguards to prevent personal data breach",
            "linked_controls": ["DPDP-006", "DPDP-018"],
            "caveat": "Potential legal category; applicability and liability not determined."
        },
        {
            "schedule_item": 2,
            "related_act_section": "Section 8(6)",
            "statutory_ceiling_inr": "₹200 crore",
            "obligation": "Breach in giving notice of a personal data breach to the Board and affected Data Principals",
            "linked_controls": ["DPDP-014"],
            "caveat": "Potential legal category; applicability and liability not determined."
        },
        {
            "schedule_item": 3,
            "related_act_section": "Section 9",
            "statutory_ceiling_inr": "₹200 crore",
            "obligation": "Breach in observance of additional obligations in relation to children",
            "linked_controls": ["DPDP-008", "DPDP-009"],
            "caveat": "Potential legal category; applicability and liability not determined."
        },
        {
            "schedule_item": 4,
            "related_act_section": "Section 10",
            "statutory_ceiling_inr": "₹150 crore",
            "obligation": "Breach in observance of additional obligations of Significant Data Fiduciary",
            "linked_controls": ["DPDP-010"],
            "caveat": "Potential legal category; applicability and liability not determined."
        },
        {
            "schedule_item": 5,
            "related_act_section": "Section 15",
            "statutory_ceiling_inr": "₹10,000",
            "obligation": "Breach in observance of duties of Data Principal",
            "linked_controls": ["DPDP-017"],
            "caveat": "Potential legal category; applicability and liability not determined."
        },
        {
            "schedule_item": 6,
            "related_act_section": "Section 32",
            "statutory_ceiling_inr": "Up to underlying breach amount",
            "obligation": "Breach of any term of voluntary undertaking accepted by Board",
            "linked_controls": [],
            "caveat": "Potential legal category; applicability and liability not determined."
        },
        {
            "schedule_item": 7,
            "related_act_section": "Other provisions",
            "statutory_ceiling_inr": "₹50 crore",
            "obligation": "Breach of any other provision of Act or Rules",
            "linked_controls": ["DPDP-001", "DPDP-002", "DPDP-003", "DPDP-004", "DPDP-005", "DPDP-007", "DPDP-011", "DPDP-012", "DPDP-013", "DPDP-015", "DPDP-016"],
            "caveat": "Potential legal category; applicability and liability not determined."
        }
    ]

    # Load Remediations
    remediations_db = db.query(RemediationActionModel).filter(RemediationActionModel.audit_id == audit_id).all()
    remediations_data = {
        "ENGINEERING": [],
        "DOCUMENTATION": [],
        "ORGANIZATIONAL": []
    }
    for r in remediations_db:
        cat = r.action_type.upper() if r.action_type else "ENGINEERING"
        if cat not in remediations_data:
            remediations_data[cat] = []
        remediations_data[cat].append({
            "priority": r.priority,
            "target_id": r.target_id,
            "title": r.title,
            "steps": r.steps_json or [],
            "validation_method": r.validation_method
        })

    return {
        "metadata": {
            "audit_id": audit.id,
            "created_at": audit.created_at.isoformat() if audit.created_at else datetime.utcnow().isoformat(),
            "status": audit.status,
            "stage": getattr(audit, "current_stage", None) or getattr(audit, "stage", "QUEUED"),
            "scopes": audit.scopes if audit.scopes else ["security", "dpdp"],
            "mandatory_header": "Developer-assistance report — not a security certificate or legal opinion.",
            "as_of_date": AS_OF_DATE_DEFAULT.isoformat(),
            "report_version": "1.0.0"
        },
        "repository": {
            "id": repo.id if repo else "",
            "url": (getattr(repo, "canonical_url", None) or getattr(repo, "github_url", "")) if repo else "",
            "branch": (getattr(repo, "default_branch", None) or "main") if repo else "main",
            "commit_sha": (audit.commit_sha or getattr(repo, "last_commit_sha", "unknown")) if repo else (audit.commit_sha or "unknown"),
            "languages": getattr(repo, "detected_languages", {}) if repo else {},
            "frameworks": getattr(repo, "detected_frameworks", []) if repo else []
        },
        "tool_versions": scanner_runs_data,
        "executive_summary": {
            "total_findings": len(findings_data),
            "severity_counts": severity_counts,
            "confirmed_count": confirmed_count,
            "potential_count": potential_count,
            "security_coverage_ratio": coverage_ratio_str,
            "security_evidenced_controls": evidenced_controls,
            "security_applicable_controls": applicable_controls,
            "security_total_controls": 32,
            "headline_grade": "NONE (Explicitly omitted per FRD §8 / Design §12: counts and coverage over grades)"
        },
        "methodology_and_exclusions": {
            "scanner_sandbox": "Isolated runner with --network=none, non-root user, read-only repository mount, dropped Linux capabilities (Z4).",
            "repo_execution_policy": "Zero repository code execution. Cloned scripts, install hooks, and test workflows are never executed (Safety Rule 1).",
            "advisory_resolver": "Separated trusted resolution channel with strict domain allowlists (Z5).",
            "limitations": [
                "Static analysis cannot prove the runtime absence of vulnerabilities (Unknown is never Pass).",
                "Reverse proxies, API gateways, and external IAM providers cannot be observed from repository code alone.",
                "DPDP readiness evaluation does not constitute a legal opinion or certify statutory compliance."
            ]
        },
        "findings": findings_data,
        "security_controls": sec_controls_list,
        "security_summary": sec_summary,
        "dpdp_controls": dpdp_controls_list,
        "legal_exposure": {
            "disclaimer": "Potential legal category; applicability and liability not determined.",
            "categories": penalty_categories,
            "fine_prediction_prohibited": True,
            "summed_fine_prohibited": True
        },
        "remediation_plan": remediations_data,
        "evidence_gaps": evidence_gaps
    }
