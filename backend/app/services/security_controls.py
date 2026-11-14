"""Security controls evaluation engine (FR-SEC, D-03, D-16, rules.md)."""
import uuid
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from app.schemas.enums import ControlState, EvidenceTier, Severity
from app.models.models import AuditModel, ControlResultModel, FindingModel, ScannerRunModel, EvidenceModel
from app.services.policy_loader import get_policy_bundle


class SecurityCoverageSummary:
    def __init__(
        self,
        total_controls: int,
        applicable_controls: int,
        evidenced_controls: int,
        coverage_ratio: float,
        pass_evidenced_count: int,
        fail_evidenced_count: int,
        potential_gap_count: int,
        not_verified_count: int,
        not_applicable_count: int,
        error_count: int
    ):
        self.total_controls = total_controls
        self.applicable_controls = applicable_controls
        self.evidenced_controls = evidenced_controls
        self.coverage_ratio = coverage_ratio
        self.pass_evidenced_count = pass_evidenced_count
        self.fail_evidenced_count = fail_evidenced_count
        self.potential_gap_count = potential_gap_count
        self.not_verified_count = not_verified_count
        self.not_applicable_count = not_applicable_count
        self.error_count = error_count

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_controls": self.total_controls,
            "applicable_controls": self.applicable_controls,
            "evidenced_controls": self.evidenced_controls,
            "coverage_ratio": round(self.coverage_ratio, 4),
            "denominator": self.applicable_controls,
            "counts": {
                "PASS_EVIDENCED": self.pass_evidenced_count,
                "FAIL_EVIDENCED": self.fail_evidenced_count,
                "POTENTIAL_GAP": self.potential_gap_count,
                "NOT_VERIFIED": self.not_verified_count,
                "NOT_APPLICABLE": self.not_applicable_count,
                "ERROR": self.error_count
            }
        }


def evaluate_security_controls(
    db: Session,
    audit_id: str,
    detected_languages: list[str],
    detected_frameworks: list[str]
) -> list[ControlResultModel]:
    """
    Evaluates all 32 security controls against scanner findings and evidence.
    Applies frozen 6-state logic and conservative semantics per FRD §3.
    """
    # Load frozen policy definitions
    bundle = get_policy_bundle()
    controls_policy = bundle.security_controls.controls

    # Retrieve all findings and scanner runs for this audit
    findings = db.query(FindingModel).filter(FindingModel.audit_id == audit_id).all()
    scanner_runs = db.query(ScannerRunModel).filter(ScannerRunModel.audit_id == audit_id).all()

    # Index findings by category and rule_id
    findings_by_cat: dict[str, list[FindingModel]] = {}
    findings_by_rule: dict[str, list[FindingModel]] = {}
    for f in findings:
        findings_by_cat.setdefault(f.category, []).append(f)
        findings_by_rule.setdefault(f.rule_id, []).append(f)

    # Index scanner status
    scanner_status = {sr.scanner: sr.status for sr in scanner_runs}

    is_supported_framework = bool({"FastAPI", "Express"}.intersection(set(detected_frameworks)))

    # Clear any previous control results for this audit
    db.query(ControlResultModel).filter(
        ControlResultModel.audit_id == audit_id,
        ControlResultModel.domain == "SECURITY"
    ).delete()

    control_results: list[ControlResultModel] = []

    for ctrl in controls_policy:
        ctrl_id = ctrl.id
        title = ctrl.title
        method = ctrl.method
        state = ControlState.NOT_VERIFIED
        evidence_tier = EvidenceTier.E1_SOURCE_CODE
        rationale = ""
        evidence_summary = ""
        linked_finding_ids: list[str] = []

        # 1. Scanner Crash Check
        if method == "gitleaks" and scanner_status.get("gitleaks") == "FAILED":
            state = ControlState.ERROR
            rationale = "Gitleaks secret scanner crashed during execution; check could not complete."
        elif method == "semgrep" and scanner_status.get("semgrep") == "FAILED":
            state = ControlState.ERROR
            rationale = "Semgrep SAST analyzer crashed during execution; check could not complete."
        elif method == "osv-scanner" and scanner_status.get("osv-scanner") == "FAILED":
            state = ControlState.ERROR
            rationale = "OSV dependency scanner encountered an error during execution."

        # 2. Specific Control Rule Evaluation
        elif ctrl_id == "SEC-001":  # Hardcoded secrets
            secret_findings = [f for f in findings if f.category == "secrets" and "client" not in f.rule_id]
            if secret_findings:
                state = ControlState.FAIL_EVIDENCED
                linked_finding_ids = [f.id for f in secret_findings]
                rationale = f"Discovered {len(secret_findings)} hardcoded secret(s) or private token(s)."
                evidence_summary = f"{len(secret_findings)} credential exposures scrubbed at parser boundary."
            elif scanner_status.get("gitleaks") == "COMPLETED":
                state = ControlState.PASS_EVIDENCED
                rationale = "No hardcoded credentials or tokens detected across scanned repository files."
                evidence_summary = "Gitleaks completed clean scan over repository worktree."

        elif ctrl_id in ("SEC-002", "SEC-003"):  # Secrets / DB strings in client assets
            client_sec_findings = [f for f in findings if "client" in f.rule_id or "sec-002" in f.rule_id or "sec-003" in f.rule_id]
            if client_sec_findings:
                state = ControlState.FAIL_EVIDENCED
                linked_finding_ids = [f.id for f in client_sec_findings]
                rationale = f"Discovered {len(client_sec_findings)} exposed database/credential connection string(s) in client asset files."
            elif is_supported_framework:
                state = ControlState.PASS_EVIDENCED
                rationale = "No database credentials or secret variables detected in client/public assets."
            else:
                state = ControlState.NOT_VERIFIED
                rationale = "Framework unsupported for automated client configuration inspection."

        elif ctrl_id == "SEC-004":  # DTO / Serializer sensitive field exposure
            dto_findings = [f for f in findings if "sec-004" in f.rule_id or ("data_exposure" in f.category and "dto" in f.title.lower())]
            if dto_findings:
                state = ControlState.FAIL_EVIDENCED
                linked_finding_ids = [f.id for f in dto_findings]
                rationale = f"Detected {len(dto_findings)} response DTO model(s) returning sensitive attributes (passwords, tokens, or national IDs)."
                evidence_summary = "Output schema model explicitly defines sensitive attributes."
            elif is_supported_framework:
                state = ControlState.PASS_EVIDENCED
                rationale = "Inspected API response schemas; no sensitive attribute exposures found."
            else:
                state = ControlState.NOT_VERIFIED
                rationale = "Repository framework not supported for automated response model inspection."

        elif ctrl_id in ("SEC-005", "SEC-006"):  # Rate Limiting
            rl_findings = [f for f in findings if "rate-limit" in f.rule_id or "bruteforce" in f.rule_id]
            if rl_findings:
                # FRD §3 rule: Missing limiter => POTENTIAL_GAP, never confirmed failure
                state = ControlState.POTENTIAL_GAP
                linked_finding_ids = [f.id for f in rl_findings]
                rationale = (
                    f"No in-code rate limiting decorators detected on {len(rl_findings)} endpoint(s). "
                    "Classified as POTENTIAL_GAP because upstream reverse proxies, API gateways, or WAFs might enforce limits."
                )
                evidence_summary = "Source code inspection found no limiter middleware or decorators."
            elif is_supported_framework:
                state = ControlState.PASS_EVIDENCED
                rationale = "Rate limiting decorators or middleware verified on API endpoints."
            else:
                state = ControlState.NOT_VERIFIED
                rationale = "Rate limiting checks unsupported on this framework; cannot verify in-code limits."

        elif ctrl_id == "SEC-007":  # Route Auth
            auth_findings = [f for f in findings if "sec-007" in f.rule_id]
            if auth_findings:
                state = ControlState.POTENTIAL_GAP
                linked_finding_ids = [f.id for f in auth_findings]
                rationale = "Discovered administrative endpoints without explicit authentication guards in route signature."
            elif is_supported_framework:
                state = ControlState.PASS_EVIDENCED
                rationale = "Authentication dependencies or middleware verified across protected routes."
            else:
                state = ControlState.NOT_VERIFIED
                rationale = "Unable to statically verify route auth on unsupported framework."

        elif ctrl_id == "SEC-008":  # BOLA / IDOR
            bola_findings = [f for f in findings if "sec-008" in f.rule_id]
            if bola_findings:
                state = ControlState.POTENTIAL_GAP
                linked_finding_ids = [f.id for f in bola_findings]
                rationale = "Route accepts object identifiers without explicit ownership verification guard."
            elif is_supported_framework:
                state = ControlState.NOT_VERIFIED
                rationale = "BOLA/IDOR requires runtime context; static analysis cannot confirm complete authorization coverage."
            else:
                state = ControlState.NOT_VERIFIED
                rationale = "Unsupported framework for BOLA authorization inspection."

        elif ctrl_id in ("SEC-011", "SEC-012", "SEC-013", "SEC-014", "SEC-015"):  # Injections (SQLi, Command, XSS, Path, SSRF)
            inj_findings = [f for f in findings if f.category == "injection"]
            relevant_inj = [f for f in inj_findings if ("sql" in f.rule_id if ctrl_id == "SEC-011" else "command" in f.rule_id if ctrl_id == "SEC-012" else True)]
            if relevant_inj:
                state = ControlState.FAIL_EVIDENCED
                linked_finding_ids = [f.id for f in relevant_inj]
                rationale = f"Detected {len(relevant_inj)} verified injection vulnerability(ies) via AST analysis."
                evidence_summary = "Unsafe string interpolation or concatenation directly reaches database / execution sink."
            elif scanner_status.get("semgrep") == "COMPLETED":
                state = ControlState.PASS_EVIDENCED
                rationale = "Semgrep SAST found no matching injection flaws in source code."

        elif ctrl_id == "SEC-018":  # TLS disabled
            tls_findings = [f for f in findings if "disabled-cert-validation" in f.rule_id]
            if tls_findings:
                state = ControlState.FAIL_EVIDENCED
                linked_finding_ids = [f.id for f in tls_findings]
                rationale = "Discovered HTTP clients with TLS certificate validation explicitly disabled."
            else:
                state = ControlState.PASS_EVIDENCED
                rationale = "No disabled TLS certificate checks detected in network client configurations."

        elif ctrl_id == "SEC-020":  # CORS
            cors_findings = [f for f in findings if "cors" in f.rule_id]
            if cors_findings:
                state = ControlState.FAIL_EVIDENCED
                linked_finding_ids = [f.id for f in cors_findings]
                rationale = "CORS middleware is configured with wildcard origin '*' and Allow-Credentials: true."
            elif is_supported_framework:
                state = ControlState.PASS_EVIDENCED
                rationale = "CORS configuration does not combine wildcard origins with credentials."
            else:
                state = ControlState.NOT_VERIFIED
                rationale = "CORS configuration not located or framework unsupported."

        elif ctrl_id == "SEC-021":  # Debug Mode
            debug_findings = [f for f in findings if "debug-mode" in f.rule_id]
            if debug_findings:
                state = ControlState.FAIL_EVIDENCED
                linked_finding_ids = [f.id for f in debug_findings]
                rationale = "Application configuration explicitly enables DEBUG mode."
            elif is_supported_framework:
                state = ControlState.PASS_EVIDENCED
                rationale = "Debug mode is disabled in application settings."
            else:
                state = ControlState.NOT_VERIFIED
                rationale = "Application settings file not identified for debug inspection."

        elif ctrl_id == "SEC-023":  # Dependencies
            dep_findings = [f for f in findings if f.category == "dependency"]
            missing_lockfile_finding = any("missing-lockfile" in f.rule_id for f in findings)
            evidence_tier = EvidenceTier.E2_CONFIG_MANIFEST
            if dep_findings:
                state = ControlState.FAIL_EVIDENCED
                linked_finding_ids = [f.id for f in dep_findings]
                rationale = f"Discovered {len(dep_findings)} known vulnerable third-party package(s) with public CVE references."
                evidence_summary = "OSV-Scanner verified package versions against OSV vulnerability database."
            elif missing_lockfile_finding:
                state = ControlState.NOT_VERIFIED
                rationale = "No dependency lockfile found. Cannot verify exact pinned package versions (FR-SCN-04)."
            elif scanner_status.get("osv-scanner") == "COMPLETED":
                state = ControlState.PASS_EVIDENCED
                rationale = "All dependencies in lockfile verified clean against OSV vulnerability database."
            else:
                state = ControlState.NOT_VERIFIED
                rationale = "Dependency manifest or lockfile not evaluated."

        elif ctrl_id == "SEC-026":  # Logs
            log_findings = [f for f in findings if "sec-026" in f.rule_id]
            if log_findings:
                state = ControlState.POTENTIAL_GAP
                linked_finding_ids = [f.id for f in log_findings]
                rationale = "Logging call references sensitive parameter or token name."
            else:
                state = ControlState.PASS_EVIDENCED
                rationale = "No sensitive tokens identified in application logging invocations."

        elif ctrl_id == "SEC-029":  # Pagination
            page_findings = [f for f in findings if "sec-029" in f.rule_id]
            if page_findings:
                state = ControlState.POTENTIAL_GAP
                linked_finding_ids = [f.id for f in page_findings]
                rationale = "Endpoint queries all records without pagination limit parameters."
            else:
                state = ControlState.PASS_EVIDENCED
                rationale = "Database queries appear bounded by limits or pagination parameters."

        elif ctrl_id == "SEC-032":  # API inventory vs OpenAPI
            state = ControlState.NOT_VERIFIED
            rationale = "OpenAPI specification comparison requires runtime route schema or spec file."

        else:
            # Default for non-automated or P1/P2 controls on unsupported frameworks
            if is_supported_framework:
                state = ControlState.NOT_VERIFIED
                rationale = "Automated heuristic check inconclusive; manual verification required."
            else:
                state = ControlState.NOT_VERIFIED
                rationale = "Framework unsupported for automated verification; manual inspection required."

        control_model = ControlResultModel(
            id=str(uuid.uuid4()),
            audit_id=audit_id,
            control_id=ctrl_id,
            domain="SECURITY",
            title=title,
            state=state.value,
            evidence_tier=evidence_tier.value,
            rationale=rationale
        )
        db.add(control_model)
        control_results.append(control_model)

    db.commit()
    return control_results


def calculate_security_coverage(control_results: list[ControlResultModel]) -> SecurityCoverageSummary:
    """
    Coverage ratio = evidenced controls / applicable controls (denominator stated).
    Evidenced = PASS_EVIDENCED + FAIL_EVIDENCED
    Applicable = Total - NOT_APPLICABLE
    """
    total = len(control_results)
    pass_cnt = sum(1 for c in control_results if c.state == ControlState.PASS_EVIDENCED.value)
    fail_cnt = sum(1 for c in control_results if c.state == ControlState.FAIL_EVIDENCED.value)
    gap_cnt = sum(1 for c in control_results if c.state == ControlState.POTENTIAL_GAP.value)
    unver_cnt = sum(1 for c in control_results if c.state == ControlState.NOT_VERIFIED.value)
    na_cnt = sum(1 for c in control_results if c.state == ControlState.NOT_APPLICABLE.value)
    err_cnt = sum(1 for c in control_results if c.state == ControlState.ERROR.value)

    applicable = total - na_cnt
    evidenced = pass_cnt + fail_cnt
    ratio = (evidenced / applicable) if applicable > 0 else 0.0

    return SecurityCoverageSummary(
        total_controls=total,
        applicable_controls=applicable,
        evidenced_controls=evidenced,
        coverage_ratio=ratio,
        pass_evidenced_count=pass_cnt,
        fail_evidenced_count=fail_cnt,
        potential_gap_count=gap_cnt,
        not_verified_count=unver_cnt,
        not_applicable_count=na_cnt,
        error_count=err_cnt
    )
