"""Finding normalization, deduplication, and persistence service."""
import hashlib
import uuid
from typing import List, Dict, Tuple
from sqlalchemy.orm import Session

from app.core.security import redact_text, assert_no_raw_secret
from app.models.models import (
    AuditModel,
    FindingModel,
    EvidenceModel,
    ScannerRunModel
)
from app.schemas.finding import FindingCreate
from app.schemas.enums import EvidenceTier
from app.scanners.base import ScannerExecutionResult
from app.services.finding_engine import compute_unified_priority, enrich_standards_mapping


def normalize_and_persist_scan_results(
    db: Session,
    audit_id: str,
    scanner_results: list[ScannerExecutionResult]
) -> tuple[int, bool]:
    """
    Normalize disparate scanner outputs into single Finding and Evidence records.
    Deduplicates findings ONLY when source file, line range, and category match.
    Enforces Partial-Failure Rule: any scanner failure sets audit status to PARTIAL.
    Returns (total_findings_count, has_failures).
    """
    audit = db.query(AuditModel).filter(AuditModel.id == audit_id).first()
    if not audit:
        return 0, False

    has_failures = False
    total_findings = 0

    # 1. Record Scanner Runs
    for res in scanner_results:
        if res.status in ("FAILED", "TIMEOUT"):
            has_failures = True

        scanner_name = res.scanner.value if hasattr(res.scanner, "value") else str(res.scanner)
        run_model = ScannerRunModel(
            id=str(uuid.uuid4()),
            audit_id=audit_id,
            scanner=scanner_name,
            version=res.version,
            status=res.status,
            duration_ms=res.duration_ms,
            findings_count=len(res.raw_findings),
            error_code=res.error_code or (res.error_message[:50] if res.error_message else None)
        )
        db.add(run_model)
        db.commit()

    # 2. Collect and deduplicate findings across scanners
    # Deduplication map key: (canonical_path, start_line, end_line, category)
    dedupe_map: dict[tuple[str, int, int, str], FindingModel] = {}

    for res in scanner_results:
        # Normalize raw findings through adapter
        if not res.raw_findings:
            continue

        for raw in res.raw_findings:
            # Deterministic fingerprint
            clean_path = raw.file_path.replace("\\", "/").lstrip("/")
            fp_raw = f"{raw.rule_id}:{clean_path}:{raw.start_line}:{raw.end_line}:{raw.category}"
            fingerprint = hashlib.sha256(fp_raw.encode("utf-8")).hexdigest()

            # Parser-level redaction assertion
            clean_snippet = redact_text(raw.raw_snippet)

            scanner_name = res.scanner.value if hasattr(res.scanner, "value") else str(res.scanner)
            scanner_signal = f"Confirmed by {scanner_name}"

            dedupe_key = (clean_path, raw.start_line, raw.end_line, raw.category)

            if dedupe_key in dedupe_map:
                # Merge secondary scanner metadata into existing finding with signals
                existing = dedupe_map[dedupe_key]
                merged_cwes = sorted(list(set(existing.cwe_ids or []).union(set(raw.cwe_ids))))
                merged_owasps = sorted(list(set(existing.owasp_refs or []).union(set(raw.owasp_refs))))
                existing.cwe_ids = merged_cwes
                existing.owasp_refs = merged_owasps

                signals = list(existing.signals or [])
                if scanner_signal not in signals:
                    signals.append(scanner_signal)
                existing.signals = signals
                existing.confidence = "CONFIRMED"
                existing.verified_state = "CONFIRMED"
                existing.priority = compute_unified_priority(
                    severity=existing.severity,
                    confidence="CONFIRMED"
                )
            else:
                finding_id = str(uuid.uuid4())
                sev_val = raw.severity.value if hasattr(raw.severity, "value") else str(raw.severity)
                conf_val = raw.confidence.value if hasattr(raw.confidence, "value") else str(raw.confidence)
                prio = compute_unified_priority(severity=sev_val, confidence=conf_val)
                stds = enrich_standards_mapping(raw.cwe_ids, raw.owasp_refs)

                # Determine engine and tool provenance (Section 5 & 6)
                engine_val = "sast"
                if raw.category == "secrets":
                    engine_val = "secrets"
                elif raw.category == "dependency":
                    engine_val = "sca"
                elif raw.rule_id.startswith("iac-docker"):
                    engine_val = "container"
                elif raw.rule_id.startswith("ci-"):
                    engine_val = "ci"
                elif raw.rule_id.startswith("iac-") or raw.rule_id.startswith("cloud-"):
                    engine_val = "iac"
                elif raw.rule_id.startswith("db-"):
                    engine_val = "db"
                elif raw.category in ("injection", "auth", "api", "misconfig"):
                    engine_val = "sast"

                tool_val = scanner_name
                if raw.rule_id.startswith("db-"):
                    tool_val = "db_static" if "static" in raw.rule_id else "db_runtime"
                elif raw.rule_id.startswith("iac-docker"):
                    tool_val = "hadolint"
                elif raw.rule_id.startswith("ci-"):
                    tool_val = "zizmor"
                elif raw.rule_id.startswith("iac-tf") or raw.rule_id.startswith("iac-k8s") or raw.rule_id.startswith("iac-compose"):
                    tool_val = "checkov"
                elif raw.rule_id.startswith("cloud-"):
                    tool_val = "cloud_config"
                elif scanner_name == "gitleaks" and "trufflehog" in raw.rule_id:
                    tool_val = "trufflehog"

                finding_model = FindingModel(
                    id=finding_id,
                    audit_id=audit_id,
                    fingerprint=fingerprint,
                    scanner_name=scanner_name,
                    scanner_version=res.version,
                    rule_id=raw.rule_id,
                    category=raw.category,
                    severity=sev_val,
                    confidence=conf_val,
                    title=raw.title,
                    description=raw.description,
                    file_path=clean_path,
                    start_line=raw.start_line,
                    end_line=raw.end_line,
                    cwe_ids=raw.cwe_ids,
                    owasp_refs=raw.owasp_refs,
                    redacted_snippet=clean_snippet,
                    technical_fix=raw.technical_fix,
                    validation_steps=raw.validation_steps,
                    engine=engine_val,
                    tool=tool_val,
                    tool_version=res.version,
                    verified_state="CONFIRMED" if conf_val == "CONFIRMED" else "LIKELY",
                    priority=prio,
                    standards=stds,
                    plain_title=raw.title,
                    plain_summary=raw.description,
                    why_it_matters=f"Vulnerability in {clean_path} affecting application security posture.",
                    how_to_fix=raw.technical_fix or "Remediate source code according to safe patterns.",
                    how_to_verify_fix=raw.validation_steps or "Re-scan repository worktree.",
                    fix_effort="30 minutes",
                    signals=[scanner_signal],
                    status="open"
                )
                db.add(finding_model)

                # Persist corresponding Evidence record
                is_config_file = any(clean_path.endswith(ext) for ext in [".yaml", ".yml", ".json", ".tf", ".env", ".rules", ".toml"]) or "dockerfile" in clean_path.lower()
                tier_val = EvidenceTier.E2_CONFIG_MANIFEST.value if (raw.category == "dependency" or is_config_file) else EvidenceTier.E1_SOURCE_CODE.value

                evidence_model = EvidenceModel(
                    id=str(uuid.uuid4()),
                    audit_id=audit_id,
                    finding_id=finding_id,
                    tier=tier_val,
                    path=clean_path,
                    start_line=raw.start_line,
                    end_line=raw.end_line,
                    redacted_excerpt=clean_snippet,
                    raw_data=raw.raw_metadata or {},
                    provenance=f"{tool_val}:{res.version}:{raw.rule_id}"
                )
                db.add(evidence_model)

                dedupe_map[dedupe_key] = finding_model
                total_findings += 1

    db.commit()

    # 3. Update Audit status
    if has_failures:
        audit.status = "PARTIAL"
        audit.current_stage = "NORMALIZING"
    else:
        audit.status = "NORMALIZING"
        audit.current_stage = "NORMALIZING"

    db.commit()
    return total_findings, has_failures
