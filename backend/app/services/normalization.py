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

            dedupe_key = (clean_path, raw.start_line, raw.end_line, raw.category)

            if dedupe_key in dedupe_map:
                # Merge secondary scanner metadata into existing finding
                existing = dedupe_map[dedupe_key]
                merged_cwes = sorted(list(set(existing.cwe_ids or []).union(set(raw.cwe_ids))))
                merged_owasps = sorted(list(set(existing.owasp_refs or []).union(set(raw.owasp_refs))))
                existing.cwe_ids = merged_cwes
                existing.owasp_refs = merged_owasps
            else:
                finding_id = str(uuid.uuid4())
                scanner_name = res.scanner.value if hasattr(res.scanner, "value") else str(res.scanner)
                sev_val = raw.severity.value if hasattr(raw.severity, "value") else str(raw.severity)
                conf_val = raw.confidence.value if hasattr(raw.confidence, "value") else str(raw.confidence)
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
                    validation_steps=raw.validation_steps
                )
                db.add(finding_model)

                # Persist corresponding Evidence record
                evidence_model = EvidenceModel(
                    id=str(uuid.uuid4()),
                    audit_id=audit_id,
                    finding_id=finding_id,
                    tier=EvidenceTier.E1_SOURCE_CODE.value if raw.category != "dependency" else EvidenceTier.E2_CONFIG_MANIFEST.value,
                    path=clean_path,
                    start_line=raw.start_line,
                    end_line=raw.end_line,
                    redacted_excerpt=clean_snippet,
                    raw_data=raw.raw_metadata or {},
                    provenance=f"{res.scanner.value}:{res.version}:{raw.rule_id}"
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
