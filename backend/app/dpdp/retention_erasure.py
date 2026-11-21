"""Data Retention, Storage Limitation and Erasure Audit Engine (Step 10, DPDP Act 2023 §8(7)-(8), §12)."""
from dataclasses import dataclass, field
import logging
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


@dataclass
class DetectedPersonalModel:
    model_name: str
    file_path: str
    has_soft_delete: bool = False
    has_retention_ttl: bool = False
    has_hard_delete: bool = False
    pii_columns: List[str] = field(default_factory=list)


@dataclass
class RetentionErasureAuditReport:
    personal_data_models: List[DetectedPersonalModel] = field(default_factory=list)
    erasure_api_found: bool = False
    erasure_endpoints: List[str] = field(default_factory=list)
    export_portability_api_found: bool = False
    export_endpoints: List[str] = field(default_factory=list)
    automated_cleanup_job_found: bool = False
    cleanup_jobs: List[str] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "personal_data_models": [
                {
                    "model_name": m.model_name,
                    "file_path": m.file_path,
                    "has_soft_delete": m.has_soft_delete,
                    "has_retention_ttl": m.has_retention_ttl,
                    "has_hard_delete": m.has_hard_delete,
                    "pii_columns": m.pii_columns,
                }
                for m in self.personal_data_models
            ],
            "erasure_api_found": self.erasure_api_found,
            "erasure_endpoints": self.erasure_endpoints,
            "export_portability_api_found": self.export_portability_api_found,
            "export_endpoints": self.export_endpoints,
            "automated_cleanup_job_found": self.automated_cleanup_job_found,
            "cleanup_jobs": self.cleanup_jobs,
            "findings": self.findings,
        }


class RetentionErasureAuditor:
    """Audits database models and API routes for DPDP Section 8(7) storage limitation and Section 12 erasure."""

    PERSONAL_MODEL_NAMES = re.compile(r"""class\s+([A-Za-z0-9_]*(?:User|Account|Customer|Profile|Patient|Employee|Student|Member|Lead)[A-Za-z0-9_]*)\b""")
    SOFT_DELETE_PATTERNS = re.compile(r"""\b(?:deleted_at|is_deleted|is_active|marked_for_deletion)\b""", re.IGNORECASE)
    RETENTION_JOB_PATTERNS = re.compile(r"""\b(?:retention_days|purge_deleted|cleanup_expired|expire_sessions|data_retention|retention_policy|cleanup_inactive)\b""", re.IGNORECASE)
    ERASURE_ROUTE_PATTERNS = re.compile(r"""(?:@(?:app|router|bp)\.(?:delete|post)\s*\([^)]*?(?:delete[-_]account|erase|purge[-_]data|user[-_]deletion|me\/delete|users\/me)[^)]*?\)|DELETE\s+['"][^'"]*?(?:user|account|profile|data)[\/'"])""", re.IGNORECASE)
    EXPORT_ROUTE_PATTERNS = re.compile(r"""(?:@(?:app|router|bp)\.get\s*\([^)]*?(?:export[-_]data|download[-_]data|data[-_]portability|me\/export)[^)]*?\)|GET\s+['"][^'"]*?(?:export|download)[-_]data[\/'"])""", re.IGNORECASE)

    PII_COLUMN_PATTERNS = re.compile(r"""\b(email|phone|mobile|aadhaar|pan|name|first_name|last_name|address|dob|birthdate|ssn|gender)\b""", re.IGNORECASE)

    @classmethod
    def audit_worktree(cls, worktree_dir: Path) -> RetentionErasureAuditReport:
        report = RetentionErasureAuditReport()

        for root, _, files in os.walk(worktree_dir):
            if ".git" in root or "node_modules" in root or "venv" in root:
                continue

            for fname in files:
                fpath = Path(root) / fname
                rel_path = str(fpath.resolve().relative_to(Path(worktree_dir).resolve())).replace("\\", "/")
                ext = fpath.suffix.lower()

                if ext not in (".py", ".ts", ".js", ".sql", ".prisma"):
                    continue

                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue

                # 1. Check for personal data models
                for m in cls.PERSONAL_MODEL_NAMES.finditer(content):
                    model_name = m.group(1)
                    has_soft = bool(cls.SOFT_DELETE_PATTERNS.search(content))
                    has_ttl = bool(cls.RETENTION_JOB_PATTERNS.search(content))
                    pii_cols = list(set(cls.PII_COLUMN_PATTERNS.findall(content)))

                    model_entry = DetectedPersonalModel(
                        model_name=model_name,
                        file_path=rel_path,
                        has_soft_delete=has_soft,
                        has_retention_ttl=has_ttl,
                        has_hard_delete=not has_soft,
                        pii_columns=pii_cols,
                    )
                    report.personal_data_models.append(model_entry)

                # 2. Check for cleanup / retention background jobs
                if cls.RETENTION_JOB_PATTERNS.search(content):
                    report.automated_cleanup_job_found = True
                    report.cleanup_jobs.append(rel_path)

                # 3. Check for erasure API
                if cls.ERASURE_ROUTE_PATTERNS.search(content):
                    report.erasure_api_found = True
                    report.erasure_endpoints.append(rel_path)

                # 4. Check for export API
                if cls.EXPORT_ROUTE_PATTERNS.search(content):
                    report.export_portability_api_found = True
                    report.export_endpoints.append(rel_path)

        # Generate DPDP findings
        # If personal data models exist but no erasure API exists
        if report.personal_data_models and not report.erasure_api_found:
            report.findings.append({
                "rule_id": "dpdp-erasure-api-missing",
                "file_path": report.personal_data_models[0].file_path,
                "title": "Missing automated Data Principal erasure API under Section 12",
                "severity": "HIGH",
                "dpdp_section": "Section 12(3) / DPDP-008",
                "remediation": "DPDP Act 2023 Section 12(3) entitles Data Principals to erasure of personal data. Expose an authenticated user erasure API (e.g. DELETE /api/v1/users/me).",
            })

        # If personal data models use soft deletion without automated cleanup jobs
        soft_models = [m for m in report.personal_data_models if m.has_soft_delete]
        if soft_models and not report.automated_cleanup_job_found:
            report.findings.append({
                "rule_id": "dpdp-soft-delete-without-purge",
                "file_path": soft_models[0].file_path,
                "title": "Soft-deleted personal data lacks automated purge routine under Section 8(7)",
                "severity": "MEDIUM",
                "dpdp_section": "Section 8(7) / DPDP-008",
                "remediation": "DPDP Act 2023 Section 8(7) requires erasing personal data when purpose is no longer served. Implement a periodic cron job to physically purge or anonymize soft-deleted records.",
            })

        return report
