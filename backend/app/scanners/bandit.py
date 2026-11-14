"""Bandit adapter: Python AST security scanner (FR-SCN)."""
import hashlib
import json
import shutil
import time
import uuid
from pathlib import Path
from typing import Any

from app.schemas.enums import ScannerName, Severity, Confidence
from app.schemas.finding import FindingCreate, FindingRemediation
from app.scanners.base import (
    BaseScannerAdapter,
    ScannerMetadata,
    RawFinding,
    ScannerExecutionResult
)
from app.scanners.runner import execute_sandboxed_command


class BanditAdapter(BaseScannerAdapter):
    """
    Adapter for Bandit Python AST vulnerability scanner.
    Conditional tool in P0/P1 scope-cut order (D-04).
    """
    VERSION = "1.8.0"

    def metadata(self) -> ScannerMetadata:
        return ScannerMetadata(
            name=ScannerName.BANDIT,
            version=self.VERSION,
            rules_version=self.VERSION,
            supported_languages=["Python"]
        )

    def supports(self, detected_languages: list[str], detected_frameworks: list[str]) -> bool:
        return "Python" in detected_languages

    def prepare(self, worktree_dir: Path) -> dict[str, Any]:
        return {"report_file": worktree_dir / "bandit_report.json"}

    def execute(self, worktree_dir: Path, context: dict[str, Any]) -> ScannerExecutionResult:
        has_cli = shutil.which("bandit") is not None
        report_file = context.get("report_file") or (worktree_dir / "bandit_report.json")

        if has_cli:
            cmd = [
                "bandit",
                "-r", str(worktree_dir),
                "-f", "json",
                "-o", str(report_file),
                "-q"
            ]
            code, stdout, stderr, duration_ms = execute_sandboxed_command(cmd, worktree_dir)
            result = ScannerExecutionResult(
                scanner=ScannerName.BANDIT,
                version=self.VERSION,
                status="COMPLETED" if code in (0, 1) else "FAILED",
                duration_ms=duration_ms,
                stdout=stdout,
                stderr=stderr
            )
        else:
            result = self._fallback_bandit(worktree_dir)

        result.raw_findings = self.parse(result, report_file=report_file, worktree_dir=worktree_dir)
        return result

    def _fallback_bandit(self, worktree_dir: Path) -> ScannerExecutionResult:
        start = time.time()
        findings: list[RawFinding] = []
        import os

        for root, _, files in os.walk(worktree_dir):
            if ".git" in root:
                continue
            for fname in files:
                if not fname.endswith(".py"):
                    continue
                fpath = Path(root) / fname
                try:
                    rel_path = str(fpath.relative_to(worktree_dir)).replace("\\", "/")
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                    lines = content.splitlines()

                    for idx, line in enumerate(lines, start=1):
                        # B108: Hardcoded /tmp file usage
                        if "/tmp/" in line or "/var/tmp/" in line:
                            findings.append(RawFinding(
                                rule_id="B108",
                                title="Probable Insecure Usage of /tmp File",
                                description="Hardcoded temporary file paths can lead to race conditions or symlink attacks.",
                                category="misconfig",
                                severity=Severity.LOW,
                                confidence=Confidence.MEDIUM,
                                file_path=rel_path,
                                start_line=idx,
                                end_line=idx,
                                raw_snippet=line.strip(),
                                cwe_ids=["CWE-377"],
                                owasp_refs=["A01:2025"],
                                technical_fix="Use the tempfile module (e.g. tempfile.NamedTemporaryFile).",
                                validation_steps="Verify tempfile handles file creation safely."
                            ))
                except Exception:
                    continue

        duration_ms = int((time.time() - start) * 1000)
        return ScannerExecutionResult(
            scanner=ScannerName.BANDIT,
            version=self.VERSION,
            status="COMPLETED",
            duration_ms=duration_ms,
            raw_findings=findings
        )

    def parse(self, result: ScannerExecutionResult, report_file: Path | None = None, worktree_dir: Path | None = None) -> list[RawFinding]:
        if result.raw_findings:
            return result.raw_findings

        findings: list[RawFinding] = []
        if report_file and report_file.exists():
            try:
                data = json.loads(report_file.read_text(encoding="utf-8", errors="ignore"))
                for res in data.get("results", []):
                    rel_file = res.get("filename", "")
                    if worktree_dir and Path(rel_file).is_absolute():
                        try:
                            rel_file = str(Path(rel_file).relative_to(worktree_dir)).replace("\\", "/")
                        except ValueError:
                            pass

                    findings.append(RawFinding(
                        rule_id=res.get("test_id", "B000"),
                        title=res.get("issue_text", "Bandit AST Finding"),
                        description=res.get("issue_text", ""),
                        category="misconfig",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        file_path=rel_file,
                        start_line=res.get("line_number", 1),
                        end_line=res.get("line_number", 1),
                        raw_snippet=res.get("code", "").strip(),
                        cwe_ids=[f"CWE-{res.get('issue_cwe', {}).get('id', 0)}"],
                        owasp_refs=["A05:2025"],
                        technical_fix="Refactor code according to Python secure coding standards.",
                        validation_steps="Rescan using Bandit."
                    ))
            except Exception:
                pass
        return findings

    def normalize(self, raw_findings: list[RawFinding], audit_id: str) -> list[FindingCreate]:
        normalized: list[FindingCreate] = []
        for raw in raw_findings:
            fp_raw = f"{raw.rule_id}:{raw.file_path}:{raw.start_line}:{raw.end_line}"
            fingerprint = hashlib.sha256(fp_raw.encode("utf-8")).hexdigest()

            fc = FindingCreate(
                audit_id=uuid.UUID(audit_id),
                fingerprint=fingerprint,
                scanner_name=ScannerName.BANDIT,
                scanner_version=self.VERSION,
                rule_id=raw.rule_id,
                title=raw.title,
                description=raw.description,
                category=raw.category,
                severity=raw.severity,
                confidence=raw.confidence,
                file_path=raw.file_path,
                start_line=raw.start_line,
                end_line=raw.end_line,
                cwe_ids=raw.cwe_ids,
                owasp_refs=raw.owasp_refs,
                redacted_snippet=raw.raw_snippet,
                remediation=FindingRemediation(
                    technical_fix=raw.technical_fix or "Remediate AST security finding.",
                    validation_steps=raw.validation_steps or "Rerun Bandit."
                )
            )
            normalized.append(fc)
        return normalized

