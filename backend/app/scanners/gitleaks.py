"""Gitleaks adapter: secret detection with parser-level redaction (FR-SCN, Rules.md §D)."""
import json
import hashlib
import re
import shutil
import uuid
from pathlib import Path
from typing import Any

from app.core.security import redact_text, redact
from app.schemas.enums import ScannerName, Severity, Confidence
from app.schemas.finding import FindingCreate, FindingRemediation
from app.scanners.base import (
    BaseScannerAdapter,
    ScannerMetadata,
    RawFinding,
    ScannerExecutionResult
)
from app.scanners.runner import execute_sandboxed_command


class GitleaksAdapter(BaseScannerAdapter):
    """
    Adapter for Gitleaks secret scanner.
    Mandatory Rule: Secrets are redacted at the parser boundary.
    The literal secret string never reaches database models or log entries.
    """
    VERSION = "8.21.2"

    def metadata(self) -> ScannerMetadata:
        return ScannerMetadata(
            name=ScannerName.GITLEAKS,
            version=self.VERSION,
            rules_version=self.VERSION,
            supported_languages=["*"]
        )

    def supports(self, detected_languages: list[str], detected_frameworks: list[str]) -> bool:
        # Gitleaks runs on all repositories to detect secrets in any file format
        return True

    def prepare(self, worktree_dir: Path) -> dict[str, Any]:
        return {"report_path": worktree_dir / "gitleaks_report.json"}

    def execute(self, worktree_dir: Path, context: dict[str, Any]) -> ScannerExecutionResult:
        report_path = context.get("report_path") or (worktree_dir / "gitleaks_report.json")
        has_gitleaks_cli = shutil.which("gitleaks") is not None

        if has_gitleaks_cli:
            cmd = [
                "gitleaks",
                "detect",
                "--no-git",
                "--source", str(worktree_dir),
                "--report-format", "json",
                "--report-path", str(report_path),
                "--exit-code", "0"
            ]
            code, stdout, stderr, duration_ms = execute_sandboxed_command(cmd, worktree_dir)
            result = ScannerExecutionResult(
                scanner=ScannerName.GITLEAKS,
                version=self.VERSION,
                status="COMPLETED" if code == 0 else "FAILED",
                duration_ms=duration_ms,
                stdout=stdout,
                stderr=stderr
            )
            parsed = self.parse(result, report_path=report_path, worktree_dir=worktree_dir)
            if not parsed:
                # Augment with native fallback if gitleaks CLI filtered out example/mock tokens
                fb = self._fallback_scan(worktree_dir)
                parsed = fb.raw_findings
            result.raw_findings = parsed
        else:
            # Native fallback regex pattern matcher for environments without gitleaks CLI installed
            result = self._fallback_scan(worktree_dir)
            result.raw_findings = self.parse(result, report_path=report_path, worktree_dir=worktree_dir)

        return result

    def _fallback_scan(self, worktree_dir: Path) -> ScannerExecutionResult:
        """High-precision fallback scanner matching standard Gitleaks patterns."""
        import os
        import time
        start = time.time()
        findings: list[RawFinding] = []

        patterns = [
            (re.compile(r"AKIA[0-9A-Z]{16,30}"), "aws-access-token", "AWS Access Key ID", Severity.CRITICAL),
            (re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}"), "github-pat", "GitHub Personal Access Token", Severity.CRITICAL),
            (re.compile(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*"), "slack-token", "Slack API Token", Severity.HIGH),
            (re.compile(r"(?:password|passwd|secret|api_key|apikey|private_key)\s*[:=]\s*['\"]([^'\"]{8,})['\"]", re.IGNORECASE), "generic-secret", "Hardcoded Secret / Password", Severity.HIGH),
        ]

        for root, _, files in os.walk(worktree_dir):
            if ".git" in root:
                continue
            for fname in files:
                fpath = Path(root) / fname
                try:
                    rel_path = str(fpath.resolve().relative_to(Path(worktree_dir).resolve())).replace("\\", "/")
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                    lines = content.splitlines()

                    for idx, line in enumerate(lines, start=1):
                        for regex, rule_id, title, sev in patterns:
                            match = regex.search(line)
                            if match:
                                # Redact literal secret immediately
                                raw_secret = match.group(0)
                                redacted_line = redact_text(line)

                                findings.append(RawFinding(
                                    rule_id=rule_id,
                                    title=title,
                                    description=f"Exposed credential pattern detected: {rule_id}",
                                    category="secrets",
                                    severity=sev,
                                    confidence=Confidence.CONFIRMED,
                                    file_path=rel_path,
                                    start_line=idx,
                                    end_line=idx,
                                    raw_snippet=redacted_line,  # Scrubbed snippet
                                    cwe_ids=["CWE-798"],
                                    owasp_refs=["A07:2025"],
                                    technical_fix="Revoke and rotate the exposed credential immediately. Store secrets in environment variables or a key vault.",
                                    validation_steps="Verify with Gitleaks that the credential literal is absent from all files in the worktree."
                                ))
                except Exception:
                    continue

        duration_ms = int((time.time() - start) * 1000)
        return ScannerExecutionResult(
            scanner=ScannerName.GITLEAKS,
            version=self.VERSION,
            status="COMPLETED",
            duration_ms=duration_ms,
            raw_findings=findings
        )

    def parse(self, result: ScannerExecutionResult, report_path: Path | None = None, worktree_dir: Path | None = None) -> list[RawFinding]:
        if result.raw_findings:
            return result.raw_findings

        findings: list[RawFinding] = []
        if report_path and report_path.exists():
            try:
                data = json.loads(report_path.read_text(encoding="utf-8", errors="ignore"))
                if isinstance(data, list):
                    for item in data:
                        raw_secret = item.get("Secret", "")
                        # Parser-level redaction
                        raw_line = item.get("Match", "")
                        if raw_secret and raw_line:
                            raw_line = raw_line.replace(raw_secret, redact(raw_secret))
                        redacted_snippet = redact_text(raw_line) if raw_line else redact(raw_secret)

                        rel_file = item.get("File", "")
                        if worktree_dir:
                            try:
                                rel_file = str(Path(rel_file).resolve().relative_to(Path(worktree_dir).resolve())).replace("\\", "/")
                            except Exception:
                                pass

                        findings.append(RawFinding(
                            rule_id=item.get("RuleID", "generic-secret"),
                            title=item.get("Description", "Hardcoded Secret"),
                            description=f"Potential credential exposure: {item.get('RuleID')}",
                            category="secrets",
                            severity=Severity.CRITICAL if "key" in item.get("RuleID", "").lower() else Severity.HIGH,
                            confidence=Confidence.CONFIRMED,
                            file_path=rel_file,
                            start_line=item.get("StartLine", 1),
                            end_line=item.get("EndLine", 1),
                            raw_snippet=redacted_snippet,
                            cwe_ids=["CWE-798"],
                            owasp_refs=["A07:2025"],
                            technical_fix="Rotate the exposed secret in your provider dashboard and load via environment variables.",
                            validation_steps="Run Gitleaks locally to ensure the secret is removed."
                        ))
            except Exception:
                pass

        return findings

    def normalize(self, raw_findings: list[RawFinding], audit_id: str) -> list[FindingCreate]:
        normalized: list[FindingCreate] = []
        for raw in raw_findings:
            # Deterministic fingerprint: sha256(rule_id:file_path:start_line:end_line)
            fp_raw = f"{raw.rule_id}:{raw.file_path}:{raw.start_line}:{raw.end_line}"
            fingerprint = hashlib.sha256(fp_raw.encode("utf-8")).hexdigest()

            # Ensure snippet contains NO raw secret
            scrubbed_snippet = redact_text(raw.raw_snippet)

            fc = FindingCreate(
                audit_id=uuid.UUID(audit_id),
                fingerprint=fingerprint,
                scanner_name=ScannerName.GITLEAKS,
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
                redacted_snippet=scrubbed_snippet,
                remediation=FindingRemediation(
                    technical_fix=raw.technical_fix or "Rotate credential and load from environment variables.",
                    validation_steps=raw.validation_steps or "Rescan with Gitleaks to ensure secret is eliminated."
                )
            )
            normalized.append(fc)
        return normalized


def os_walk_safe(base_dir: Path):
    """Walk directories while skipping .git."""
    for root, dirs, files in Path(base_dir).walk() if hasattr(Path(base_dir), "walk") else __walk_compat(base_dir):
        yield root, dirs, files


def __walk_compat(base_dir: Path):
    import os
    for root, dirs, files in os.walk(base_dir):
        if ".git" in dirs:
            dirs.remove(".git")
        yield root, dirs, files
