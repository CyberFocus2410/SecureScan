"""TruffleHog adapter: multi-engine secret detection, git-history scanning, and rotation guidance (Step 4, ADR-002)."""
import hashlib
import json
import re
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any, List, Dict, Tuple, Optional

from app.core.security import redact_text, redact, assert_no_raw_secret
from app.schemas.enums import ScannerName, Severity, Confidence
from app.schemas.finding import FindingCreate, FindingRemediation
from app.scanners.base import (
    BaseScannerAdapter,
    ScannerMetadata,
    RawFinding,
    ScannerExecutionResult
)
from app.scanners.runner import execute_sandboxed_command


ROTATION_GUIDANCE = {
    "AWS": (
        "1. Open AWS IAM Console -> Users -> Security credentials.\n"
        "2. Create a new Access Key and deploy to secrets manager.\n"
        "3. Deactivate the old Access Key and verify applications remain operational.\n"
        "4. Delete the deactivated key permanently."
    ),
    "GitHub": (
        "1. Open GitHub Settings -> Developer settings -> Personal access tokens.\n"
        "2. Revoke or regenerate the compromised token immediately.\n"
        "3. Review audit log for unauthorized repository access or workflow runs."
    ),
    "Stripe": (
        "1. Open Stripe Dashboard -> Developers -> API Keys.\n"
        "2. Click 'Roll key' on the compromised key to generate a replacement with a 24-hour expiration window for the old key.\n"
        "3. Update backend environment variables and verify webhooks."
    ),
    "Slack": (
        "1. Open Slack App Management -> OAuth & Permissions.\n"
        "2. Revoke the exposed bot/user token.\n"
        "3. Reinstall app to workspace to mint a fresh token."
    ),
    "PrivateKey": (
        "1. Generate a new cryptographic keypair using ssh-keygen or openssl.\n"
        "2. Add the new public key to target servers / authorized_keys.\n"
        "3. Remove the compromised public key from all servers and certificate registries."
    ),
    "DatabaseURI": (
        "1. Change user password directly in the database server: ALTER USER username WITH PASSWORD '...';\n"
        "2. Update the application connection string in your vault or secrets manager.\n"
        "3. Restart application instances to purge cached connection pools."
    ),
    "Generic": (
        "1. Identify the service provider associated with the secret.\n"
        "2. Invalidate the existing token/credential via provider management console.\n"
        "3. Provision a new credential and inject via environment variables (never commit to version control)."
    )
}

PLACEHOLDER_PATTERNS = [
    re.compile(r"your[-_]key", re.IGNORECASE),
    re.compile(r"example[-_]key", re.IGNORECASE),
    re.compile(r"test[-_]token", re.IGNORECASE),
    re.compile(r"changeme", re.IGNORECASE),
    re.compile(r"dummy[-_]value", re.IGNORECASE),
    re.compile(r"placeholder", re.IGNORECASE),
    re.compile(r"fake[-_]key", re.IGNORECASE),
    re.compile(r"<[^>]+>"),
    re.compile(r"^\*{4,}$"),
]

FRONTEND_PATH_INDICATORS = [
    "frontend/", "src/", "public/", "dist/", "client/", "web/",
    ".env.local", ".env.client", "NEXT_PUBLIC_", "VITE_", "REACT_APP_"
]


class TruffleHogAdapter(BaseScannerAdapter):
    """
    Adapter for TruffleHog secret detector with native git history analysis.
    Categorizes:
    - secret_type
    - current_vs_history (CURRENT_FILE vs GIT_HISTORY)
    - frontend_bundle_exposure
    - real vs placeholder
    - provider rotation guidance
    """
    VERSION = "3.88.0"

    def metadata(self) -> ScannerMetadata:
        return ScannerMetadata(
            name=ScannerName.TRUFFLEHOG if hasattr(ScannerName, "TRUFFLEHOG") else ScannerName.GITLEAKS,
            version=self.VERSION,
            rules_version=self.VERSION,
            supported_languages=["*"]
        )

    def supports(self, detected_languages: list[str], detected_frameworks: list[str]) -> bool:
        return True

    def prepare(self, worktree_dir: Path) -> dict[str, Any]:
        return {"report_path": worktree_dir / "trufflehog_report.json"}

    def execute(self, worktree_dir: Path, context: dict[str, Any]) -> ScannerExecutionResult:
        start_time = time.time()
        findings: list[RawFinding] = []
        has_cli = shutil.which("trufflehog") is not None

        if has_cli:
            report_path = context.get("report_path") or (worktree_dir / "trufflehog_report.json")
            cmd = [
                "trufflehog",
                "filesystem",
                str(worktree_dir),
                "--json",
                "--no-update"
            ]
            code, stdout, stderr, dur = execute_sandboxed_command(cmd, worktree_dir)
            findings.extend(self._parse_trufflehog_cli_json(stdout, worktree_dir))

        # Always complement with git history inspection and regex fallback
        history_findings = self._scan_git_history(worktree_dir)
        findings.extend(history_findings)

        # In working tree files (fallback scanner)
        if not has_cli:
            tree_findings = self._scan_working_tree_regex(worktree_dir)
            findings.extend(tree_findings)

        duration_ms = int((time.time() - start_time) * 1000)
        return ScannerExecutionResult(
            scanner=ScannerName.GITLEAKS,  # Normalizes under primary SECRETS scanner
            version=self.VERSION,
            status="COMPLETED",
            duration_ms=duration_ms,
            raw_findings=findings
        )

    def parse(self, result: ScannerExecutionResult, **kwargs) -> list[RawFinding]:
        return result.raw_findings

    def normalize(self, raw_findings: list[RawFinding], audit_id: str) -> list[Any]:
        return []

    def _is_placeholder(self, snippet: str) -> bool:
        for p in PLACEHOLDER_PATTERNS:
            if p.search(snippet):
                return True
        return False

    def _is_frontend_exposure(self, file_path: str) -> bool:
        norm_path = file_path.replace("\\", "/").lower()
        return any(ind.lower() in norm_path for ind in FRONTEND_PATH_INDICATORS)

    def _get_rotation_guidance(self, secret_type: str) -> str:
        return ROTATION_GUIDANCE.get(secret_type, ROTATION_GUIDANCE["Generic"])

    def _scan_git_history(self, worktree_dir: Path) -> list[RawFinding]:
        """Inspect git commits for committed-and-deleted secrets without executing git hooks."""
        findings = []
        git_dir = worktree_dir / ".git"
        if not git_dir.exists():
            return findings

        try:
            # Query commit patch history safely
            proc = subprocess.run(
                ["git", "log", "-p", "-n", "30", "--no-merges", "--no-color", "--diff-filter=D"],
                cwd=str(worktree_dir),
                capture_output=True,
                text=True,
                timeout=10,
                check=False
            )
            patch_text = proc.stdout
            if not patch_text:
                # Also check all diffs if no file deletions
                proc_all = subprocess.run(
                    ["git", "log", "-p", "-n", "20", "--no-merges", "--no-color"],
                    cwd=str(worktree_dir),
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False
                )
                patch_text = proc_all.stdout

            current_file = "git/history"
            current_commit = "unknown"
            line_no = 1

            for line in patch_text.splitlines():
                line_no += 1
                if line.startswith("commit "):
                    current_commit = line.split()[1][:8]
                elif line.startswith("--- a/") or line.startswith("+++ b/"):
                    current_file = line[6:].strip()
                elif line.startswith("-") and not line.startswith("---"):
                    # Deleted line in diff: potential deleted secret in history!
                    deleted_content = line[1:].strip()
                    secret_match = self._match_secret_patterns(deleted_content)
                    if secret_match:
                        stype, raw_val = secret_match
                        if not self._is_placeholder(raw_val):
                            redacted_snippet = redact_text(deleted_content)
                            assert_no_raw_secret(redacted_snippet, raw_val)

                            rule_id = f"trufflehog.git_history.{stype.lower()}"
                            f = RawFinding(
                                rule_id=rule_id,
                                title=f"Exposed {stype} in Git History (Commit {current_commit})",
                                description=(
                                    f"A sensitive {stype} credential was found in commit {current_commit} diff. "
                                    "Even if deleted in later commits, credentials in git history remain compromised."
                                ),
                                category="secrets",
                                severity=Severity.CRITICAL,
                                confidence=Confidence.CONFIRMED,
                                file_path=current_file,
                                start_line=line_no,
                                end_line=line_no,
                                cwe_ids=["CWE-798", "CWE-540"],
                                owasp_refs=["A07:2021-Identification and Authentication Failures"],
                                raw_snippet=redacted_snippet,
                                technical_fix=self._get_rotation_guidance(stype),
                                validation_steps="Verify with 'git log -S <fingerprint>' that key history is expunged."
                            )
                            findings.append(f)
        except Exception:
            pass

        return findings

    def _scan_working_tree_regex(self, worktree_dir: Path) -> list[RawFinding]:
        """Fallback regex search across working tree with frontend-exposure check."""
        findings = []
        for path in worktree_dir.rglob("*"):
            if not path.is_file() or ".git" in path.parts:
                continue
            if path.stat().st_size > 500_000:
                continue

            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
                rel_path = str(path.relative_to(worktree_dir)).replace("\\", "/")
                is_frontend = self._is_frontend_exposure(rel_path)

                for line_idx, line in enumerate(content.splitlines(), start=1):
                    match = self._match_secret_patterns(line)
                    if match:
                        stype, raw_val = match
                        if not self._is_placeholder(raw_val):
                            redacted_snippet = redact_text(line)
                            assert_no_raw_secret(redacted_snippet, raw_val)

                            exposure_title = f"Exposed {stype} in Frontend Bundle" if is_frontend else f"Hardcoded {stype} in Source Code"
                            rule_id = f"trufflehog.frontend.{stype.lower()}" if is_frontend else f"trufflehog.source.{stype.lower()}"
                            f = RawFinding(
                                rule_id=rule_id,
                                title=exposure_title,
                                description=(
                                    f"Discovered an active {stype} credential in '{rel_path}'. "
                                    + ("This file appears in a frontend/client bundle, exposing keys directly to end users." if is_frontend else "Hardcoded credentials in source code can be extracted by unauthorized parties.")
                                ),
                                category="secrets",
                                severity=Severity.CRITICAL if not is_frontend else Severity.HIGH,
                                confidence=Confidence.CONFIRMED,
                                file_path=rel_path,
                                start_line=line_idx,
                                end_line=line_idx,
                                cwe_ids=["CWE-798"],
                                owasp_refs=["A07:2021-Identification and Authentication Failures"],
                                raw_snippet=redacted_snippet,
                                technical_fix=self._get_rotation_guidance(stype),
                                validation_steps="Confirm secret has been rotated and moved to environment variables."
                            )
                            findings.append(f)
            except Exception:
                pass

        return findings

    def _match_secret_patterns(self, text: str) -> Optional[Tuple[str, str]]:
        patterns = [
            ("AWS", r"(?:AKIA[0-9A-Z]{16})"),
            ("GitHub", r"(?:ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})"),
            ("Stripe", r"(?:sk_live_[0-9a-zA-Z]{24})"),
            ("Slack", r"(?:xox[baprs]-[0-9a-zA-Z]{10,48})"),
            ("PrivateKey", r"(?:-----BEGIN (?:RSA|OPENSSH|EC|DSA) PRIVATE KEY-----)"),
            ("DatabaseURI", r"(?:postgres(?:ql)?:\/\/[a-zA-Z0-9_-]+:[^@\s]+@[a-zA-Z0-9._-]+:\d+\/[a-zA-Z0-9._-]+)"),
        ]
        for name, pat in patterns:
            m = re.search(pat, text)
            if m:
                return name, m.group(0)
        return None

    def _parse_trufflehog_cli_json(self, output: str, worktree_dir: Path) -> list[RawFinding]:
        findings = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                detector_name = item.get("DetectorName", "Secret")
                raw_secret = item.get("Raw", "")
                source_meta = item.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
                file_path = source_meta.get("file", "unknown")
                line_no = source_meta.get("line", 1)

                redacted_snippet = redact_text(raw_secret)
                if raw_secret:
                    assert_no_raw_secret(redacted_snippet, raw_secret)

                findings.append(
                    RawFinding(
                        rule_id=f"trufflehog.{detector_name.lower()}",
                        title=f"Hardcoded {detector_name}",
                        description=f"TruffleHog identified an exposed {detector_name} credential.",
                        category="secrets",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.CONFIRMED,
                        file_path=file_path,
                        start_line=line_no,
                        end_line=line_no,
                        cwe_ids=["CWE-798"],
                        owasp_refs=["A07:2021-Identification and Authentication Failures"],
                        raw_snippet=redacted_snippet,
                        technical_fix=self._get_rotation_guidance(detector_name),
                        validation_steps="Verify with securescan doctor and invalidate compromised key."
                    )
                )
            except Exception:
                continue
        return findings
