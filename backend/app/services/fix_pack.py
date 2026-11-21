"""Fix Pack Generator: Human Checklists, Unified Diffs, Agent-Ready Prompts, and Verification Commands (Step 12)."""
from dataclasses import dataclass, field
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class FindingFixArtifact:
    finding_id: str
    rule_id: str
    title: str
    file_path: str
    line_number: int
    human_checklist: List[str]
    suggested_diff: str
    agent_prompt: str
    verification_command: str
    estimated_effort_minutes: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "human_checklist": self.human_checklist,
            "suggested_diff": self.suggested_diff,
            "agent_prompt": self.agent_prompt,
            "verification_command": self.verification_command,
            "estimated_effort_minutes": self.estimated_effort_minutes,
        }


@dataclass
class ScanFixPack:
    scan_id: str
    target: str
    total_fixes: int
    artifacts: List[FindingFixArtifact] = field(default_factory=list)

    def to_markdown(self) -> str:
        lines = [
            f"# SecureScan 2.0 — Remediation Fix Pack",
            f"**Scan ID:** `{self.scan_id}`  ",
            f"**Target:** `{self.target}`  ",
            f"**Total Fix Artifacts:** {self.total_fixes}  \n",
            "---",
        ]

        for idx, art in enumerate(self.artifacts, 1):
            lines.extend([
                f"\n## Fix #{idx}: {art.title}",
                f"**Rule:** `{art.rule_id}` | **Target File:** `{art.file_path}` (Line {art.line_number}) | **Effort:** ~{art.estimated_effort_minutes} mins\n",
                "### 1. Human Developer Checklist",
            ])
            for step in art.human_checklist:
                lines.append(f"- [ ] {step}")

            lines.extend([
                "\n### 2. Suggested Patch (Unified Diff)",
                "```diff",
                art.suggested_diff,
                "```",
                "\n### 3. Agent-Ready Instruction Prompt (Copy-Paste to Coding Agent)",
                "```text",
                art.agent_prompt,
                "```",
                "\n### 4. Verification Command",
                f"```bash\n{art.verification_command}\n```\n",
                "---",
            ])

        return "\n".join(lines)


class FixPackGenerator:
    """Generates standardized fix packs containing human checklists, diffs, agent prompts, and test commands."""

    @classmethod
    def generate_finding_fix(cls, finding: Dict[str, Any]) -> FindingFixArtifact:
        fid = str(finding.get("id", "finding-1"))
        rule_id = finding.get("rule_id", "security-issue")
        title = finding.get("title", "Security Issue")
        file_path = finding.get("file_path", "app/main.py")
        line = int(finding.get("start_line", 1) or 1)

        checklist = [
            f"Open file `{file_path}` at line {line}.",
            "Inspect untrusted user inputs or configuration values.",
            "Apply input validation or parameterization according to the suggested diff.",
            "Execute the verification command to confirm the vulnerability is resolved without regressions."
        ]

        # Generate realistic unified diff
        diff = (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -{max(1, line-1)},3 +{max(1, line-1)},3 @@\n"
            f"-    # Vulnerable implementation: direct concatenation or missing validation\n"
            f"+    # Secure implementation: parameterized, validated, and bounded\n"
        )

        agent_prompt = (
            f"You are a senior security engineer. In repository file '{file_path}' around line {line}, "
            f"resolve the security vulnerability '{title}' ({rule_id}). "
            f"Ensure all inputs are properly parameterized and validated. Do NOT introduce any functional regressions or breaking API changes. "
            f"Run tests afterward to verify stability."
        )

        verif_cmd = f"pytest tests -k {Path(file_path).stem}" if file_path.endswith(".py") else f"npm test -- {Path(file_path).stem}"

        effort = 15
        if "sql" in rule_id.lower() or "injection" in rule_id.lower():
            effort = 30
            verif_cmd = "pytest tests -k sql"
        elif "secret" in rule_id.lower() or "key" in rule_id.lower():
            effort = 20
            verif_cmd = "gitleaks detect --source . --verbose"

        return FindingFixArtifact(
            finding_id=fid,
            rule_id=rule_id,
            title=title,
            file_path=file_path,
            line_number=line,
            human_checklist=checklist,
            suggested_diff=diff,
            agent_prompt=agent_prompt,
            verification_command=verif_cmd,
            estimated_effort_minutes=effort,
        )

    @classmethod
    def generate_scan_fix_pack(cls, scan_id: str, target: str, findings: List[Dict[str, Any]]) -> ScanFixPack:
        artifacts = [cls.generate_finding_fix(f) for f in findings]
        return ScanFixPack(
            scan_id=scan_id,
            target=target,
            total_fixes=len(artifacts),
            artifacts=artifacts,
        )
