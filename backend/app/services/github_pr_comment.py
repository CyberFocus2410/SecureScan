"""GitHub PR Comment Summary Service (Step 15, ADR-002).

Generates developer-friendly, actionable PR review comments summarizing
audit security findings, priority counts, gate status, and fix-pack links.
"""
from typing import Any


class GitHubPrCommentGenerator:
    """Formats audit results as a GitHub PR review comment."""

    @classmethod
    def generate_comment(
        cls,
        audit_id: str,
        gate_passed: bool,
        fail_on_threshold: str,
        findings: list[dict[str, Any]],
        dpdp_score: int | None = None,
        commit_sha: str | None = None
    ) -> str:
        status_badge = "✅ **SECURESCAN CI GATE: PASSED**" if gate_passed else "❌ **SECURESCAN CI GATE: FAILED**"
        verdict_msg = (
            f"No active findings met or exceeded threshold `{fail_on_threshold}`."
            if gate_passed
            else f"Audit identified active findings meeting or exceeding threshold `{fail_on_threshold}`."
        )

        # Count active findings by priority (P0-P3)
        p_counts = {"P0": 0, "P1": 0, "P2": 0, "P3": 0}
        active_findings = []
        for f in findings:
            st = f.get("status", "open")
            if st in {"accepted-risk", "false-positive", "fixed"}:
                continue
            pri = f.get("priority") or "P2"
            if pri in p_counts:
                p_counts[pri] += 1
            active_findings.append(f)

        dpdp_line = f"- **India DPDP Readiness Score**: `{dpdp_score}/100`\n" if dpdp_score is not None else ""
        sha_str = f" (`{commit_sha[:8]}`)" if commit_sha else ""

        # Top findings table
        if active_findings:
            table_header = "| Priority | Rule / Title | File & Line | Fix Effort |\n|---|---|---|---|\n"
            table_rows = []
            for f in active_findings[:10]:
                pri = f.get("priority", "P2")
                title = f.get("plain_title") or f.get("title") or f.get("rule_id", "Vulnerability")
                loc = f"`{f.get('file_path', 'unknown')}:{f.get('start_line', 1)}`"
                effort = f.get("fix_effort", "10-30 min")
                table_rows.append(f"| **{pri}** | {title} | {loc} | {effort} |")
            findings_table = table_header + "\n".join(table_rows)
            if len(active_findings) > 10:
                findings_table += f"\n\n*... and {len(active_findings) - 10} more findings.*"
        else:
            findings_table = "🎉 *No active security findings detected.*"

        comment = f"""## 🛡️ SecureScan AI Security Gate{sha_str}

{status_badge}
> {verdict_msg}

### Summary
- **P0 (Emergency)**: {p_counts['P0']}
- **P1 (Critical)**: {p_counts['P1']}
- **P2 (Important)**: {p_counts['P2']}
- **P3 (Improvement)**: {p_counts['P3']}
{dpdp_line}

### Active Findings
{findings_table}

---
💡 **Remediation & Fix Pack**: Download automated patches or review full details:
`securescan fix-pack {audit_id}` or visit the SecureScan dashboard.

> *Developer-assistance report — not a security certificate or legal opinion.*
"""
        return comment.strip()
