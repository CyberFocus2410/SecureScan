"""Developer Markdown Report Exporter (Step 13, ADR-002)."""
import logging
from sqlalchemy.orm import Session
from app.reporting.collector import collect_audit_report_data
from app.core.security import redact_text

logger = logging.getLogger(__name__)


def generate_markdown_report(audit_id: str, db: Session) -> str:
    """Generates structured developer Markdown report with zero raw secrets."""
    data = collect_audit_report_data(audit_id, db)
    audit = data.get("audit", {})
    findings = data.get("findings", [])
    controls = data.get("controls", [])
    penalties = data.get("legal_exposure", {}).get("statutory_penalties", [])

    lines = [
        "# SecureScan 2.0 — Security & DPDP Readiness Audit Report",
        "> **Notice:** Developer-assistance report — not a security certificate or legal opinion.  ",
        f"> **Audit ID:** `{audit.get('id')}` | **Target:** `{audit.get('repository', {}).get('canonical_url', 'target')}` | **Date:** {audit.get('created_at', '')[:10]}\n",
        "---",
        "\n## 1. Executive Summary & Priority Metrics",
        f"- **Status:** `{audit.get('status', 'COMPLETED')}`",
        f"- **Total Security Findings:** {len(findings)}",
        f"- **DPDP Controls Assessed:** {len(controls)}\n",
        "### Findings Breakdown by Priority",
        "| Priority | Level | Description | Count |",
        "|:---:|---|---|:---:|",
        f"| **P0** | Critical | Confirmed exploitability / immediate danger | {sum(1 for f in findings if f.get('priority') == 'P0')} |",
        f"| **P1** | High | High impact, conditional exploitability | {sum(1 for f in findings if f.get('priority') == 'P1')} |",
        f"| **P2** | Medium | Moderate risk / hardening gap | {sum(1 for f in findings if f.get('priority') == 'P2')} |",
        f"| **P3** | Low / Info | Informational / code hygiene | {sum(1 for f in findings if f.get('priority') == 'P3')} |",
        "\n---",
        "\n## 2. Detailed Technical Findings & Remediation",
    ]

    for idx, f in enumerate(findings, 1):
        lines.extend([
            f"\n### #{idx} [{f.get('priority', 'P2')}] {f.get('title', 'Vulnerability')}",
            f"- **Rule ID:** `{f.get('rule_id')}`",
            f"- **Severity:** `{f.get('severity')}` | **Confidence:** `{f.get('confidence')}`",
            f"- **Location:** `{f.get('file_path')}`:{f.get('start_line', 1)}",
            f"- **Description:** {f.get('description', '')}",
            f"- **Remediation:** {f.get('how_to_fix') or f.get('technical_fix', 'Apply input validation and security controls.')}",
            f"- **Verification:** `{f.get('how_to_verify_fix') or f.get('validation_steps', 'Re-run scanner to verify remediation.')}`",
        ])

    lines.extend([
        "\n---",
        "\n## 3. India DPDP Act 2023 Readiness & Statutory Penalty Ceilings",
        "> **Mandatory Legal Caveat:** *Potential legal category; applicability and liability not determined.*  ",
        "> SecureScan AI strictly reports statutory upper ceilings under Section 33. It never calculates, predicts, or sums fines.\n",
        "| Schedule Item | Statutory Breach Provision | Statutory Ceiling | SecureScan Control Linkage |",
        "|:---:|---|---|:---:|",
        "| **Item 1** | Section 8(5) - Reasonable security safeguards failure | Up to ₹250 crore | DPDP-006, DPDP-018 |",
        "| **Item 2** | Section 8(6) - Personal data breach notification failure | Up to ₹200 crore | DPDP-007 |",
        "| **Item 3** | Section 9 - Children's data obligations failure | Up to ₹200 crore | DPDP-011, DPDP-012 |",
        "| **Item 4** | Section 10 - Significant Data Fiduciary obligations failure | Up to ₹150 crore | DPDP-013 |",
        "| **Item 5** | Section 15 - Data Principal duties failure | Up to ₹10,000 | DPDP-010 |",
        "| **Item 6** | Section 32 - Breach of voluntary undertaking | Extent of underlying breach | DPDP-001 |",
        "| **Item 7** | Other provisions of Act / Rules | Up to ₹50 crore | Residual Controls |",
        "\n---",
        "\n## 4. Appendix: Pinned Tool Inventory",
        "- **SAST:** Semgrep OSS (pinned) / Custom AST Engine",
        "- **Secrets:** Gitleaks 8.30.1 / TruffleHog OSS",
        "- **Dependencies:** OSV-Scanner / pip-audit",
        "- **IaC / Container:** IacConfigScanner",
        "- **DAST / Web:** Scoped DAST Engine",
        "- **API Security:** OWASP API Top 10 Engine",
        "- **AI Security:** OWASP LLM Top 10 Engine",
    ])

    raw_md = "\n".join(lines)
    return redact_text(raw_md)
