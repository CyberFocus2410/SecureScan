"""Unit tests for Step 11: OWASP LLM Top 10 Application Security Scanner."""
from pathlib import Path
import pytest

from app.scanners.ai_security import AiSecurityScanner
from app.schemas.enums import Severity, Confidence

FIXTURES_DIR = Path(__file__).parent.parent.parent.parent / "fixtures" / "ai-fixtures"
INSECURE_APP = FIXTURES_DIR / "insecure_ai_app.py"
CLEAN_APP = FIXTURES_DIR / "clean_ai_app.py"


def test_ai_security_scanner_detects_seeded_vulnerabilities(tmp_path):
    """Verifies detection of OWASP LLM Top 10 issues in the insecure AI fixture."""
    # Copy insecure app to temp dir for isolated testing
    insecure_dest = tmp_path / "insecure_app.py"
    insecure_dest.write_text(INSECURE_APP.read_text(encoding="utf-8"), encoding="utf-8")

    scanner = AiSecurityScanner()
    plan = scanner.prepare(tmp_path)
    result = scanner.execute(plan)

    assert result.status == "COMPLETED"
    rule_ids = [f.rule_id for f in result.raw_findings]

    # 1. LLM01: Prompt Injection
    assert "llm-prompt-injection-concatenation" in rule_ids
    pi_finding = next(f for f in result.raw_findings if f.rule_id == "llm-prompt-injection-concatenation")
    assert pi_finding.severity == Severity.HIGH
    assert "LLM01:2025-Prompt Injection" in pi_finding.owasp_refs

    # 2. LLM02: Sensitive Info Disclosure (Exposed API Key)
    assert "llm-sensitive-info-disclosure-api-key" in rule_ids
    key_finding = next(f for f in result.raw_findings if f.rule_id == "llm-sensitive-info-disclosure-api-key")
    assert key_finding.severity == Severity.CRITICAL
    # Verify parser-level redaction (raw key masked)
    assert "sk-proj-fakekey" not in key_finding.raw_snippet

    # 3. LLM05: Insecure Output Handling (eval)
    assert "llm-insecure-output-handling-eval" in rule_ids
    eval_finding = next(f for f in result.raw_findings if f.rule_id == "llm-insecure-output-handling-eval")
    assert eval_finding.severity == Severity.CRITICAL
    assert "CWE-94" in eval_finding.cwe_ids or "CWE-95" in eval_finding.cwe_ids

    # 4. LLM06: Excessive Agency (Destructive tool without approval)
    assert "llm-excessive-agency-unrestricted-tool" in rule_ids
    tool_finding = next(f for f in result.raw_findings if f.rule_id == "llm-excessive-agency-unrestricted-tool")
    assert tool_finding.severity == Severity.HIGH

    # 5. LLM08: Vector search missing tenant filter
    assert "llm-vector-search-missing-tenant-filter" in rule_ids
    v_finding = next(f for f in result.raw_findings if f.rule_id == "llm-vector-search-missing-tenant-filter")
    assert v_finding.severity == Severity.HIGH

    # 6. LLM10: Unbounded Consumption
    assert "llm-unbounded-consumption-missing-limits" in rule_ids


def test_ai_security_scanner_passes_clean_hardened_app(tmp_path):
    """Verifies that the clean, hardened AI application emits PASS_EVIDENCED findings with zero high/critical issues."""
    clean_dest = tmp_path / "clean_app.py"
    clean_dest.write_text(CLEAN_APP.read_text(encoding="utf-8"), encoding="utf-8")

    scanner = AiSecurityScanner()
    plan = scanner.prepare(tmp_path)
    result = scanner.execute(plan)

    assert result.status == "COMPLETED"

    # Zero High/Critical security findings
    high_or_crit = [f for f in result.raw_findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
    assert len(high_or_crit) == 0

    # Evidenced passes
    pass_rule_ids = [f.rule_id for f in result.raw_findings if f.rule_id.startswith("pass-llm-")]
    assert "pass-llm-prompt-boundaries-enforced" in pass_rule_ids
    assert "pass-llm-output-handling-validated" in pass_rule_ids
    assert "pass-llm-tool-agency-constrained" in pass_rule_ids
    assert "pass-llm-vector-tenant-isolation-enforced" in pass_rule_ids


def test_ai_security_scanner_contracts_and_metadata():
    """Validates adapter metadata and non-destructive execution contracts."""
    scanner = AiSecurityScanner()
    meta = scanner.metadata()

    assert meta.rules_version == "2025-owasp-llm-top10"
    assert "python" in meta.supported_languages
    assert scanner.is_available() is True
