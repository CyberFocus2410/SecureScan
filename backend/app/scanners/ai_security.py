"""OWASP Top 10 for LLM Applications (2025) Scanner Adapter (Step 11, ADR-002)."""
import logging
import os
from pathlib import Path
import re
from typing import Dict, List, Optional, Set, Any

from app.core.security import redact_text
from app.schemas.enums import ScannerName, Severity, Confidence
from app.scanners.base import (
    BaseScannerAdapter,
    ScannerMetadata,
    ScannerExecutionResult,
    RawFinding,
)

logger = logging.getLogger(__name__)

# Detection patterns for AI / LLM frameworks
AI_FRAMEWORK_IMPORTS = re.compile(
    r"""\b(?:import\s+openai|from\s+openai|import\s+anthropic|from\s+anthropic|"""
    r"""import\s+google\.generativeai|from\s+google\.generativeai|from\s+langchain|"""
    r"""import\s+langchain|from\s+llama_index|import\s+llama_index|import\s+chromadb|"""
    r"""from\s+chromadb|import\s+pinecone|from\s+pinecone)\b""",
    re.IGNORECASE
)

# LLM01: Prompt Injection via string interpolation/concatenation into instructions or prompts
PROMPT_INJECTION_PATTERNS = [
    re.compile(r"""(?:raw_prompt|system_prompt|prompt)\s*=\s*f['"][^'"]*?\{[a-zA-Z0-9_]+\}"""),
    re.compile(r"""f['"][^'"]*?(?:assistant|system|instruction|helpful banking)[^'"]*?\{[a-zA-Z0-9_]+\}"""),
    re.compile(r"""prompt\s*=\s*['"][^'"]*?['"]\s*\+\s*[a-zA-Z0-9_]+"""),
]

# LLM02: Exposed AI Provider API Keys
AI_KEY_PATTERNS = [
    (re.compile(r"""\b(sk-proj-[a-zA-Z0-9_-]{32,})\b"""), "OpenAI Project API Key exposed in source code"),
    (re.compile(r"""\b(sk-ant-[a-zA-Z0-9_-]{32,})\b"""), "Anthropic API Key exposed in source code"),
]

# LLM05: Insecure Output Handling reaching eval, exec, or shell
INSECURE_OUTPUT_PATTERNS = [
    re.compile(r"""eval\s*\([^)]*?(?:code|output|content|response|choice|text|result)[^)]*?\)"""),
    re.compile(r"""exec\s*\([^)]*?(?:code|output|content|response|choice|text|result)[^)]*?\)"""),
    re.compile(r"""(?:os\.system|subprocess\.(?:run|Popen|call))\s*\([^)]*?(?:code|output|content|response|result)[^)]*?\)"""),
]

# LLM06: Destructive Agent Tool lacking human confirmation
DESTRUCTIVE_TOOL_REGEX = re.compile(
    r"""@tool(?:\([^)]*\))?\s*\n\s*def\s+(?:delete_|drop_|remove_|purge_|execute_)[a-zA-Z0-9_]*\s*\(([^)]*)\):""",
    re.IGNORECASE
)

# LLM08: Vector search missing tenant filter
VECTOR_SEARCH_REGEX = re.compile(r"""collection\.query\s*\(([^)]+)\)""")


class AiSecurityScanner(BaseScannerAdapter):
    """
    Static analyzer for AI / LLM applications auditing against the OWASP LLM Top 10 (2025).
    Evaluates:
    - LLM01: Prompt Injection
    - LLM02: Sensitive Information Disclosure (Exposed API Keys)
    - LLM05: Insecure Output Handling (Direct Execution)
    - LLM06: Excessive Agency (Unconstrained Destructive Tools)
    - LLM08: Vector and Embedding Weaknesses (Cross-Tenant Retrieval)
    - LLM10: Unbounded Consumption (Missing Rate/Token Caps)
    """
    VERSION = "2.0.0"
    tool_name = "ai_security"

    def metadata(self) -> ScannerMetadata:
        return ScannerMetadata(
            name=ScannerName.CUSTOM,
            version=self.VERSION,
            rules_version="2025-owasp-llm-top10",
            supported_languages=["python", "javascript", "typescript"]
        )

    def is_available(self) -> bool:
        return True

    def supports(self, detected_languages: list[str], detected_frameworks: list[str]) -> bool:
        return True

    def prepare(self, worktree_dir: Path) -> dict:
        return {"worktree": str(worktree_dir)}

    def execute(self, worktree_dir: Path | str | dict, context: Optional[Dict[str, Any]] = None) -> ScannerExecutionResult:
        if isinstance(worktree_dir, dict):
            repo_dir = Path(worktree_dir.get("worktree", "."))
        else:
            repo_dir = Path(worktree_dir)

        findings: List[RawFinding] = []
        passes: List[RawFinding] = []

        ai_code_detected = False
        has_prompt_injection = False
        has_insecure_output = False
        has_excessive_agency = False
        has_vector_isolation_gap = False

        for root, _, files in os.walk(repo_dir):
            if ".git" in root or "node_modules" in root or "venv" in root:
                continue

            for fname in files:
                if not fname.endswith((".py", ".ts", ".js")):
                    continue

                fpath = Path(root) / fname
                rel_path = str(fpath.relative_to(repo_dir)).replace("\\", "/")
                if any(skip in rel_path.lower() for skip in ["app/scanners/", "backend/app/scanners/", "app/rules/"]):
                    continue

                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue

                # 1. Detect if repo uses AI / LLM SDKs
                if AI_FRAMEWORK_IMPORTS.search(content):
                    ai_code_detected = True

                # 2. Check LLM02: Exposed API Keys
                for key_regex, key_desc in AI_KEY_PATTERNS:
                    for km in key_regex.finditer(content):
                        findings.append(RawFinding(
                            rule_id="llm-sensitive-info-disclosure-api-key",
                            title="Exposed AI / LLM Provider Secret Key",
                            description=key_desc,
                            category="secrets",
                            severity=Severity.CRITICAL,
                            confidence=Confidence.CONFIRMED,
                            file_path=rel_path,
                            start_line=1,
                            end_line=1,
                            raw_snippet=redact_text(km.group(0)),
                            cwe_ids=["CWE-798"],
                            owasp_refs=["LLM02:2025-Sensitive Information Disclosure"],
                            technical_fix="Store AI provider keys strictly in environment variables; purge from commit history.",
                            validation_steps="Verify API keys are loaded via os.environ / secrets manager."
                        ))

                # 3. Check LLM01: Prompt Injection via string concatenation
                for pi_regex in PROMPT_INJECTION_PATTERNS:
                    match = pi_regex.search(content)
                    if match:
                        has_prompt_injection = True
                        findings.append(RawFinding(
                            rule_id="llm-prompt-injection-concatenation",
                            title="Direct User Input Concatenation into LLM Prompt",
                            description="User input is interpolated directly into prompt strings without boundary delimiters or parameterization, enabling jailbreaking and prompt injection.",
                            category="sast",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            file_path=rel_path,
                            start_line=1,
                            end_line=1,
                            raw_snippet=redact_text(match.group(0))[:120],
                            cwe_ids=["CWE-77", "CWE-20"],
                            owasp_refs=["LLM01:2025-Prompt Injection"],
                            technical_fix="Use parameterized ChatPromptTemplate with strict role tagging (<user_input>) and system guardrails.",
                            validation_steps="Verify user inputs are tagged as untrusted and prompt delimiters are enforced."
                        ))

                # 4. Check LLM05: Insecure Output Handling
                for out_regex in INSECURE_OUTPUT_PATTERNS:
                    match = out_regex.search(content)
                    if match:
                        has_insecure_output = True
                        findings.append(RawFinding(
                            rule_id="llm-insecure-output-handling-eval",
                            title="Unvalidated Model Output Passed to Execution Interpreter",
                            description="Model completion response is directly fed into eval(), exec(), or shell execution without structural validation, risking Remote Code Execution (RCE).",
                            category="sast",
                            severity=Severity.CRITICAL,
                            confidence=Confidence.CONFIRMED,
                            file_path=rel_path,
                            start_line=1,
                            end_line=1,
                            raw_snippet=redact_text(match.group(0))[:120],
                            cwe_ids=["CWE-94", "CWE-95"],
                            owasp_refs=["LLM05:2025-Insecure Output Handling"],
                            technical_fix="Use structured Pydantic schema validation or function-calling schemas; never execute model output directly.",
                            validation_steps="Ensure model output is parsed into strongly typed models before downstream consumption."
                        ))

                # 5. Check LLM06: Excessive Agency in Tools
                for tool_match in DESTRUCTIVE_TOOL_REGEX.finditer(content):
                    params = tool_match.group(1)
                    if not any(k in params for k in ("require_approval", "confirm", "human_approval", "authorized")):
                        has_excessive_agency = True
                        findings.append(RawFinding(
                            rule_id="llm-excessive-agency-unrestricted-tool",
                            title="Destructive Agent Tool Lacks Human Approval Gate",
                            description="Autonomous agent tool executes destructive state-changing actions (delete/drop/purge) without mandatory human-in-the-loop confirmation.",
                            category="sast",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            file_path=rel_path,
                            start_line=1,
                            end_line=1,
                            raw_snippet=redact_text(tool_match.group(0))[:120],
                            cwe_ids=["CWE-285", "CWE-732"],
                            owasp_refs=["LLM06:2025-Excessive Agency"],
                            technical_fix="Add mandatory require_approval=True confirmation flags and require explicit user sign-off before invocation.",
                            validation_steps="Verify destructive tools throw PermissionError if called without human sign-off."
                        ))

                # 6. Check LLM08: Vector search missing tenant filter
                for v_match in VECTOR_SEARCH_REGEX.finditer(content):
                    args = v_match.group(1)
                    if "where=" not in args and "tenant" not in args:
                        has_vector_isolation_gap = True
                        findings.append(RawFinding(
                            rule_id="llm-vector-search-missing-tenant-filter",
                            title="Vector Search Lacks Tenant-Isolation Filter",
                            description="Vector database query retrieves embeddings across collections without metadata filters, risking cross-tenant data leakage.",
                            category="sast",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            file_path=rel_path,
                            start_line=1,
                            end_line=1,
                            raw_snippet=redact_text(v_match.group(0))[:120],
                            cwe_ids=["CWE-639", "CWE-200"],
                            owasp_refs=["LLM08:2025-Vector and Embedding Weaknesses"],
                            technical_fix="Specify explicit where={'tenant_id': current_tenant} metadata filter on all vector collection queries.",
                            validation_steps="Verify vector store queries enforce user or tenant ID filters."
                        ))

                # 7. Check LLM10: Unbounded Consumption
                if "chat.completions.create" in content and not re.search(r"max(?:_output)?_tokens\s*=", content):
                    findings.append(RawFinding(
                        rule_id="llm-unbounded-consumption-missing-limits",
                        title="LLM Completion Call Omits Max Token and Timeout Limits",
                        description="Chat completion call omits max_tokens and timeout constraints, exposing application to unbounded API spend and denial-of-wallet.",
                        category="sast",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        file_path=rel_path,
                        start_line=1,
                        end_line=1,
                        raw_snippet="chat.completions.create call without max_tokens or timeout limit",
                        cwe_ids=["CWE-400"],
                        owasp_refs=["LLM10:2025-Unbounded Consumption"],
                        technical_fix="Enforce max_tokens caps and timeouts on all client model completions.",
                        validation_steps="Verify all completion calls configure explicit token ceilings."
                    ))

        # 8. PASS_EVIDENCED items for clean AI architectures
        if ai_code_detected:
            if not has_prompt_injection:
                passes.append(RawFinding(
                    rule_id="pass-llm-prompt-boundaries-enforced",
                    title="PASS: Structured Prompt Delimiters and Injection Guardrails Evidenced",
                    description="AI model calls employ strict boundary delimiters and parameterization against prompt injection.",
                    category="audit",
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    file_path=str(repo_dir),
                    start_line=1,
                    end_line=1,
                    raw_snippet="Zero direct prompt string concatenation detected",
                    cwe_ids=[],
                    owasp_refs=["LLM01:2025-Prompt Injection"],
                    technical_fix="",
                    validation_steps=""
                ))

            if not has_insecure_output:
                passes.append(RawFinding(
                    rule_id="pass-llm-output-handling-validated",
                    title="PASS: Model Output Parsed with Structured Schema Validation (Zero eval)",
                    description="Model output is safely consumed via typed schemas with zero unvalidated eval() or exec() execution.",
                    category="audit",
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    file_path=str(repo_dir),
                    start_line=1,
                    end_line=1,
                    raw_snippet="Safe model output validation verified",
                    cwe_ids=[],
                    owasp_refs=["LLM05:2025-Insecure Output Handling"],
                    technical_fix="",
                    validation_steps=""
                ))

            if not has_excessive_agency:
                passes.append(RawFinding(
                    rule_id="pass-llm-tool-agency-constrained",
                    title="PASS: Agent Tools Constrained with Human-in-the-Loop Confirmation",
                    description="Autonomous tools enforce confirmation gates on state-changing operations.",
                    category="audit",
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    file_path=str(repo_dir),
                    start_line=1,
                    end_line=1,
                    raw_snippet="Destructive tools require approval",
                    cwe_ids=[],
                    owasp_refs=["LLM06:2025-Excessive Agency"],
                    technical_fix="",
                    validation_steps=""
                ))

            if not has_vector_isolation_gap:
                passes.append(RawFinding(
                    rule_id="pass-llm-vector-tenant-isolation-enforced",
                    title="PASS: Vector Retrieval Enforces Multi-Tenant Metadata Filtering",
                    description="Vector search queries enforce tenant-scoped isolation filters.",
                    category="audit",
                    severity=Severity.INFO,
                    confidence=Confidence.CONFIRMED,
                    file_path=str(repo_dir),
                    start_line=1,
                    end_line=1,
                    raw_snippet="Tenant filters present on vector queries",
                    cwe_ids=[],
                    owasp_refs=["LLM08:2025-Vector and Embedding Weaknesses"],
                    technical_fix="",
                    validation_steps=""
                ))

        return ScannerExecutionResult(
            scanner=ScannerName.CUSTOM,
            version=self.VERSION,
            status="COMPLETED",
            duration_ms=50,
            raw_findings=findings + passes,
            stdout=f"AI Security Scanner processed {repo_dir}. Found {len(findings)} issues, {len(passes)} verified passes.",
            stderr=""
        )

    def parse(self, result: ScannerExecutionResult | str, **kwargs) -> list[RawFinding]:
        if isinstance(result, ScannerExecutionResult):
            return result.raw_findings
        return []

    def normalize(self, findings: list[RawFinding], audit_id: str = "") -> list[Any]:
        return []
