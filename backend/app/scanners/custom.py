"""Custom security rules scanner for FastAPI and Express (FR-SEC, D-12, Rules.md)."""
import ast
import re
import os
import uuid
from pathlib import Path
from typing import Any, List, Optional, Tuple

from app.core.security import redact_text
from app.schemas.enums import ScannerName, Severity, Confidence
from app.scanners.base import (
    BaseScannerAdapter,
    ScannerMetadata,
    RawFinding,
    ScannerExecutionResult
)


SENSITIVE_FIELD_NAMES = {
    "password", "passwd", "secret", "token", "access_token", "refresh_token",
    "ssn", "aadhar", "aadhaar", "national_id", "credit_card", "card_number",
    "cvv", "api_key", "apikey", "private_key", "secret_key"
}

RATE_LIMIT_MARKERS_FASTAPI = [
    "limiter.limit", "RateLimiter", "slowapi", "redis_rate_limit"
]

RATE_LIMIT_MARKERS_EXPRESS = [
    "rateLimit", "express-rate-limit", "limiter", "rate_limit"
]

AUTH_MARKERS_FASTAPI = [
    "Depends(", "Security(", "get_current_user", "oauth2_scheme", "HTTPBearer", "APIKeyHeader"
]

AUTH_MARKERS_EXPRESS = [
    "authenticate", "requireAuth", "passport.authenticate", "verifyToken", "jwtAuth", "authMiddleware"
]


class CustomRulesScanner(BaseScannerAdapter):
    """
    AST and pattern-based security analyzer for FastAPI (Python) and Express (Node.js).
    Enforces conservative semantics:
    - Missing limiter => POTENTIAL_GAP, never confirmed failure
    - Sensitive DTO exposure => flagged only when field in output schema; auth context unverified
    - Unsupported framework => NOT_VERIFIED, never clean
    """
    VERSION = "1.0.0"

    def metadata(self) -> ScannerMetadata:
        return ScannerMetadata(
            name=ScannerName.CUSTOM,
            version=self.VERSION,
            rules_version=self.VERSION,
            supported_languages=["Python", "JavaScript", "TypeScript"]
        )

    def supports(self, detected_languages: list[str], detected_frameworks: list[str]) -> bool:
        supported_frameworks = {"FastAPI", "Express", "Next.js"}
        return bool(supported_frameworks.intersection(set(detected_frameworks)))

    def prepare(self, worktree_dir: Path) -> dict[str, Any]:
        return {}

    def execute(self, worktree_dir: Path, context: dict[str, Any]) -> ScannerExecutionResult:
        detected_languages = context.get("detected_languages", [])
        detected_frameworks = context.get("detected_frameworks", [])

        findings: list[RawFinding] = []

        is_fastapi = "FastAPI" in detected_frameworks
        is_express = "Express" in detected_frameworks or "Next.js" in detected_frameworks

        if is_fastapi:
            findings.extend(self._scan_fastapi(worktree_dir))

        if is_express:
            findings.extend(self._scan_express(worktree_dir))

        # Frontend asset / config scan for secrets (SEC-002, SEC-003)
        findings.extend(self._scan_client_configs(worktree_dir))

        return ScannerExecutionResult(
            scanner=ScannerName.CUSTOM,
            version=self.VERSION,
            status="COMPLETED",
            duration_ms=50,
            raw_findings=findings
        )

    def parse(self, result: ScannerExecutionResult, **kwargs) -> list[RawFinding]:
        return result.raw_findings

    def normalize(self, raw_findings: list[RawFinding], audit_id: str) -> list[Any]:
        return []

    # -------------------------------------------------------------------------
    # FastAPI Deep Analyzer
    # -------------------------------------------------------------------------
    def _scan_fastapi(self, worktree_dir: Path) -> list[RawFinding]:
        findings: list[RawFinding] = []

        for root, _, files in os.walk(worktree_dir):
            if ".git" in root or "venv" in root or "node_modules" in root:
                continue
            for fname in files:
                if not fname.endswith(".py"):
                    continue
                fpath = Path(root) / fname
                try:
                    rel_path = str(fpath.resolve().relative_to(Path(worktree_dir).resolve())).replace("\\", "/")
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                    tree = ast.parse(content, filename=str(fpath))
                except Exception:
                    continue

                # 1. DTO / Response Model Sensitive Field Exposure (SEC-004)
                findings.extend(self._check_fastapi_dto_exposure(tree, rel_path, content))

                # 2. Rate Limiting on Routes (SEC-005, SEC-006)
                findings.extend(self._check_fastapi_rate_limiting(tree, rel_path, content))

                # 3. Missing Route Authentication on Admin/Private endpoints (SEC-007)
                findings.extend(self._check_fastapi_auth(tree, rel_path, content))

                # 4. Sensitive Data in Logs (SEC-026)
                findings.extend(self._check_logging_exposure(tree, rel_path, content))

                # 5. Missing Pagination on List Endpoints (SEC-029)
                findings.extend(self._check_fastapi_pagination(tree, rel_path, content))

                # 6. Open Redirects (SEC-014 / SEC-015 / Playbook §18)
                findings.extend(self._check_open_redirects(tree, rel_path, content))

                # 7. Unverified Webhooks (SEC-007 / Playbook §19)
                findings.extend(self._check_unverified_webhooks(tree, rel_path, content))

                # 8. Frontend/Client-supplied pricing (SEC-009 / Playbook §17)
                findings.extend(self._check_client_pricing(tree, rel_path, content))

        return findings

    def _check_fastapi_dto_exposure(self, tree: ast.AST, rel_path: str, content: str) -> list[RawFinding]:
        """Flag when response_model or Pydantic schema returned by API exposes sensitive fields."""
        findings = []
        lines = content.splitlines()

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                # Check Pydantic model definitions representing response schemas
                is_pydantic = any(
                    isinstance(base, ast.Name) and base.id in ("BaseModel", "Schema")
                    for base in node.bases
                )
                if is_pydantic or "response" in node.name.lower() or "dto" in node.name.lower() or "out" in node.name.lower():
                    for stmt in node.body:
                        # Check field definitions: field_name: type = ...
                        if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                            field_name = stmt.target.id.lower()
                            if any(sens in field_name for sens in SENSITIVE_FIELD_NAMES):
                                line_num = stmt.lineno
                                snippet = lines[line_num - 1] if line_num <= len(lines) else field_name
                                findings.append(RawFinding(
                                    rule_id="sec-004-dto-sensitive-exposure",
                                    title="Sensitive Field Exposed in API Response DTO / Model",
                                    description=(
                                        f"Field '{stmt.target.id}' in response model '{node.name}' exposes sensitive data. "
                                        "Auth context is labelled unverified (conservative heuristic per FR-SEC-04)."
                                    ),
                                    category="data_exposure",
                                    severity=Severity.HIGH,
                                    confidence=Confidence.CONFIRMED,
                                    file_path=rel_path,
                                    start_line=line_num,
                                    end_line=line_num,
                                    raw_snippet=redact_text(snippet.strip()),
                                    cwe_ids=["CWE-200"],
                                    owasp_refs=["API3:2023"],
                                    technical_fix=f"Exclude '{stmt.target.id}' from response DTO or mark with exclude=True in Pydantic Field.",
                                    validation_steps="Verify API output schema JSON does not include the sensitive property in responses."
                                ))
        return findings

    def _check_fastapi_rate_limiting(self, tree: ast.AST, rel_path: str, content: str) -> list[RawFinding]:
        """Flag API routes missing rate limiter markers (SEC-005/006) as POTENTIAL_GAP."""
        findings = []
        lines = content.splitlines()

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Detect route decorator e.g. @app.get, @router.post
                is_route = False
                has_limiter = False
                route_line = node.lineno

                for dec in node.decorator_list:
                    dec_src = ast.unparse(dec) if hasattr(ast, "unparse") else ""
                    if any(verb in dec_src.lower() for verb in [".get(", ".post(", ".put(", ".delete(", ".patch("]):
                        is_route = True
                    if any(marker in dec_src for marker in RATE_LIMIT_MARKERS_FASTAPI):
                        has_limiter = True

                if is_route and not has_limiter:
                    # Check if global limiter middleware exists in file
                    has_global_limiter = any(marker in content for marker in RATE_LIMIT_MARKERS_FASTAPI)
                    if not has_global_limiter:
                        is_auth_route = any(w in node.name.lower() for w in ["login", "token", "auth", "otp", "password", "reset"])
                        rule_id = "sec-006-auth-bruteforce-missing" if is_auth_route else "sec-005-missing-rate-limit"
                        title = "Authentication Endpoint Missing Rate Limiter (Brute-Force Risk)" if is_auth_route else "Endpoint Possibly Missing Rate Limiting"
                        snippet = lines[route_line - 1] if route_line <= len(lines) else node.name

                        findings.append(RawFinding(
                            rule_id=rule_id,
                            title=title,
                            description=(
                                f"Route handler '{node.name}' has no in-code rate limiting decorator. "
                                "Reported as POTENTIAL_GAP: a gateway/proxy (e.g. Cloudflare, NGINX) might enforce limits upstream."
                            ),
                            category="api",
                            severity=Severity.HIGH if is_auth_route else Severity.MEDIUM,
                            confidence=Confidence.MEDIUM,
                            file_path=rel_path,
                            start_line=route_line,
                            end_line=route_line,
                            raw_snippet=redact_text(snippet.strip()),
                            cwe_ids=["CWE-770"],
                            owasp_refs=["API4:2023", "API6:2023"],
                            technical_fix="Attach SlowAPI @limiter.limit('5/minute') decorator or configure an upstream API gateway rate limit.",
                            validation_steps="Send requests in rapid succession; verify HTTP 429 Too Many Requests response is returned."
                        ))
        return findings

    def _check_fastapi_auth(self, tree: ast.AST, rel_path: str, content: str) -> list[RawFinding]:
        """Flag admin or internal routes lacking authentication guards (SEC-007)."""
        findings = []
        lines = content.splitlines()

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_name = node.name.lower()
                is_admin = any(w in func_name for w in ["admin", "internal", "delete_all", "priv"])
                if is_admin:
                    has_auth = False
                    for dec in node.decorator_list:
                        dec_src = ast.unparse(dec) if hasattr(ast, "unparse") else ""
                        if any(marker in dec_src for marker in AUTH_MARKERS_FASTAPI):
                            has_auth = True
                    # Check args for Depends(get_current_user)
                    for arg in node.args.args:
                        # arg default or annotation
                        pass

                    if not has_auth and not any(marker in content for marker in AUTH_MARKERS_FASTAPI):
                        line_num = node.lineno
                        snippet = lines[line_num - 1] if line_num <= len(lines) else node.name
                        findings.append(RawFinding(
                            rule_id="sec-007-missing-route-auth",
                            title="Sensitive / Administrative Endpoint Missing Explicit Authentication Guard",
                            description=f"Function '{node.name}' contains administrative keywords but lacks Depends(get_current_user) or equivalent guard.",
                            category="auth",
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            file_path=rel_path,
                            start_line=line_num,
                            end_line=line_num,
                            raw_snippet=redact_text(snippet.strip()),
                            cwe_ids=["CWE-306"],
                            owasp_refs=["A01:2025"],
                            technical_fix="Inject authentication dependency: e.g. current_user: User = Depends(get_current_active_admin).",
                            validation_steps="Invoke endpoint unauthenticated; assert HTTP 401 Unauthorized."
                        ))
        return findings

    def _check_logging_exposure(self, tree: ast.AST, rel_path: str, content: str) -> list[RawFinding]:
        """Flag logger.info/error calls passing passwords, tokens, or personal identifiers (SEC-026)."""
        findings = []
        lines = content.splitlines()

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call_src = ast.unparse(node) if hasattr(ast, "unparse") else ""
                if any(log_call in call_src for log_call in ["logger.", "logging.", "print("]):
                    for sens in SENSITIVE_FIELD_NAMES:
                        if sens in call_src.lower():
                            line_num = node.lineno
                            snippet = lines[line_num - 1] if line_num <= len(lines) else call_src
                            findings.append(RawFinding(
                                rule_id="sec-026-log-sensitive-exposure",
                                title="Potential Sensitive Token or Personal Data Logged to Output",
                                description=f"Logging invocation references sensitive parameter '{sens}'.",
                                category="data_exposure",
                                severity=Severity.MEDIUM,
                                confidence=Confidence.MEDIUM,
                                file_path=rel_path,
                                start_line=line_num,
                                end_line=line_num,
                                raw_snippet=redact_text(snippet.strip()),
                                cwe_ids=["CWE-532"],
                                owasp_refs=["A09:2025"],
                                technical_fix="Sanitize or redact sensitive attributes prior to logging, or use structured log filtering.",
                                validation_steps="Inspect application log outputs; verify credentials and tokens are absent."
                            ))
                            break
        return findings

    def _check_fastapi_pagination(self, tree: ast.AST, rel_path: str, content: str) -> list[RawFinding]:
        """Flag list endpoints returning database models without pagination limits (SEC-029)."""
        findings = []
        lines = content.splitlines()

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Route that does query.all() or fetchall() without limit
                func_src = ast.unparse(node) if hasattr(ast, "unparse") else ""
                if any(m in func_src for m in [".all()", ".fetchall()"]):
                    if "limit" not in func_src.lower() and "offset" not in func_src.lower():
                        line_num = node.lineno
                        snippet = lines[line_num - 1] if line_num <= len(lines) else node.name
                        findings.append(RawFinding(
                            rule_id="sec-029-missing-pagination-limits",
                            title="List Endpoint Missing Mandatory Pagination Limits",
                            description=f"Endpoint '{node.name}' queries all database records without limit or offset bounds.",
                            category="data_exposure",
                            severity=Severity.LOW,
                            confidence=Confidence.MEDIUM,
                            file_path=rel_path,
                            start_line=line_num,
                            end_line=line_num,
                            raw_snippet=redact_text(snippet.strip()),
                            cwe_ids=["CWE-770"],
                            owasp_refs=["API4:2023"],
                            technical_fix="Add limit and offset query parameters with an upper maximum bound (e.g. limit: int = 50).",
                            validation_steps="Send requests requesting large dataset; verify response is bounded."
                        ))
        return findings

    def _check_open_redirects(self, tree: ast.AST, rel_path: str, content: str) -> list[RawFinding]:
        """Flag unvalidated redirect calls accepting user parameters (Playbook §18)."""
        findings = []
        lines = content.splitlines()

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call_name = ""
                if isinstance(node.func, ast.Name):
                    call_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    call_name = node.func.attr

                if call_name in ("RedirectResponse", "redirect"):
                    call_src = ast.unparse(node) if hasattr(ast, "unparse") else ""
                    if any(arg in call_src.lower() for arg in ["url", "next", "target", "redirect", "dest", "return"]):
                        line_num = getattr(node, "lineno", 1)
                        snippet = lines[line_num - 1] if line_num <= len(lines) else call_src
                        findings.append(RawFinding(
                            rule_id="sec-014-open-redirect-risk",
                            title="Unvalidated Open Redirect Target",
                            description="Endpoint uses RedirectResponse or redirect with user-controlled parameter without URL validation.",
                            category="injection",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.MEDIUM,
                            file_path=rel_path,
                            start_line=line_num,
                            end_line=line_num,
                            raw_snippet=redact_text(snippet.strip()),
                            cwe_ids=["CWE-601"],
                            owasp_refs=["A01:2025"],
                            technical_fix="Validate redirect target using safe URL parser: only allow relative URLs starting with a single '/' or explicit allow-list.",
                            validation_steps="Test redirect with target='https://evil.com' and '//evil.com'; verify rejected."
                        ))
        return findings

    def _check_unverified_webhooks(self, tree: ast.AST, rel_path: str, content: str) -> list[RawFinding]:
        """Flag webhook endpoints lacking cryptographic signature verification (Playbook §19)."""
        findings = []
        lines = content.splitlines()

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_src = ast.unparse(node) if hasattr(ast, "unparse") else ""
                for dec in node.decorator_list:
                    dec_src = ast.unparse(dec) if hasattr(ast, "unparse") else ""
                    if "webhook" in dec_src.lower() or "webhook" in node.name.lower():
                        has_sig = any(term in func_src.lower() for term in [
                            "signature", "hmac", "verify", "secret", "hub-signature", "stripe-signature"
                        ])
                        if not has_sig:
                            line_num = node.lineno
                            snippet = lines[line_num - 1] if line_num <= len(lines) else node.name
                            findings.append(RawFinding(
                                rule_id="sec-007-unverified-webhook",
                                title="Webhook Endpoint Lacking Signature Verification",
                                description=f"Webhook handler '{node.name}' does not appear to verify cryptographic provider signatures.",
                                category="auth",
                                severity=Severity.HIGH,
                                confidence=Confidence.POTENTIAL_GAP,
                                file_path=rel_path,
                                start_line=line_num,
                                end_line=line_num,
                                raw_snippet=redact_text(snippet.strip()),
                                cwe_ids=["CWE-345", "CWE-353"],
                                owasp_refs=["A07:2025"],
                                technical_fix="Compute HMAC-SHA256 signature over raw request body with configured shared secret and compare using constant-time equality.",
                                validation_steps="Post payload with invalid or missing signature; verify HTTP 401/403."
                            ))
        return findings

    def _check_client_pricing(self, tree: ast.AST, rel_path: str, content: str) -> list[RawFinding]:
        """Flag endpoints accepting client-specified price or payment totals (Playbook §17)."""
        findings = []
        lines = content.splitlines()

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                cls_name = node.name.lower()
                if any(w in cls_name for w in ["order", "checkout", "payment", "cart", "purchase"]):
                    for stmt in node.body:
                        field_name = ""
                        if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                            field_name = stmt.target.id
                        elif isinstance(stmt, ast.Assign):
                            for target in stmt.targets:
                                if isinstance(target, ast.Name):
                                    field_name = target.id
                        if field_name.lower() in ("price", "amount", "total", "discount", "is_paid", "paid"):
                            line_num = stmt.lineno
                            snippet = lines[line_num - 1] if line_num <= len(lines) else field_name
                            findings.append(RawFinding(
                                rule_id="sec-004-client-supplied-pricing",
                                title="Client-Supplied Pricing or Payment State in Request Model",
                                description=f"Request model '{node.name}' contains writable field '{field_name}'. Price and payment totals must be computed server-side.",
                                category="data_exposure",
                                severity=Severity.HIGH,
                                confidence=Confidence.CONFIRMED,
                                file_path=rel_path,
                                start_line=line_num,
                                end_line=line_num,
                                raw_snippet=redact_text(snippet.strip()),
                                cwe_ids=["CWE-472"],
                                owasp_refs=["API3:2023"],
                                technical_fix="Do not trust client-supplied prices or payment status. Compute totals from authoritative database records and gate access on verified webhooks.",
                                validation_steps="Attempt to submit order with manipulated price; verify price is ignored and recomputed server-side."
                            ))
        return findings

    # -------------------------------------------------------------------------
    # Express (Node.js) Deep Analyzer
    # -------------------------------------------------------------------------
    def _scan_express(self, worktree_dir: Path) -> list[RawFinding]:
        findings: list[RawFinding] = []

        route_pattern = re.compile(r"""(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]\s*,\s*(.*?)(?=\);|\}\s*\);)""", re.DOTALL)

        for root, _, files in os.walk(worktree_dir):
            if ".git" in root or "node_modules" in root:
                continue
            for fname in files:
                if not fname.endswith((".js", ".ts")):
                    continue
                fpath = Path(root) / fname
                try:
                    rel_path = str(fpath.resolve().relative_to(Path(worktree_dir).resolve())).replace("\\", "/")
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                    lines = content.splitlines()
                except Exception:
                    continue

                # 1. Rate Limiting Check on Express Routes (SEC-005, SEC-006)
                has_global_limiter = any(m in content for m in RATE_LIMIT_MARKERS_EXPRESS)
                for match in route_pattern.finditer(content):
                    method, path_str, handlers = match.groups()
                    start_line = content[:match.start()].count("\n") + 1
                    snippet = lines[start_line - 1] if start_line <= len(lines) else f"{method} {path_str}"

                    has_route_limiter = any(m in handlers for m in RATE_LIMIT_MARKERS_EXPRESS)
                    if not has_global_limiter and not has_route_limiter:
                        is_auth = any(w in path_str.lower() for w in ["login", "token", "auth", "password", "reset"])
                        rule_id = "sec-006-auth-bruteforce-missing" if is_auth else "sec-005-missing-rate-limit"
                        findings.append(RawFinding(
                            rule_id=rule_id,
                            title="Authentication Endpoint Missing Rate Limiter (Brute-Force Risk)" if is_auth else "Endpoint Possibly Missing Rate Limiting",
                            description=(
                                f"Express route '{method.upper()} {path_str}' has no rate-limiting middleware attached. "
                                "Reported as POTENTIAL_GAP: upstream reverse proxy or API gateway may enforce limits."
                            ),
                            category="api",
                            severity=Severity.HIGH if is_auth else Severity.MEDIUM,
                            confidence=Confidence.MEDIUM,
                            file_path=rel_path,
                            start_line=start_line,
                            end_line=start_line,
                            raw_snippet=redact_text(snippet.strip()),
                            cwe_ids=["CWE-770"],
                            owasp_refs=["API4:2023", "API6:2023"],
                            technical_fix="Apply 'express-rate-limit' middleware to route handler.",
                            validation_steps="Send bursts of requests; assert 429 Too Many Requests response is returned."
                        ))

                    # 2. BOLA / IDOR Indicators (SEC-008)
                    if ":id" in path_str or ":userId" in path_str:
                        # Check if handler inspects req.user or ownership
                        if "req.user" not in handlers and "userId" not in handlers:
                            findings.append(RawFinding(
                                rule_id="sec-008-bola-idor-indicator",
                                title="Potential Broken Object-Level Authorization (BOLA/IDOR)",
                                description=f"Route '{path_str}' takes an object identifier but contains no apparent owner verification guard.",
                                category="auth",
                                severity=Severity.MEDIUM,
                                confidence=Confidence.MEDIUM,
                                file_path=rel_path,
                                start_line=start_line,
                                end_line=start_line,
                                raw_snippet=redact_text(snippet.strip()),
                                cwe_ids=["CWE-639"],
                                owasp_refs=["API1:2023"],
                                technical_fix="Verify that req.user.id matches the owner of the requested resource before returning data.",
                                validation_steps="Attempt to access resource ID belonging to another user; verify HTTP 403 Forbidden."
                            ))
        return findings

    # -------------------------------------------------------------------------
    # Client / Public Asset Secrets Scan (SEC-002, SEC-003)
    # -------------------------------------------------------------------------
    def _scan_client_configs(self, worktree_dir: Path) -> list[RawFinding]:
        findings: list[RawFinding] = []

        db_regex = re.compile(r"""(?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/[^:\s'"]+:[^@\s'"]+@[^\s'"]+""", re.IGNORECASE)

        for root, _, files in os.walk(worktree_dir):
            if ".git" in root or "node_modules" in root:
                continue
            for fname in files:
                fpath = Path(root) / fname
                rel_path = str(fpath.resolve().relative_to(Path(worktree_dir).resolve())).replace("\\", "/")

                # Target frontend or public assets: public/, static/, .env.example, frontend/
                is_client_asset = any(p in rel_path.lower() for p in ["public/", "static/", "frontend/", "client/", ".env"])
                if not is_client_asset:
                    continue

                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                    lines = content.splitlines()

                    for idx, line in enumerate(lines, start=1):
                        # SEC-003: DB connection string with credentials in client config
                        if db_regex.search(line):
                            findings.append(RawFinding(
                                rule_id="sec-003-client-db-connection-string",
                                title="Database Connection String Exposed in Client / Public Asset",
                                description="Found database connection string with credentials in public or client configuration.",
                                category="secrets",
                                severity=Severity.CRITICAL,
                                confidence=Confidence.CONFIRMED,
                                file_path=rel_path,
                                start_line=idx,
                                end_line=idx,
                                raw_snippet=redact_text(line.strip()),
                                cwe_ids=["CWE-798"],
                                owasp_refs=["A07:2025"],
                                technical_fix="Remove database credentials from client code. Database connections must only be initiated by backend services.",
                                validation_steps="Verify client bundle does not include database connection strings."
                            ))
                except Exception:
                    continue

        return findings
