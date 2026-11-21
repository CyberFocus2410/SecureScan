"""DAST Frontend & Client-Side SPA Security Analyzer (Step 7, ADR-002, ASVS 5.1 & 14.4)."""
import logging
import re
from typing import Dict, List, Optional
from urllib.parse import urlparse

from app.core.security import redact_text
from app.schemas.enums import Severity, Confidence
from app.scanners.base import RawFinding

logger = logging.getLogger(__name__)

# DOM-XSS Sinks
DOM_XSS_SINKS = [
    (re.compile(r"""dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*([^}]+)\}""", re.IGNORECASE),
     "React dangerouslySetInnerHTML sink used: dynamic HTML rendering without sanitization permits DOM-based Cross-Site Scripting (XSS).",
     "dast-frontend-react-dangerouslysetinnerhtml", Severity.HIGH, "CWE-79"),
    (re.compile(r"""\.(?:innerHTML|outerHTML)\s*=\s*(?:location\.(?:search|hash|pathname)|window\.name|document\.referrer|[^;]+)""", re.IGNORECASE),
     "Unsafe innerHTML/outerHTML DOM assignment: direct assignment of unescaped content to the DOM enables DOM-XSS.",
     "dast-frontend-dom-innerhtml-sink", Severity.HIGH, "CWE-79"),
    (re.compile(r"""document\.(?:write|writeln)\s*\(""", re.IGNORECASE),
     "Deprecated document.write() sink: dynamic document modification can be manipulated by malicious payloads.",
     "dast-frontend-document-write-sink", Severity.MEDIUM, "CWE-79"),
    (re.compile(r"""\b(?:eval|Function)\s*\([^)]*["']?\s*\+\s*""", re.IGNORECASE),
     "Dynamic JavaScript code execution via eval/Function: dynamic evaluation of concatenated expressions allows arbitrary script execution.",
     "dast-frontend-eval-dynamic-execution", Severity.HIGH, "CWE-95")
]

# Sensitive Client Storage
CLIENT_STORAGE_PATTERNS = [
    (re.compile(r"""(?:localStorage|sessionStorage)\.setItem\s*\(\s*['"](?:jwt|token|access_token|auth_token|id_token|session)['"]""", re.IGNORECASE),
     "Authentication token stored in Web Storage (localStorage/sessionStorage): accessible to any script executing in origin, creating severe exposure to XSS credential theft.",
     "dast-frontend-insecure-token-storage", Severity.MEDIUM, "CWE-922")
]

# PostMessage without origin check
POSTMESSAGE_LISTEN_REGEX = re.compile(r"""(?:window\.)?addEventListener\s*\(\s*['"]message['"]""", re.IGNORECASE)
POSTMESSAGE_ORIGIN_REGEX = re.compile(r"""\b(?:event|e)\.origin\b""", re.IGNORECASE)

# Source map reference
SOURCE_MAP_REGEX = re.compile(r"""(?:sourceMappingURL\s*=\s*([^\s]+\.map))""", re.IGNORECASE)

# Secrets in JS bundles
FRONTEND_SECRET_PATTERNS = [
    (re.compile(r"""AIza[0-9A-Za-z\-_]{35}"""), "Google API Key exposed in client bundle", "dast-frontend-secret-google-api-key", Severity.HIGH),
    (re.compile(r"""AKIA[0-9A-Z]{16}"""), "AWS Access Key ID exposed in client bundle", "dast-frontend-secret-aws-key", Severity.CRITICAL),
    (re.compile(r"""gh[pousr]_[A-Za-z0-9_]{36,}"""), "GitHub Personal Access Token exposed in client bundle", "dast-frontend-secret-github-token", Severity.CRITICAL),
    (re.compile(r"""xox[baprs]-[0-9A-Za-z-]{10,}"""), "Slack Bot/User Token exposed in client bundle", "dast-frontend-secret-slack-token", Severity.HIGH),
    (re.compile(r"""-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"""), "Private cryptographic key exposed in client bundle", "dast-frontend-secret-private-key", Severity.CRITICAL)
]

# Client-side Open Redirect
OPEN_REDIRECT_CLIENT_REGEX = re.compile(
    r"""(?:window\.)?location(?:\.href)?\s*=\s*(?:new\s+URLSearchParams\s*\([^)]*\)\.get\s*\(\s*['"](?:redirect|returnUrl|next|url|goto|target)['"]\)|[a-zA-Z0-9_]+\.get\s*\(\s*['"](?:redirect|returnUrl|next|url|goto|target)['"]\))""",
    re.IGNORECASE
)


class FrontendAnalyzer:
    """Audits client-side JavaScript, React SPA bundles, and HTML documents for security defects."""

    @classmethod
    def audit_page(
        cls,
        page_url: str,
        html_content: str,
        scripts: Optional[Dict[str, str]] = None
    ) -> List[RawFinding]:
        findings: List[RawFinding] = []
        scripts = scripts or {}

        # 1. Inspect HTML for inline scripts and direct sinks
        all_targets: List[Tuple[str, str]] = [(page_url, html_content)]
        for s_url, s_content in scripts.items():
            all_targets.append((s_url, s_content))

        has_secrets = False
        has_dom_xss = False
        has_token_storage = False

        for target_ref, content in all_targets:
            if not content:
                continue

            # Check DOM-XSS Sinks
            for pattern, desc, rule_id, sev, cwe in DOM_XSS_SINKS:
                match = pattern.search(content)
                if match:
                    has_dom_xss = True
                    snippet = redact_text(match.group(0))[:160]
                    findings.append(RawFinding(
                        rule_id=rule_id,
                        title="Client-Side DOM-XSS Vulnerability Detected",
                        description=desc,
                        category="xss",
                        severity=sev,
                        confidence=Confidence.CONFIRMED,
                        file_path=target_ref,
                        start_line=1,
                        end_line=1,
                        raw_snippet=snippet,
                        cwe_ids=[cwe],
                        owasp_refs=["A03:2021-Injection"],
                        technical_fix="Sanitize untrusted inputs with DOMPurify before inserting into the DOM, or use safe text-rendering APIs (e.g. textContent, React standard JSX expressions).",
                        validation_steps="Verify with browser DevTools that inputs cannot alter document structure or trigger script execution."
                    ))

            # Check Client-Side Open Redirect
            match_redir = OPEN_REDIRECT_CLIENT_REGEX.search(content)
            if match_redir:
                snippet = redact_text(match_redir.group(0))[:160]
                findings.append(RawFinding(
                    rule_id="dast-frontend-client-open-redirect",
                    title="Client-Side Open Redirect via URL Parameter",
                    description="Client-side script reads an untrusted URL parameter from window.location and redirects the browser without origin validation.",
                    category="misconfig",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    file_path=target_ref,
                    start_line=1,
                    end_line=1,
                    raw_snippet=snippet,
                    cwe_ids=["CWE-601"],
                    owasp_refs=["A01:2021-Broken Access Control"],
                    technical_fix="Validate redirect target against a strict allowlist of application domains or use relative paths only.",
                    validation_steps="Supply external URL (?redirect=https://evil.com) and confirm redirect is blocked."
                ))

            # Check Insecure Token Storage in Web Storage
            for pattern, desc, rule_id, sev, cwe in CLIENT_STORAGE_PATTERNS:
                match = pattern.search(content)
                if match:
                    has_token_storage = True
                    snippet = redact_text(match.group(0))[:160]
                    findings.append(RawFinding(
                        rule_id=rule_id,
                        title="Sensitive Authentication Token Stored in Web Storage",
                        description=desc,
                        category="auth",
                        severity=sev,
                        confidence=Confidence.HIGH,
                        file_path=target_ref,
                        start_line=1,
                        end_line=1,
                        raw_snippet=snippet,
                        cwe_ids=[cwe],
                        owasp_refs=["A07:2021-Identification and Authentication Failures"],
                        technical_fix="Store session credentials in HttpOnly, Secure, SameSite=Strict/Lax cookies rather than accessible localStorage.",
                        validation_steps="Inspect browser Application Storage tab and verify tokens are not accessible to JavaScript document.cookie or localStorage."
                    ))

            # Check PostMessage listener without origin verification
            if POSTMESSAGE_LISTEN_REGEX.search(content):
                if not POSTMESSAGE_ORIGIN_REGEX.search(content):
                    findings.append(RawFinding(
                        rule_id="dast-frontend-postmessage-missing-origin",
                        title="Unsafe postMessage Handler Missing Origin Validation",
                        description="Application registers a window 'message' listener without validating event.origin, permitting any third-party iframe or window to send arbitrary messages.",
                        category="misconfig",
                        severity=Severity.HIGH,
                        confidence=Confidence.CONFIRMED,
                        file_path=target_ref,
                        start_line=1,
                        end_line=1,
                        raw_snippet="addEventListener('message', ...) without event.origin check",
                        cwe_ids=["CWE-345"],
                        owasp_refs=["A01:2021-Broken Access Control"],
                        technical_fix="Strictly check 'if (event.origin !== trustedOrigin) return;' at the very beginning of the message handler.",
                        validation_steps="Send postMessage from an untrusted origin and confirm it is rejected."
                    ))

            # Check Secrets in JS
            for pattern, desc, rule_id, sev in FRONTEND_SECRET_PATTERNS:
                match = pattern.search(content)
                if match:
                    has_secrets = True
                    findings.append(RawFinding(
                        rule_id=rule_id,
                        title=f"Hard-Coded Secret in Client Bundle: {desc}",
                        description="Sensitive credential or private API key is bundled into public frontend code, allowing anyone with access to the website to compromise cloud infrastructure.",
                        category="secret",
                        severity=sev,
                        confidence=Confidence.CONFIRMED,
                        file_path=target_ref,
                        start_line=1,
                        end_line=1,
                        raw_snippet="[REDACTED_FRONTEND_SECRET]",
                        cwe_ids=["CWE-798"],
                        owasp_refs=["A07:2021-Identification and Authentication Failures"],
                        technical_fix="Move sensitive API calls to the backend server. Never compile private secrets into client bundles.",
                        validation_steps="Ensure secret is revoked and replaced with server-side proxy endpoint."
                    ))

            # Check Source Map Exposure
            sm_match = SOURCE_MAP_REGEX.search(content)
            if sm_match:
                findings.append(RawFinding(
                    rule_id="dast-frontend-sourcemap-exposed",
                    title="Frontend Production JavaScript Source Map Exposed",
                    description=f"Source map reference discovered ({sm_match.group(1)}). Exposing source maps in production reveals original TypeScript/React source code, comments, and internal API designs.",
                    category="misconfig",
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    file_path=target_ref,
                    start_line=1,
                    end_line=1,
                    raw_snippet=f"sourceMappingURL={sm_match.group(1)}",
                    cwe_ids=["CWE-540"],
                    owasp_refs=["A05:2021-Security Misconfiguration"],
                    technical_fix="Configure build tool (e.g. vite.config.ts, webpack.config.js) to omit source maps in production ('sourcemap: false').",
                    validation_steps="Verify .map files return 404 in production environments."
                ))

        # Evidenced passes
        if not has_secrets:
            findings.append(RawFinding(
                rule_id="pass-frontend-no-hardcoded-secrets",
                title="PASS: No Hard-Coded API Keys or Secrets in Client JavaScript Bundles",
                description="Frontend scripts and assets were inspected and no raw cloud provider secrets, private keys, or tokens were detected.",
                category="audit",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                file_path=page_url,
                start_line=1,
                end_line=1,
                raw_snippet="All frontend bundles clean of sensitive credentials",
                cwe_ids=[],
                owasp_refs=[],
                technical_fix="",
                validation_steps=""
            ))

        if not has_dom_xss:
            findings.append(RawFinding(
                rule_id="pass-frontend-dom-xss-clean",
                title="PASS: No Unsafe DOM-XSS Sinks Detected in Frontend Scripts",
                description="No dangerous uses of dangerouslySetInnerHTML, document.write, or unescaped innerHTML were detected in client code.",
                category="audit",
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                file_path=page_url,
                start_line=1,
                end_line=1,
                raw_snippet="No unescaped DOM insertion sinks",
                cwe_ids=[],
                owasp_refs=[],
                technical_fix="",
                validation_steps=""
            ))

        return findings
