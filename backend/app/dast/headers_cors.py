"""DAST Security Headers, Cookie Flags, and CORS Analyzer (Step 7, ADR-002, ASVS 14.4)."""
import logging
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from app.core.security import redact_text
from app.schemas.enums import Severity, Confidence
from app.scanners.base import RawFinding

logger = logging.getLogger(__name__)

RECOMMENDED_SECURITY_HEADERS = [
    ("Strict-Transport-Security", "HSTS missing: communication can be downgraded to plaintext HTTP via SSL-stripping.", Severity.HIGH, "CWE-319", "A02:2021-Cryptographic Failures"),
    ("Content-Security-Policy", "CSP missing: application lacks defense-in-depth against Cross-Site Scripting (XSS) and data exfiltration.", Severity.MEDIUM, "CWE-1021", "A03:2021-Injection"),
    ("X-Content-Type-Options", "X-Content-Type-Options missing: browsers may MIME-sniff response content away from declared Content-Type.", Severity.LOW, "CWE-79", "A05:2021-Security Misconfiguration"),
    ("X-Frame-Options", "X-Frame-Options missing: page may be framed by third-party origins, exposing users to clickjacking.", Severity.MEDIUM, "CWE-1021", "A05:2021-Security Misconfiguration"),
    ("Referrer-Policy", "Referrer-Policy missing: full URL path or query parameters may leak to external domains upon navigation.", Severity.LOW, "CWE-200", "A05:2021-Security Misconfiguration"),
    ("Permissions-Policy", "Permissions-Policy missing: browser features (camera, microphone, geolocation) not explicitly restricted.", Severity.LOW, "CWE-250", "A05:2021-Security Misconfiguration")
]


class HeadersAndCorsAnalyzer:
    """Evaluates security headers, cookie flags, and CORS configurations for live web targets."""

    @staticmethod
    def analyze_headers(target_url: str, response_headers: Dict[str, str]) -> List[RawFinding]:
        findings: List[RawFinding] = []
        normalized = {k.lower(): v for k, v in response_headers.items()}
        parsed = urlparse(target_url)
        path = parsed.path or "/"

        # 1. Missing Security Headers
        for header_name, desc, sev, cwe, owasp in RECOMMENDED_SECURITY_HEADERS:
            h_lower = header_name.lower()
            if h_lower not in normalized:
                # If target is HTTP (not HTTPS), HSTS is expected to be omitted, but flag if HTTPS
                if header_name == "Strict-Transport-Security" and parsed.scheme.lower() != "https":
                    continue

                findings.append(RawFinding(
                    rule_id=f"dast-header-missing-{h_lower}",
                    title=f"Missing Security Header: {header_name}",
                    description=desc,
                    category="misconfig",
                    severity=sev,
                    confidence=Confidence.CONFIRMED,
                    file_path=f"{target_url}",
                    start_line=1,
                    end_line=1,
                    raw_snippet=f"Missing header: {header_name}",
                    cwe_ids=[cwe],
                    owasp_refs=[owasp],
                    technical_fix=f"Configure server or reverse proxy to include '{header_name}' in all HTTP responses.",
                    validation_steps=f"Inspect response headers using 'curl -I {target_url}' and verify presence of {header_name}."
                ))

        # 2. Permissive or Broken CSP
        if "content-security-policy" in normalized:
            csp = normalized["content-security-policy"].lower()
            if "'unsafe-inline'" in csp and "nonce-" not in csp and "sha256-" not in csp:
                findings.append(RawFinding(
                    rule_id="dast-csp-unsafe-inline",
                    title="Content Security Policy Permits 'unsafe-inline' Scripts",
                    description="CSP header contains 'unsafe-inline' without nonces or cryptographic hashes, neutralizing XSS protection.",
                    category="misconfig",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    file_path=f"{target_url}",
                    start_line=1,
                    end_line=1,
                    raw_snippet=redact_text(normalized["content-security-policy"]),
                    cwe_ids=["CWE-1021", "CWE-79"],
                    owasp_refs=["A05:2021-Security Misconfiguration"],
                    technical_fix="Remove 'unsafe-inline' and implement cryptographically random nonces (nonce-...) or strict-dynamic.",
                    validation_steps="Verify CSP header forbids inline execution without matching script nonce."
                ))

        # 3. Server Version Banner Leakage
        for server_header in ["server", "x-powered-by", "x-aspnet-version"]:
            if server_header in normalized:
                val = normalized[server_header]
                if any(char.isdigit() for char in val):
                    findings.append(RawFinding(
                        rule_id=f"dast-server-version-leak-{server_header}",
                        title=f"Server Fingerprint and Version Information Leakage ({server_header})",
                        description=f"Response header '{server_header}: {val}' reveals exact underlying framework or software version numbers to attackers.",
                        category="misconfig",
                        severity=Severity.LOW,
                        confidence=Confidence.CONFIRMED,
                        file_path=f"{target_url}",
                        start_line=1,
                        end_line=1,
                        raw_snippet=redact_text(f"{server_header}: {val}"),
                        cwe_ids=["CWE-200"],
                        owasp_refs=["A05:2021-Security Misconfiguration"],
                        technical_fix=f"Suppress or mask the '{server_header}' header in reverse proxy or web server configuration.",
                        validation_steps=f"Verify '{server_header}' is stripped in response headers."
                    ))

        return findings

    @staticmethod
    def analyze_cookies(target_url: str, cookie_headers: Any) -> List[RawFinding]:
        """Inspects Set-Cookie headers for Secure, HttpOnly, and SameSite flags."""
        findings: List[RawFinding] = []
        is_https = urlparse(target_url).scheme.lower() == "https"

        raw_list: List[str] = []
        if isinstance(cookie_headers, dict):
            for k, v in cookie_headers.items():
                if k.lower() == "set-cookie":
                    if isinstance(v, list):
                        raw_list.extend(v)
                    else:
                        raw_list.append(str(v))
        elif isinstance(cookie_headers, list):
            raw_list = cookie_headers
        elif isinstance(cookie_headers, str):
            raw_list = [cookie_headers]

        for cookie_str in raw_list:
            parts = [p.strip() for p in cookie_str.split(";")]
            if not parts:
                continue

            cookie_name = parts[0].split("=")[0] if "=" in parts[0] else parts[0]
            cookie_lower = cookie_str.lower()

            # 1. Missing Secure Flag (on HTTPS)
            if is_https and "secure" not in [p.lower() for p in parts]:
                findings.append(RawFinding(
                    rule_id="dast-cookie-missing-secure",
                    title=f"Cookie Lacks 'Secure' Flag ({cookie_name})",
                    description=f"Cookie '{cookie_name}' is transmitted over HTTPS without the 'Secure' attribute, risking transmission over cleartext HTTP upon MITM redirection.",
                    category="auth",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    file_path=target_url,
                    start_line=1,
                    end_line=1,
                    raw_snippet=f"Set-Cookie: {cookie_name}=***; (missing Secure)",
                    cwe_ids=["CWE-614"],
                    owasp_refs=["A05:2021-Security Misconfiguration"],
                    technical_fix="Append '; Secure' to all Set-Cookie directives.",
                    validation_steps="Verify cookie response header includes 'Secure' attribute."
                ))

            # 2. Missing HttpOnly Flag (for session or auth tokens)
            is_session_cookie = any(kw in cookie_name.lower() for kw in ["session", "auth", "token", "jwt", "id", "sid"])
            if is_session_cookie and "httponly" not in [p.lower() for p in parts]:
                findings.append(RawFinding(
                    rule_id="dast-cookie-missing-httponly",
                    title=f"Authentication Cookie Lacks 'HttpOnly' Flag ({cookie_name})",
                    description=f"Cookie '{cookie_name}' contains session or authorization credentials but lacks the 'HttpOnly' attribute, making it readable by JavaScript document.cookie.",
                    category="auth",
                    severity=Severity.HIGH,
                    confidence=Confidence.CONFIRMED,
                    file_path=target_url,
                    start_line=1,
                    end_line=1,
                    raw_snippet=f"Set-Cookie: {cookie_name}=***; (missing HttpOnly)",
                    cwe_ids=["CWE-1004"],
                    owasp_refs=["A07:2021-Identification and Authentication Failures"],
                    technical_fix="Configure session manager to set 'HttpOnly: true'.",
                    validation_steps="Verify document.cookie in browser console cannot access the session cookie."
                ))

            # 3. Missing or Permissive SameSite
            has_samesite = any("samesite" in p.lower() for p in parts)
            if not has_samesite or "samesite=none" in cookie_lower:
                findings.append(RawFinding(
                    rule_id="dast-cookie-lax-or-missing-samesite",
                    title=f"Cookie Missing or Overly Permissive SameSite Attribute ({cookie_name})",
                    description=f"Cookie '{cookie_name}' lacks 'SameSite=Lax' or 'SameSite=Strict', exposing the endpoint to Cross-Site Request Forgery (CSRF).",
                    category="auth",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    file_path=target_url,
                    start_line=1,
                    end_line=1,
                    raw_snippet=f"Set-Cookie: {cookie_name}=***; (SameSite missing or None)",
                    cwe_ids=["CWE-1275"],
                    owasp_refs=["A01:2021-Broken Access Control"],
                    technical_fix="Set 'SameSite=Lax' (default) or 'SameSite=Strict' for all sensitive cookies.",
                    validation_steps="Inspect Set-Cookie header for SameSite=Lax or SameSite=Strict."
                ))

        return findings

    @staticmethod
    def analyze_cors(target_url: str, response_headers: Any = None, request_origin: Any = "https://evil-untrusted-origin.com") -> List[RawFinding]:
        """Analyzes Access-Control response headers against supplied test Origin."""
        findings: List[RawFinding] = []
        if isinstance(response_headers, str) and isinstance(request_origin, dict):
            actual_origin = response_headers
            actual_headers = request_origin
        else:
            actual_headers = response_headers or {}
            actual_origin = request_origin or "https://evil-untrusted-origin.com"

        normalized = {k.lower(): v for k, v in actual_headers.items()}

        acao = normalized.get("access-control-allow-origin", "").strip()
        acac = normalized.get("access-control-allow-credentials", "").strip().lower()

        # 1. Wildcard Origin with Credentials Allowed
        if acao == "*" and acac == "true":
            findings.append(RawFinding(
                rule_id="dast-cors-wildcard-with-credentials",
                title="CORS Wildcard Allowed-Origin Combined with Credentials",
                description="Server responds with Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true. Browsers reject this combination, but it reveals dangerous CORS intent.",
                category="misconfig",
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                file_path=target_url,
                start_line=1,
                end_line=1,
                raw_snippet="Access-Control-Allow-Origin: * | Access-Control-Allow-Credentials: true",
                cwe_ids=["CWE-942"],
                owasp_refs=["A05:2021-Security Misconfiguration"],
                technical_fix="Specify an explicit allowlist of trusted origins; never combine wildcard origins with credentials.",
                validation_steps="Send Origin: https://untrusted-attacker.com and verify Access-Control-Allow-Origin is not returned."
            ))

        # 2. Reflective Origin (Reflecting untrusted Origin header verbatim)
        if actual_origin and acao == actual_origin and acac == "true":
            findings.append(RawFinding(
                rule_id="dast-cors-arbitrary-origin-reflection",
                title="Arbitrary Origin Reflected in CORS Response with Credentials Allowed",
                description=(
                    f"Server dynamically reflected attacker origin '{actual_origin}' into Access-Control-Allow-Origin with "
                    "Access-Control-Allow-Credentials: true, allowing any third-party website to make authenticated cross-origin requests."
                ),
                category="auth",
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                file_path=target_url,
                start_line=1,
                end_line=1,
                raw_snippet=f"Origin: {request_origin} -> Access-Control-Allow-Origin: {acao}",
                cwe_ids=["CWE-942"],
                owasp_refs=["A01:2021-Broken Access Control"],
                technical_fix="Validate requested Origin against a strict whitelist before echoing it in Access-Control-Allow-Origin.",
                validation_steps=f"Curl target with 'Origin: https://evil.example.com' and assert no ACAO header is returned."
            ))

        return findings
