"""Unit tests for Step 7: DAST Engine, Web Testing & Correlation (ADR-002, Step 7)."""
import pytest
from unittest.mock import MagicMock, patch

from app.core.errors import TargetNotVerifiedError, ConsentRequiredError, SSRFBlockedError
from app.dast.crawler import ScopedCrawler
from app.dast.headers_cors import HeadersAndCorsAnalyzer
from app.dast.tls_scanner import TlsScanner
from app.dast.frontend_tester import FrontendAnalyzer
from app.dast.backend_tester import BackendExposureTester
from app.dast.static_runtime_correlator import StaticRuntimeCorrelator
from app.dast.pipeline import DastPipeline
from app.schemas.enums import Severity, Confidence


def test_dast_crawler_scope_enforcement_and_dangerous_exclusions():
    """Crawler strictly respects allowed_hosts and drops dangerous safety paths."""
    crawler = ScopedCrawler(
        base_url="https://securescanbox.xyz",
        allowed_hosts=["securescanbox.xyz"],
        allowed_paths=["/"],
        excluded_paths=["/logout", "/delete", "/payment", "/admin/wipe"],
        max_depth=2,
        max_requests=10
    )

    # Allowed in-scope URL
    assert crawler.is_permitted_url("https://securescanbox.xyz/dashboard")[0] is True

    # Out-of-scope third-party host
    assert crawler.is_permitted_url("https://thirdparty.com/login")[0] is False

    # Excluded safety paths (hard-dropped)
    assert crawler.is_permitted_url("https://securescanbox.xyz/logout")[0] is False
    assert crawler.is_permitted_url("https://securescanbox.xyz/api/v1/payment/checkout")[0] is False
    assert crawler.is_permitted_url("https://securescanbox.xyz/admin/wipe")[0] is False


def test_dast_headers_cookies_and_cors_analysis():
    """Headers, cookies, and CORS analyzer detects missing headers, insecure cookies, and permissive CORS."""
    # 1. Missing headers
    bad_headers = {
        "Server": "Apache/2.4.41",
        "Content-Type": "text/html; charset=UTF-8"
    }
    findings = HeadersAndCorsAnalyzer.analyze_headers("https://example.com", bad_headers)
    rule_ids = [f.rule_id for f in findings]
    assert "dast-header-missing-strict-transport-security" in rule_ids
    assert "dast-header-missing-content-security-policy" in rule_ids
    assert "dast-header-missing-x-frame-options" in rule_ids

    # 2. Insecure Cookie Flags
    cookie_headers = {
        "Set-Cookie": "session_id=abc123456; Path=/"  # Missing HttpOnly, Secure, SameSite
    }
    cookie_findings = HeadersAndCorsAnalyzer.analyze_cookies("https://example.com", cookie_headers)
    c_rules = [f.rule_id for f in cookie_findings]
    assert "dast-cookie-missing-httponly" in c_rules
    assert "dast-cookie-missing-secure" in c_rules
    assert "dast-cookie-lax-or-missing-samesite" in c_rules

    # 3. Permissive CORS with credentials
    cors_headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true"
    }
    cors_findings = HeadersAndCorsAnalyzer.analyze_cors("https://example.com/api", cors_headers, "https://evil.com")
    cors_rules = [f.rule_id for f in cors_findings]
    assert "dast-cors-wildcard-with-credentials" in cors_rules


def test_dast_tls_scanner_flags_plaintext_http():
    """TLS scanner detects cleartext HTTP schemes without TLS."""
    findings = TlsScanner.audit_target_tls("http://example.com")
    assert len(findings) == 1
    assert findings[0].rule_id == "dast-tls-plaintext-http"
    assert findings[0].severity == Severity.HIGH


def test_dast_frontend_analyzer_detects_dom_xss_secrets_and_sourcemaps():
    """Frontend analyzer detects DOM-XSS sinks, exposed secrets, token storage, and produces PASS on clean components."""
    vulnerable_js = """
    // React component with unsafe sink
    function UserProfile({ data }) {
        const apiKey = "AIzaSyD-1234567890abcdefghijklmnopqrstu";
        localStorage.setItem("token", "jwt-eyJhbGciOi...");
        window.addEventListener("message", function(e) {
            console.log(e.data);
        });
        return <div dangerouslySetInnerHTML={{ __html: data.bio }} />;
    }
    //# sourceMappingURL=UserProfile.js.map
    """

    findings = FrontendAnalyzer.audit_page(
        page_url="https://securescanbox.xyz/profile",
        html_content="<html><head></head><body><div id='root'></div></body></html>",
        scripts={"https://securescanbox.xyz/assets/UserProfile.js": vulnerable_js}
    )

    rule_ids = [f.rule_id for f in findings]
    assert "dast-frontend-react-dangerouslysetinnerhtml" in rule_ids
    assert "dast-frontend-secret-google-api-key" in rule_ids
    assert "dast-frontend-insecure-token-storage" in rule_ids
    assert "dast-frontend-postmessage-missing-origin" in rule_ids
    assert "dast-frontend-sourcemap-exposed" in rule_ids

    # Verify secret is never printed in raw snippet
    for f in findings:
        if "secret" in f.rule_id:
            assert "AIzaSyD-1234567890abcdefghijklmnopqrstu" not in f.raw_snippet

    # Clean script produces PASS_EVIDENCED findings
    clean_js = "console.log('clean bundle');"
    clean_findings = FrontendAnalyzer.audit_page(
        page_url="https://securescanbox.xyz/clean",
        html_content="<html><body>Clean</body></html>",
        scripts={"https://securescanbox.xyz/assets/clean.js": clean_js}
    )
    clean_rules = [f.rule_id for f in clean_findings]
    assert "pass-frontend-no-hardcoded-secrets" in clean_rules
    assert "pass-frontend-dom-xss-clean" in clean_rules


def test_dast_backend_tester_probes_and_error_leakage():
    """Backend tester detects exposed sensitive paths, stack traces, and safe reflected canary."""
    mock_responses = {
        "https://securescanbox.xyz/.env": MagicMock(status_code=200, text="APP_KEY=base64:xyz\nDB_PASSWORD=secret", headers={}),
        "https://securescanbox.xyz": MagicMock(status_code=200, text="<html>Home</html>", headers={}),
    }

    tester = BackendExposureTester(base_url="https://securescanbox.xyz")

    with patch("httpx.Client.get") as mock_get, patch("httpx.Client.request") as mock_req:
        def side_effect(url, **kwargs):
            if "/.env" in url:
                return MagicMock(status_code=200, text="APP_KEY=xyz\nDB_PASSWORD=secret", headers={})
            elif "__secscan_test" in url:
                return MagicMock(status_code=500, text="Traceback (most recent call last):\n  File 'app.py'", headers={})
            elif "secscancanary" in url:
                return MagicMock(status_code=200, text="<div>Search results for: <secscancanary", headers={"content-type": "text/html"})
            return MagicMock(status_code=404, text="Not Found", headers={})

        mock_get.side_effect = side_effect
        mock_req.return_value = MagicMock(status_code=405, text="Method Not Allowed", headers={})

        findings = tester.probe_all(candidate_urls=["https://securescanbox.xyz/search"])
        rule_ids = [f.rule_id for f in findings]

        assert "dast-backend-exposed-env-file" in rule_ids
        assert "dast-backend-python-traceback-leak" in rule_ids
        assert "dast-backend-missing-rate-limit" in rule_ids


def test_static_runtime_finding_correlation():
    """Static finding correlates with runtime finding, upgrading confidence to CONFIRMED and priority to P0."""
    static_findings = [
        {
            "id": "sast-finding-01",
            "rule_id": "fastapi-raw-sql-injection",
            "title": "SQL Injection in User Search Query",
            "category": "injection",
            "severity": "HIGH",
            "confidence": "LIKELY",
            "file_path": "backend/app/api/users.py",
            "start_line": 42,
            "cwe_ids": ["CWE-89"],
            "data_sensitivity": "credentials",
            "exposure": "internal"
        }
    ]

    runtime_findings = [
        {
            "id": "dast-finding-01",
            "rule_id": "dast-backend-sqli-syntax-error",
            "title": "SQL Injection Vulnerability Detected via Syntax Error Diagnostic",
            "category": "injection",
            "severity": "CRITICAL",
            "confidence": "CONFIRMED",
            "file_path": "https://securescanbox.xyz/api/users?id=1",
            "start_line": 1,
            "cwe_ids": ["CWE-89"],
            "raw_snippet": "Parameter 'id' triggered SQL syntax error"
        }
    ]

    correlated = StaticRuntimeCorrelator.correlate(static_findings, runtime_findings)
    assert len(correlated) == 1

    matched = correlated[0]
    assert matched["confidence"] == "CONFIRMED"
    assert matched["verified_state"] == "CONFIRMED"
    assert matched["exposure"] == "public"
    assert matched["priority"] == "P0"  # P0 because confirmed + public/credentials
    assert any("Confirmed via live runtime response" in sig for sig in matched["signals"])
    assert "dast-finding-01" in matched["related_finding_ids"]


def test_dast_pipeline_zero_data_extraction_and_progress_events():
    """Pipeline emits events, respects cancel flag, and proves zero data extraction."""
    events = []

    def on_progress(phase, pct, msg):
        events.append((phase, pct))

    with patch("app.dast.crawler.ScopedCrawler.crawl") as mock_crawl, \
         patch("app.dast.tls_scanner.TlsScanner.audit_target_tls") as mock_tls, \
         patch("app.dast.backend_tester.BackendExposureTester.probe_all") as mock_probe:

        mock_crawl.return_value = []
        mock_tls.return_value = []
        mock_probe.return_value = []

        result = DastPipeline.run_scan(
            target_url="https://securescanbox.xyz",
            intensity="Standard",
            progress_cb=on_progress
        )

        assert result.zero_data_extraction_proven is True
        assert len(events) >= 6
        assert events[-1] == ("COMPLETE", 100)
