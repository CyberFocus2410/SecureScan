"""
Comprehensive security regression test suite enforcing the 20-class Web App Security Hardening Playbook.
Covers: IDOR/BOLA, Mass Assignment, Input Validation, Rate Limiting, Webhook Signatures, SSRF, Open Redirects,
Path Traversal, Security Headers, and Exception Masking.
"""
import time
import uuid
import hmac
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.core.config import settings
from app.core.db import SessionLocal
from app.core.safe_fetch import is_safe_url, is_private_ip
from app.core.security import is_safe_redirect_url, verify_webhook_signature
from app.core.rate_limit import limiter
from app.models.models import AuditModel, RepositoryModel, ReportArtifactModel
from app.services.reports import get_report_artifact
from app.core.errors import UnauthorizedSessionError, SecureScanException


@pytest.fixture
def client():
    # Reset limiter before each test
    limiter.reset()
    return TestClient(app)


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


# ==============================================================================
# 1. IDOR / BOLA Object-Level Authorization Tests (Playbook §10)
# ==============================================================================
def test_idor_cross_session_audit_access_is_blocked(client, db: Session):
    """Verify session B cannot read session A's audit (HTTP 403 Forbidden)."""
    session_a = str(uuid.uuid4())
    session_b = str(uuid.uuid4())

    repo_id = str(uuid.uuid4())
    rand_suffix = uuid.uuid4().hex[:8]
    repo = RepositoryModel(
        id=repo_id,
        github_owner="securescan-org",
        github_repo=f"idor-test-{rand_suffix}",
        canonical_url=f"https://github.com/securescan-org/idor-test-{rand_suffix}",
        default_branch="main"
    )
    db.add(repo)

    audit_id = str(uuid.uuid4())
    audit = AuditModel(
        id=audit_id,
        repository_id=repo_id,
        session_id=session_a,
        scopes=["SECURITY"],
        status="COMPLETED"
    )
    db.add(audit)
    db.commit()

    # Session A reads its own audit -> 200 OK
    res_a = client.get(f"/api/v1/audits/{audit_id}", headers={"X-Session-ID": session_a})
    assert res_a.status_code == 200

    # Session B attempts to read Session A's audit -> 403 Forbidden
    res_b = client.get(f"/api/v1/audits/{audit_id}", headers={"X-Session-ID": session_b})
    assert res_b.status_code == 403
    assert res_b.json()["error"]["code"] == "ERR_UNAUTHORIZED_SESSION"


def test_idor_cross_session_report_download_is_blocked(client, db: Session, tmp_path: Path):
    """Verify session B cannot download session A's generated report artifact."""
    session_a = str(uuid.uuid4())
    session_b = str(uuid.uuid4())

    audit_id = str(uuid.uuid4())
    audit = AuditModel(
        id=audit_id,
        repository_id=str(uuid.uuid4()),
        session_id=session_a,
        scopes=["SECURITY"],
        status="COMPLETED"
    )
    db.add(audit)

    # Create dummy artifact file within storage dir
    storage_dir = Path(settings.REPORTS_STORAGE_DIR) / audit_id
    storage_dir.mkdir(parents=True, exist_ok=True)
    report_file = storage_dir / "test_report.pdf"
    report_file.write_bytes(b"%PDF-1.4 mock content")

    report_id = str(uuid.uuid4())
    report = ReportArtifactModel(
        id=report_id,
        audit_id=audit_id,
        format="pdf",
        status="COMPLETED",
        safe_storage_key=str(report_file),
        expires_at=datetime.utcnow() + timedelta(hours=24)
    )
    db.add(report)
    db.commit()

    # Session B attempts download -> 403 Forbidden
    res_b = client.get(f"/api/v1/reports/{report_id}/download", headers={"X-Session-ID": session_b})
    assert res_b.status_code == 403
    assert res_b.json()["error"]["code"] == "ERR_UNAUTHORIZED_SESSION"


# ==============================================================================
# 2. Mass Assignment Rejection Tests (Playbook §11)
# ==============================================================================
def test_mass_assignment_extra_fields_rejected_on_audit_create(client):
    """Verify injecting extra untyped fields (e.g. role, isAdmin, status) into AuditCreate is rejected."""
    payload = {
        "repository_id": str(uuid.uuid4()),
        "scopes": ["SECURITY"],
        "commit_sha": None,
        "role": "admin",
        "isAdmin": True,
        "status": "COMPLETED",
        "pwned": True
    }
    res = client.post("/api/v1/audits", json=payload, headers={"X-Session-ID": str(uuid.uuid4())})
    # Pydantic extra='forbid' raises 422 Unprocessable Entity
    assert res.status_code == 422
    err_body = res.json()["error"]
    assert err_body["code"] == "ERR_VALIDATION_ERROR"
    # Verify the error detail flags extra forbidden fields
    detail_str = str(err_body["details"]).lower()
    assert "extra" in detail_str or "extra_forbidden" in detail_str


def test_mass_assignment_extra_fields_rejected_on_repo_create(client):
    """Verify injecting extra fields into RepositoryCreate is rejected."""
    payload = {
        "github_url": "https://github.com/torvalds/linux",
        "branch": "main",
        "detected_languages": ["Malicious"],
        "is_verified": True
    }
    res = client.post("/api/v1/repositories", json=payload)
    assert res.status_code == 422
    assert res.json()["error"]["code"] == "ERR_VALIDATION_ERROR"


# ==============================================================================
# 3. Missing Input Validation Rejection Tests (Playbook §8)
# ==============================================================================
def test_input_validation_malformed_urls_rejected(client):
    """Verify non-HTTP, non-GitHub, and script injection URLs are rejected."""
    # Javascript scheme
    res1 = client.post("/api/v1/repositories", json={"github_url": "javascript:alert(1)"})
    assert res1.status_code == 422

    # HTTP non-https
    res2 = client.post("/api/v1/repositories", json={"github_url": "http://github.com/owner/repo"})
    assert res2.status_code in (400, 422)

    # Missing repo path
    res3 = client.post("/api/v1/repositories", json={"github_url": "https://github.com/"})
    assert res3.status_code in (400, 422)


# ==============================================================================
# 4. Rate Limiting Tests (Playbook §16)
# ==============================================================================
def test_rate_limiting_enforcement_returns_429(client):
    """Verify bursts exceeding rate limit return 429 with Retry-After header."""
    # Temporarily set small threshold for unit test
    original_max = limiter.max_requests
    limiter.max_requests = 5
    try:
        session_id = str(uuid.uuid4())
        # Execute 5 allowed calls
        for _ in range(5):
            res = client.get("/api/v1/repositories/non-existent-id", headers={"X-Session-ID": session_id})
            assert res.status_code != 429

        # 6th request triggers rate limiter
        res_limited = client.get("/api/v1/repositories/non-existent-id", headers={"X-Session-ID": session_id})
        assert res_limited.status_code == 429
        assert "Retry-After" in res_limited.headers
        assert res_limited.json()["error"]["code"] == "ERR_QUOTA_EXCEEDED"
    finally:
        limiter.max_requests = original_max
        limiter.reset()


# ==============================================================================
# 5. Webhook Signature Verification Tests (Playbook §19)
# ==============================================================================
def test_webhook_signature_verification_success_and_rejection():
    """Verify constant-time HMAC-SHA256 signature validation and replay protection."""
    secret = "test-webhook-secret-key-32bytes!!"
    raw_payload = b'{"action":"push","repository":"SecureScan"}'
    current_time = int(time.time())

    # 1. Valid signature with timestamp format
    valid_hmac = hmac.new(secret.encode("utf-8"), f"{current_time}.".encode("utf-8") + raw_payload, hashlib.sha256).hexdigest()
    sig_header = f"t={current_time},v1={valid_hmac}"
    is_valid, reason = verify_webhook_signature(raw_payload, sig_header, secret, tolerance_seconds=300)
    assert is_valid is True
    assert reason == "Signature verified."

    # 2. Tampered payload rejection
    tampered_payload = b'{"action":"push","repository":"SecureScan","hacked":true}'
    is_valid_tampered, reason_tampered = verify_webhook_signature(tampered_payload, sig_header, secret, tolerance_seconds=300)
    assert is_valid_tampered is False
    assert "mismatch" in reason_tampered.lower()

    # 3. Wrong secret rejection
    is_valid_wrong_key, reason_key = verify_webhook_signature(raw_payload, sig_header, "wrong-secret-key", tolerance_seconds=300)
    assert is_valid_wrong_key is False
    assert "mismatch" in reason_key.lower()

    # 4. Replay attack rejection (expired timestamp: 10 minutes ago)
    old_time = current_time - 600
    old_hmac = hmac.new(secret.encode("utf-8"), f"{old_time}.".encode("utf-8") + raw_payload, hashlib.sha256).hexdigest()
    old_sig_header = f"t={old_time},v1={old_hmac}"
    is_valid_expired, reason_expired = verify_webhook_signature(raw_payload, old_sig_header, secret, tolerance_seconds=300)
    assert is_valid_expired is False
    assert "expired" in reason_expired.lower()

    # 5. Missing / empty signature rejection
    is_valid_empty, _ = verify_webhook_signature(raw_payload, "", secret)
    assert is_valid_empty is False


# ==============================================================================
# 6. SSRF Blocking Tests (Playbook §7)
# ==============================================================================
def test_ssrf_blocking_cloud_metadata_and_private_ips():
    """Verify SSRF helper blocks loopback, private RFC1918 ranges, and AWS/GCP metadata IPs."""
    # AWS / GCP metadata
    assert is_private_ip("169.254.169.254") is True
    safe, reason = is_safe_url("http://169.254.169.254/latest/meta-data/", allowed_schemes=("http", "https"))
    assert safe is False
    assert "blocked" in reason.lower() or "private" in reason.lower()

    # IPv4 loopback
    assert is_private_ip("127.0.0.1") is True
    safe_lb, _ = is_safe_url("https://127.0.0.1:8000/api", allowed_schemes=("https",))
    assert safe_lb is False

    # IPv6 loopback
    assert is_private_ip("::1") is True
    safe_v6, _ = is_safe_url("https://[::1]/", allowed_schemes=("https",))
    assert safe_v6 is False

    # RFC 1918 Private Ranges
    assert is_private_ip("10.0.0.1") is True
    assert is_private_ip("172.16.0.1") is True
    assert is_private_ip("192.168.1.1") is True
    safe_priv, _ = is_safe_url("https://192.168.1.1/admin")
    assert safe_priv is False

    # Credentials in URL
    safe_cred, _ = is_safe_url("https://admin:secret@github.com/repo")
    assert safe_cred is False

    # Allowed host restriction
    safe_non_gh, _ = is_safe_url("https://attacker.com/repo", allowed_hosts=("github.com",))
    assert safe_non_gh is False


# ==============================================================================
# 7. Open Redirect Defense Tests (Playbook §18)
# ==============================================================================
def test_open_redirect_defense():
    """Verify is_safe_redirect_url permits safe relative paths and rejects URL traps."""
    # Safe relative paths
    assert is_safe_redirect_url("/dashboard") is True
    assert is_safe_redirect_url("/api/v1/audits/12345") is True

    # Protocol-relative attacks
    assert is_safe_redirect_url("//evil.com") is False
    assert is_safe_redirect_url("//google.com/test") is False

    # Backslash / Windows separator attacks
    assert is_safe_redirect_url("/\\evil.com") is False
    assert is_safe_redirect_url("\\\\evil.com") is False

    # Javascript & data pseudo-schemes
    assert is_safe_redirect_url("javascript:alert(document.cookie)") is False
    assert is_safe_redirect_url("data:text/html,<script>alert(1)</script>") is False

    # External schemes without host allow-list
    assert is_safe_redirect_url("https://evil.com/phish") is False

    # Explicit allowed host match
    assert is_safe_redirect_url("https://github.com/login", allowed_hosts=["github.com"]) is True
    assert is_safe_redirect_url("https://evil.com/login", allowed_hosts=["github.com"]) is False


# ==============================================================================
# 8. Path Traversal Defense Tests (Playbook §6)
# ==============================================================================
def test_path_traversal_in_report_download_is_blocked(db: Session):
    """Verify attempts to load arbitrary filesystem paths outside REPORTS_STORAGE_DIR are trapped."""
    session_id = str(uuid.uuid4())
    audit_id = str(uuid.uuid4())

    audit = AuditModel(
        id=audit_id,
        repository_id=str(uuid.uuid4()),
        session_id=session_id,
        scopes=["SECURITY"],
        status="COMPLETED"
    )
    db.add(audit)

    # Malicious storage key pointing outside reports directory (e.g. windows win.ini or etc/passwd)
    traversal_report = ReportArtifactModel(
        id=str(uuid.uuid4()),
        audit_id=audit_id,
        format="pdf",
        status="COMPLETED",
        safe_storage_key="C:/Windows/win.ini" if Path("C:/Windows/win.ini").exists() else "/etc/passwd",
        expires_at=datetime.utcnow() + timedelta(hours=24)
    )
    db.add(traversal_report)
    db.commit()

    with pytest.raises(SecureScanException) as exc_info:
        get_report_artifact(traversal_report.id, session_id, db)

    # Must reject with 403 or 404
    assert exc_info.value.status_code in (403, 404)


# ==============================================================================
# 9. Security Headers Tests (Playbook §1, §20)
# ==============================================================================
def test_security_headers_are_present(client):
    """Verify strict HTTP security headers are returned on all API responses."""
    res = client.get("/")
    assert res.status_code == 200

    headers = res.headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "Content-Security-Policy" in headers
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]


# ==============================================================================
# 10. Generic 500 Error Masking Tests (Playbook §20)
# ==============================================================================
def test_generic_500_error_masks_internal_stack_trace():
    """Verify unhandled exceptions return sanitized JSON without file paths or tracebacks."""
    # Force an unhandled error route on test client
    @app.get("/api/v1/test-unhandled-exception")
    def trigger_crash():
        raise RuntimeError("Simulated database failure with secret key SECRET_123456789")

    unhandled_client = TestClient(app, raise_server_exceptions=False)
    res = unhandled_client.get("/api/v1/test-unhandled-exception")
    assert res.status_code == 500
    body = res.json()
    assert body["error"]["code"] == "ERR_INTERNAL_SERVER_ERROR"
    assert body["error"]["message"] == "An internal server error occurred."
    assert body["error"]["details"] is None
    # Ensure raw error message and secret were not leaked to caller
    assert "SECRET_123456789" not in res.text
    assert "RuntimeError" not in res.text
    assert "Traceback" not in res.text
