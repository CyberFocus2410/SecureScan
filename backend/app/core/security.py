"""Security primitives: secret redaction and leakage assertions."""
import re
import hmac
import hashlib
import time
from urllib.parse import urlparse
from typing import Any, Sequence

# Standard placeholder format: [REDACTED:<type>]
REDACTION_PATTERN = re.compile(
    r"""(?xi)
    # Generic key-value assignment patterns with secrets
    (?P<prefix>(?:password|passwd|secret|api_key|apikey|access_token|auth_token|token|private_key|client_secret)\s*[:=]\s*["']?)
    (?P<secret>[A-Za-z0-9_\-\.\+/]{8,})
    (?P<suffix>["']?)
    """
)

# Known high-confidence token prefixes
SPECIFIC_SECRET_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "aws-access-key"),
    (re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}"), "github-token"),
    (re.compile(r"glpat-[0-9a-zA-Z\-_]{20,255}"), "gitlab-token"),
    (re.compile(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*"), "slack-token"),
    (re.compile(r"sk-(?:proj|ant|live|test)?[a-zA-Z0-9_\-]{20,255}"), "ai-api-key"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "private-key"),
]


def redact(secret_match: str, secret_type: str = "secret") -> str:
    """Replace a raw secret match with a sanitized placeholder."""
    if not secret_match:
        return ""
    return f"[REDACTED:{secret_type}]"


def redact_text(text: str) -> str:
    """Scrub known secret patterns from arbitrary text snippets."""
    if not text:
        return ""

    sanitized = text

    # First check specific known token formats
    for pattern, stype in SPECIFIC_SECRET_PATTERNS:
        sanitized = pattern.sub(f"[REDACTED:{stype}]", sanitized)

    # Next check generic assignment patterns
    def _replace_kv(m: re.Match) -> str:
        return f"{m.group('prefix')}[REDACTED:secret]{m.group('suffix')}"

    sanitized = REDACTION_PATTERN.sub(_replace_kv, sanitized)
    return sanitized


def assert_no_raw_secret(container: Any, raw_secret: str) -> None:
    """
    Test assertion helper verifying that a raw secret literal does not appear
    in any string, dictionary, list, byte sequence, or nested data structure.
    Raises AssertionError if raw_secret is found.
    """
    if not raw_secret or len(raw_secret) < 3:
        return

    if isinstance(container, str):
        if raw_secret in container:
            raise AssertionError(f"Security Violation: Raw secret '{raw_secret}' found in string payload!")
    elif isinstance(container, bytes):
        if raw_secret.encode("utf-8") in container:
            raise AssertionError(f"Security Violation: Raw secret '{raw_secret}' found in bytes payload!")
    elif isinstance(container, dict):
        for key, val in container.items():
            assert_no_raw_secret(key, raw_secret)
            assert_no_raw_secret(val, raw_secret)
    elif isinstance(container, (list, tuple, set)):
        for item in container:
            assert_no_raw_secret(item, raw_secret)


def is_safe_redirect_url(target_url: str, allowed_hosts: Sequence[str] | None = None) -> bool:
    """
    Validate redirect URLs to defend against Open Redirect attacks (Playbook §18).
    - Requires relative URLs to begin with single '/' and disallows '//', '/\\', or scheme-relative tricks.
    - If absolute URL, strictly matches host against allowed_hosts.
    """
    if not target_url or not isinstance(target_url, str):
        return False

    url = target_url.strip()
    if "\r" in url or "\n" in url or "\0" in url:
        return False

    # Disallow protocol-relative or Windows-path-relative: '//', '/\', '\\'
    if url.startswith("//") or url.startswith("/\\") or url.startswith("\\"):
        return False

    # Relative path check
    if url.startswith("/") and not url.startswith("/_") and not url.startswith("//"):
        try:
            parsed = urlparse(url)
            # Must not have netloc or scheme
            if not parsed.netloc and not parsed.scheme:
                return True
        except Exception:
            return False

    # Absolute URL check
    try:
        parsed = urlparse(url)
        if parsed.scheme.lower() not in ("http", "https"):
            return False
        if not parsed.hostname:
            return False
        if allowed_hosts:
            allowed = [h.lower().strip() for h in allowed_hosts]
            return parsed.hostname.lower().strip() in allowed
        return False
    except Exception:
        return False


def verify_webhook_signature(
    raw_body: bytes,
    signature_header: str,
    secret: str,
    tolerance_seconds: int = 300,
    timestamp: int | None = None
) -> tuple[bool, str]:
    """
    Verify webhook HMAC-SHA256 signature with constant-time equality and replay protection (Playbook §19).
    Returns (is_valid: bool, reason: str).
    """
    if not signature_header or not secret:
        return False, "Missing signature header or secret."

    if not isinstance(raw_body, bytes):
        return False, "Raw body must be bytes."

    # Parse potential timestamp and signature formatted as 't=...,v1=...' or 'sha256=...'
    sig_clean = signature_header.strip()
    ts_val = timestamp

    if "t=" in sig_clean and "v1=" in sig_clean:
        parts = dict(part.split("=", 1) for part in sig_clean.split(",") if "=" in part)
        try:
            ts_val = int(parts.get("t", 0))
            sig_clean = parts.get("v1", "")
        except ValueError:
            return False, "Invalid timestamp in signature header."

    # Check timestamp replay protection if provided
    if ts_val is not None:
        current_time = int(time.time())
        if abs(current_time - ts_val) > tolerance_seconds:
            return False, f"Signature timestamp expired (drift > {tolerance_seconds}s)."

    # Compute expected signature
    to_sign = f"{ts_val}.".encode("utf-8") + raw_body if ts_val is not None else raw_body
    computed = hmac.new(secret.encode("utf-8"), to_sign, hashlib.sha256).hexdigest()

    # Normalize hex prefix if present
    if sig_clean.startswith("sha256="):
        sig_clean = sig_clean[7:]

    # Constant-time comparison
    if not hmac.compare_digest(computed.lower(), sig_clean.lower()):
        return False, "HMAC signature mismatch."

    return True, "Signature verified."


