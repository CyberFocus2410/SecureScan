"""Security primitives: secret redaction and leakage assertions."""
import re
from typing import Any

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

