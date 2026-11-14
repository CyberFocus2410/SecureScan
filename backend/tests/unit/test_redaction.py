"""Unit tests for secret redaction utility and leakage assertion helper."""
import pytest
from app.core.security import redact, redact_text, assert_no_raw_secret


def test_redact_placeholder():
    assert redact("my_super_secret_key", "api-key") == "[REDACTED:api-key]"
    assert redact("", "secret") == ""


def test_redact_text_aws_key():
    raw_snippet = "client = boto3.client('s3', aws_access_key_id='AKIAIOSFODNN7EXAMPLE')"
    redacted = redact_text(raw_snippet)
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "[REDACTED:aws-access-key]" in redacted


def test_redact_text_generic_assignment():
    raw_snippet = 'password = "supersecretpassword123"'
    redacted = redact_text(raw_snippet)
    assert "supersecretpassword123" not in redacted
    assert "[REDACTED:secret]" in redacted


def test_assert_no_raw_secret_clean():
    safe_data = {
        "finding": "AWS Key leaked",
        "snippet": "key = '[REDACTED:aws-access-key]'",
        "metadata": ["safe", 123, True]
    }
    # Should not raise
    assert_no_raw_secret(safe_data, "AKIAIOSFODNN7EXAMPLE")


def test_assert_no_raw_secret_catches_leak_in_nested_dict():
    leaked_data = {
        "finding": "Secret found",
        "details": {
            "environment": {
                "SECRET_KEY": "supersecretpassword123"
            }
        }
    }
    with pytest.raises(AssertionError, match="Security Violation: Raw secret"):
        assert_no_raw_secret(leaked_data, "supersecretpassword123")


def test_assert_no_raw_secret_catches_leak_in_bytes():
    raw_payload = b"Authorization: Bearer my_raw_jwt_token_12345"
    with pytest.raises(AssertionError, match="Security Violation: Raw secret"):
        assert_no_raw_secret(raw_payload, "my_raw_jwt_token_12345")

