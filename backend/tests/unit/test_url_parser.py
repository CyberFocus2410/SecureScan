"""AT-02: Negative URL parsing and validation tests.
Asserts that malicious, internal, non-GitHub, or malformed URLs are rejected
BEFORE any network call is initiated.
"""
import socket
import pytest
from app.services.github_import import parse_and_validate_github_url, validate_branch
from app.core.errors import InvalidRepoUrlError


def test_at02_negative_urls_rejected_without_network(monkeypatch):
    """
    AT-02: Negative URLs rejected before fetch; assert no network call.
    Monkeypatches socket.socket to ensure zero network calls are attempted.
    """
    def fail_on_network(*args, **kwargs):
        raise AssertionError("Network socket was opened during URL parsing! (Violates AT-02)")

    monkeypatch.setattr(socket, "socket", fail_on_network)
    monkeypatch.setattr(socket, "getaddrinfo", fail_on_network)

    malicious_and_invalid_urls = [
        # Non-HTTPS schemes
        "file:///etc/passwd",
        "file://C:/Windows/win.ini",
        "http://github.com/owner/repo",
        "ftp://github.com/owner/repo",
        "ssh://git@github.com:owner/repo.git",

        # Internal and metadata IP addresses
        "http://169.254.169.254/latest/meta-data/",
        "https://169.254.169.254/repo",
        "http://127.0.0.1:8000/admin",
        "https://127.0.0.1/owner/repo",
        "http://10.0.0.1/internal/repo",
        "http://192.168.1.1/secret/repo",
        "http://0.0.0.0:80/repo",

        # Alternative hosts / spoofing
        "https://gitlab.com/owner/repo",
        "https://bitbucket.org/owner/repo",
        "https://github.com.attacker.com/owner/repo",
        "https://attacker-github.com/owner/repo",
        "https://notgithub.com/owner/repo",

        # Userinfo / credentials embedded
        "https://user:password@github.com/owner/repo",
        "https://token@github.com/owner/repo",

        # Query strings and fragments
        "https://github.com/owner/repo?param=value",
        "https://github.com/owner/repo#access_token=secret",

        # Directory traversal tricks
        "https://github.com/../repo",
        "https://github.com/owner/..",
        "https://github.com/owner/../admin/repo",

        # Malformed paths
        "https://github.com/",
        "https://github.com/owner",
        "https://github.com/owner/repo/extra/path",
        "not_a_url",
        "",
    ]

    for bad_url in malicious_and_invalid_urls:
        with pytest.raises(InvalidRepoUrlError, match="Invalid|Unsupported|Malformed|format|Prohibited|prohibited|not permitted|non-empty"):
            parse_and_validate_github_url(bad_url)


def test_valid_github_urls_canonicalized():
    # Standard URL
    owner, repo, canonical = parse_and_validate_github_url("https://github.com/fastapi/fastapi")
    assert owner == "fastapi"
    assert repo == "fastapi"
    assert canonical == "https://github.com/fastapi/fastapi"

    # With .git suffix
    owner, repo, canonical = parse_and_validate_github_url("https://github.com/expressjs/express.git")
    assert owner == "expressjs"
    assert repo == "express"
    assert canonical == "https://github.com/expressjs/express"

    # With trailing slash
    owner, repo, canonical = parse_and_validate_github_url("https://github.com/psf/requests/")
    assert owner == "psf"
    assert repo == "requests"
    assert canonical == "https://github.com/psf/requests"


def test_validate_branch_safety():
    assert validate_branch("main") == "main"
    assert validate_branch("feature/auth-v2") == "feature/auth-v2"
    assert validate_branch("release-1.0.0") == "release-1.0.0"

    with pytest.raises(InvalidRepoUrlError):
        validate_branch("../../../etc/passwd")

    with pytest.raises(InvalidRepoUrlError):
        validate_branch("branch@{1}")

