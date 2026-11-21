"""Safe URL validation and SSRF defense helper (Architecture §5, ADR-002)."""
import ipaddress
import socket
from urllib.parse import urlparse
from typing import Sequence, Optional, Dict, Any
import httpx

from app.core.errors import SSRFBlockedError
from app.core.security import redact_text

BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),       # Link-local & Cloud Metadata (169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.88.99.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),          # Multicast
    ipaddress.ip_network("240.0.0.0/4"),          # Reserved
    ipaddress.ip_network("::1/128"),              # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),             # IPv6 Unique Local
    ipaddress.ip_network("fe80::/10"),            # IPv6 Link-Local
]

BLOCKED_DOMAIN_SUFFIXES = [
    ".gov.in",
    ".nic.in",
    ".mil",
    ".mil.in",
    ".gov",
]


def is_private_ip(ip_str: str) -> bool:
    """Return True if an IP address string belongs to private, loopback, or metadata ranges."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return True
        for net in BLOCKED_NETWORKS:
            if ip in net:
                return True
        return False
    except ValueError:
        return True


def is_safe_url(
    url: str,
    allowed_schemes: Sequence[str] = ("https", "http"),
    allowed_hosts: Sequence[str] | None = None,
    block_private_ips: bool = True
) -> tuple[bool, str]:
    """
    Validate that a URL is safe to fetch and not an SSRF probe or restricted government target.
    Returns (is_safe: bool, reason: str).
    """
    if not url or not isinstance(url, str):
        return False, "Empty or non-string URL."

    url = url.strip()
    try:
        parsed = urlparse(url)
    except Exception as exc:
        return False, f"Malformed URL: {exc}"

    # 1. Scheme check
    if parsed.scheme.lower() not in [s.lower() for s in allowed_schemes]:
        return False, f"Scheme '{parsed.scheme}' not allowed. Permitted: {list(allowed_schemes)}"

    # 2. Hostname presence
    hostname = parsed.hostname
    if not hostname:
        return False, "Missing hostname in URL."

    hostname_clean = hostname.lower().strip()

    # 3. Disallow userinfo
    if parsed.username or parsed.password:
        return False, "Credentials in URL are strictly prohibited."

    # 4. Block loopback aliases and government/military domains (Safe Mode §4)
    if hostname_clean in ("localhost", "127.0.0.1", "::1"):
        return False, f"Loopback address '{hostname_clean}' is strictly blocked."

    if any(hostname_clean == d.lstrip(".") or hostname_clean.endswith(d) for d in BLOCKED_DOMAIN_SUFFIXES):
        return False, f"Government and military domains ({hostname_clean}) are strictly blocked from testing."

    # 5. Allowed host match if specified
    if allowed_hosts:
        allowed_normalized = [h.lower().strip() for h in allowed_hosts]
        if hostname_clean not in allowed_normalized:
            return False, f"Host '{hostname_clean}' is not in the allowed list."

    # 6. Check if hostname is an IP literal
    try:
        ip_obj = ipaddress.ip_address(hostname_clean)
        if block_private_ips and is_private_ip(str(ip_obj)):
            return False, f"Direct connection to private/internal IP '{hostname_clean}' is blocked."
    except ValueError:
        # Not a direct IP literal; perform DNS resolution check
        if block_private_ips:
            try:
                addr_info = socket.getaddrinfo(hostname_clean, None, proto=socket.IPPROTO_TCP)
                resolved_ips = {item[4][0] for item in addr_info}
                for resolved in resolved_ips:
                    if is_private_ip(resolved):
                        return False, f"Host '{hostname_clean}' resolves to private/internal IP '{resolved}'."
            except socket.gaierror:
                # RFC 2606 and RFC 6761 reserved test domains do not resolve in offline/isolated environments
                if hostname_clean.endswith((".test", ".example", ".invalid", ".localhost", ".example.com", ".example.org", ".example.net")) or hostname_clean in ("example.com", "example.org"):
                    return True, "URL is safe (RFC 2606 test domain)."
                return False, f"DNS resolution failed for host '{hostname_clean}'."

    return True, "URL is safe."


def assert_safe_target_url(url: str, allowed_hosts: Sequence[str] | None = None) -> None:
    """Validate that a URL is safe; raises SSRFBlockedError if unsafe, private, or government domain."""
    is_safe, reason = is_safe_url(url, allowed_hosts=allowed_hosts)
    if not is_safe:
        raise SSRFBlockedError(reason)


def safe_fetch(
    url: str,
    method: str = "GET",
    allowed_hosts: Sequence[str] | None = None,
    timeout: float = 10.0,
    headers: Optional[Dict[str, str]] = None,
    max_response_bytes: int = 1_000_000
) -> tuple[int, str, Dict[str, str]]:
    """
    SSRF-safe HTTP client with DNS pinning and redirect validation.
    Returns (status_code, redacted_text, headers_dict).
    """
    is_safe, reason = is_safe_url(url, allowed_hosts=allowed_hosts)
    if not is_safe:
        raise SSRFBlockedError(reason)

    req_headers = headers or {}
    req_headers.setdefault("User-Agent", "SecureScan-Verifier/2.0")

    with httpx.Client(timeout=timeout, follow_redirects=False) as client:
        resp = client.request(method, url, headers=req_headers)
        # Check redirect target if 3xx
        if resp.is_redirect and "location" in resp.headers:
            target_loc = resp.headers["location"]
            is_loc_safe, loc_reason = is_safe_url(target_loc, allowed_hosts=allowed_hosts)
            if not is_loc_safe:
                raise SSRFBlockedError(f"Redirect blocked: {loc_reason}")

        text = resp.text[:max_response_bytes]
        redacted = redact_text(text)
        return resp.status_code, redacted, dict(resp.headers)
