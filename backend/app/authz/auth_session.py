"""Multi-Account Authenticated Session Manager (Step 9, ADR-002, Section 4)."""
import logging
from typing import Dict, Optional, Any
import httpx

from app.core.security import redact_text

logger = logging.getLogger(__name__)


class AuthRoleSession:
    """
    Represents an authenticated testing session pinned to a specific security role:
    - 'anon': Unauthenticated public requests
    - 'user_a': Regular Tenant/User A
    - 'user_b': Regular Tenant/User B
    - 'admin': Privileged Administrator
    """

    def __init__(
        self,
        role: str,
        auth_type: str = "NONE",  # "BEARER", "COOKIE", "HEADER", "NONE"
        token: Optional[str] = None,
        cookies: Optional[Dict[str, str]] = None,
        custom_headers: Optional[Dict[str, str]] = None,
        user_id: Optional[str] = None
    ):
        self.role = role.lower()
        self.auth_type = auth_type.upper()
        self.token = token
        self.cookies = cookies or {}
        self.custom_headers = custom_headers or {}
        self.user_id = user_id or f"{self.role}_id"

    def get_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {
            "User-Agent": f"SecureScan-AuthTester/2.0 ({self.role})"
        }
        if self.auth_type == "BEARER" and self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        elif self.auth_type == "HEADER" and self.custom_headers:
            headers.update(self.custom_headers)
        return headers

    def get_cookies(self) -> Dict[str, str]:
        return dict(self.cookies)

    def mask_credentials(self) -> str:
        """Returns safe representation with zero raw secrets or tokens."""
        if self.auth_type == "NONE":
            return "Role: anon (Unauthenticated)"
        return f"Role: {self.role} (AuthType: {self.auth_type}, Token: [MASKED_{self.role.upper()}])"
