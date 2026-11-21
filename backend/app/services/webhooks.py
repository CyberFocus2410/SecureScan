"""HMAC-signed Webhook Service (Step 15, ADR-002).

Cryptographically signs outgoing webhook payloads using HMAC-SHA256 with
WEBHOOK_SECRET so consumers can verify authenticity and integrity.
"""
import hmac
import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any
import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)


class WebhookService:
    """Service to sign and deliver HMAC-SHA256 authenticated webhooks."""

    @staticmethod
    def compute_signature(payload_bytes: bytes, secret: str | None = None) -> str:
        """Compute HMAC-SHA256 signature in the format 'sha256=<hex>'."""
        active_secret = (secret or settings.WEBHOOK_SECRET).encode("utf-8")
        mac = hmac.new(active_secret, payload_bytes, hashlib.sha256)
        return f"sha256={mac.hexdigest()}"

    @staticmethod
    def verify_signature(payload_bytes: bytes, signature_header: str, secret: str | None = None) -> bool:
        """Constant-time verification of an incoming signature against the secret."""
        if not signature_header or not signature_header.startswith("sha256="):
            return False
        expected_sig = WebhookService.compute_signature(payload_bytes, secret)
        return hmac.compare_digest(expected_sig, signature_header)

    @classmethod
    def format_event(cls, event_type: str, data: dict[str, Any]) -> dict[str, Any]:
        """Wrap payload in a standardized event envelope."""
        return {
            "event": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data
        }

    @classmethod
    def deliver_webhook(
        cls,
        url: str,
        event_type: str,
        data: dict[str, Any],
        secret: str | None = None,
        timeout: float = 5.0
    ) -> dict[str, Any]:
        """Format, sign, and deliver webhook payload over HTTP."""
        event_payload = cls.format_event(event_type, data)
        payload_bytes = json.dumps(event_payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        signature = cls.compute_signature(payload_bytes, secret)

        headers = {
            "Content-Type": "application/json",
            "X-SecureScan-Signature": signature,
            "X-SecureScan-Event": event_type,
            "User-Agent": "SecureScan-Webhook/2.0"
        }

        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.post(url, content=payload_bytes, headers=headers)
                return {
                    "success": resp.is_success,
                    "status_code": resp.status_code,
                    "signature": signature,
                    "event": event_type
                }
        except Exception as e:
            logger.warning(f"Webhook delivery to {url} failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "signature": signature,
                "event": event_type
            }
