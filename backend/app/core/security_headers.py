"""Security headers middleware for HTTP response hardening (Playbook §1, §20)."""
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from app.core.config import settings


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Inject strict security headers into all outgoing HTTP responses."""

    CSP_POLICY = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https://github.com; "
        "font-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        if not settings.SECURITY_HEADERS_ENABLED:
            return response

        headers = response.headers
        headers["X-Content-Type-Options"] = "nosniff"
        headers["X-Frame-Options"] = "DENY"
        headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=(), payment=()"
        headers["Cross-Origin-Opener-Policy"] = "same-origin"
        headers["Content-Security-Policy"] = self.CSP_POLICY

        # In production or HTTPS, add Strict-Transport-Security
        if settings.ENVIRONMENT != "development" or request.url.scheme == "https":
            headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        return response
