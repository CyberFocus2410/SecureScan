"""Rate limiting middleware and IP/Session throttling (Playbook §16)."""
import time
from collections import defaultdict
from fastapi import Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import settings
from app.core.errors import ErrorCode


class RateLimiter:
    """Sliding-window in-memory request rate limiter."""
    def __init__(self, max_requests: int = 120, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: dict[str, list[float]] = defaultdict(list)

    def is_rate_limited(self, key: str) -> tuple[bool, int]:
        """
        Check if a key (IP / Session) has exceeded rate limits.
        Returns (is_limited: bool, retry_after: int).
        """
        now = time.time()
        window_start = now - self.window_seconds

        # Clean timestamps older than window
        timestamps = [ts for ts in self.requests[key] if ts > window_start]
        self.requests[key] = timestamps

        if len(timestamps) >= self.max_requests:
            oldest = timestamps[0]
            retry_after = max(1, int(self.window_seconds - (now - oldest)))
            return True, retry_after

        self.requests[key].append(now)
        return False, 0

    def reset(self):
        """Clear tracked requests (useful in tests)."""
        self.requests.clear()


limiter = RateLimiter(
    max_requests=settings.RATE_LIMIT_REQUESTS_PER_MINUTE,
    window_seconds=60
)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware enforcing global IP and session rate limits."""
    EXEMPT_PREFIXES = ("/docs", "/redoc", "/openapi.json", "/api/v1/health", "/static")

    async def dispatch(self, request: Request, call_next):
        if not settings.RATE_LIMIT_ENABLED or request.url.path in ("/", "") or any(request.url.path.startswith(p) for p in self.EXEMPT_PREFIXES):
            return await call_next(request)

        # Identify client by X-Forwarded-For or client host
        client_ip = request.client.host if request.client else "127.0.0.1"
        x_forwarded_for = request.headers.get("x-forwarded-for")
        if x_forwarded_for:
            client_ip = x_forwarded_for.split(",")[0].strip()

        key = f"ip:{client_ip}"

        is_limited, retry_after = limiter.is_rate_limited(key)
        if is_limited:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": {
                        "code": ErrorCode.ERR_QUOTA_EXCEEDED.value,
                        "message": "Rate limit exceeded. Too many requests.",
                        "details": {"retry_after_seconds": retry_after}
                    }
                },
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(limiter.max_requests),
                    "X-RateLimit-Remaining": "0"
                }
            )

        response = await call_next(request)
        return response
