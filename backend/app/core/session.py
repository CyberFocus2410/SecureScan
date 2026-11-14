"""Anonymous session-scoped capability management (FR-ACC-01, D-11)."""
import uuid
from fastapi import Header, HTTPException, status
from app.core.errors import UnauthorizedSessionError


def get_session_id(x_session_id: str | None = Header(default=None, alias="X-Session-ID")) -> str:
    """
    Extract or generate anonymous session capability ID.
    Clients supply X-Session-ID; if omitted, a new UUID is generated.
    """
    if not x_session_id:
        return str(uuid.uuid4())
    x_session_id = x_session_id.strip()
    try:
        # Validate UUID format
        val = uuid.UUID(x_session_id)
        return str(val)
    except ValueError:
        raise UnauthorizedSessionError("X-Session-ID header must be a valid UUID format.")

