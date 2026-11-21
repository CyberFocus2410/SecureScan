"""Administrative diagnostics and tool health endpoints (Step 2, ADR-002, Section 5)."""
from fastapi import APIRouter
from app.services.tool_doctor import run_tool_diagnostics

router = APIRouter(prefix="/admin", tags=["Admin"])


@router.get("/tools")
def get_tool_health():
    """
    Diagnostic self-test and tool health endpoint.
    Reports primary tool status, versions, active fallbacks, and sandbox isolation mode.
    """
    return run_tool_diagnostics()
