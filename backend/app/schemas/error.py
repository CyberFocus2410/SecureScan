"""Standard ErrorResponse schema."""
from typing import Any
from pydantic import BaseModel, Field


class ErrorDetail(BaseModel):
    code: str = Field(..., description="Frozen error code e.g. ERR_INVALID_REPO_URL")
    message: str = Field(..., description="Human-readable safe explanation")
    details: Any = Field(default=None, description="Optional structured validation or contextual metadata")


class ErrorResponse(BaseModel):
    error: ErrorDetail

