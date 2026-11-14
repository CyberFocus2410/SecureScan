"""AI explanation schemas (FR-AI-03)."""
from typing import Optional
from uuid import UUID
from pydantic import BaseModel, Field, ConfigDict


class AIExplainRequest(BaseModel):
    include_risk_context: bool = Field(True, description="Whether to include contextual risk breakdown")

    model_config = ConfigDict(extra="forbid")


class AIExplanation(BaseModel):
    finding_id: UUID
    ai_generated: bool = Field(True, description="Flag indicating the analysis is AI-generated assistance")
    provider: str = Field(..., description="LLM provider name (e.g. google, anthropic, fallback)")
    model: str = Field(..., description="Specific model identifier")
    root_cause: str = Field(..., description="Root cause analysis based on static evidence")
    risk_context: str = Field(..., description="Contextual architectural risk analysis")
    code_evidence_ref: str = Field(..., description="File and line reference grounding the explanation")
    recommended_technical_fix: str = Field(..., description="Concrete technical remediation guidance")
    recommended_document_or_process_action: str = Field(
        ..., description="Organizational or procedural steps to prevent recurrence"
    )
    validation_steps: list[str] = Field(..., description="Actionable commands or tests to verify the fix")
    unanswered_questions: list[str] = Field(
        default_factory=list, description="Questions that cannot be resolved solely from static analysis"
    )
    limitations: str = Field(
        "AI explanation is automated developer assistance; does not certify absence of other vulnerabilities.",
        description="Explicit disclaimer of AI analysis boundaries"
    )

    model_config = ConfigDict(from_attributes=True)

