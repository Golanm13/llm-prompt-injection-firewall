"""Schema definitions for proxy request/response payloads.

These models represent the external API contract and centralize input/output
validation to keep endpoint code focused on orchestration.
"""

from pydantic import BaseModel, Field


class ProxyRequest(BaseModel):
    """Request body accepted by the LLM firewall proxy endpoint."""

    prompt: str = Field(..., min_length=1, description="Raw prompt from the client")


class ProxyResponse(BaseModel):
    """Response returned when a prompt is accepted by the firewall."""

    response: str = Field(..., description="Mocked output from downstream LLM")


class ErrorResponse(BaseModel):
    """Standardized error message payload for blocked or failed requests."""

    detail: str = Field(..., description="Human-readable explanation of the error")
