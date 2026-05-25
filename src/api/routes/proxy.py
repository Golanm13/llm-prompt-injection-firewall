"""Proxy endpoint for receiving and filtering prompts before LLM execution."""

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import JSONResponse

from src.schemas.proxy import ErrorResponse, ProxyRequest, ProxyResponse
from src.services.decision_logic import is_prompt_safe


router = APIRouter(prefix="/api/v1", tags=["proxy"])


@router.post(
    "/proxy",
    response_model=ProxyResponse,
    responses={
        status.HTTP_403_FORBIDDEN: {
            "model": ErrorResponse,
            "description": "Prompt was blocked by firewall policy.",
        },
        status.HTTP_500_INTERNAL_SERVER_ERROR: {
            "model": ErrorResponse,
            "description": "Unexpected internal processing error.",
        },
    },
)
def proxy_prompt(payload: ProxyRequest) -> ProxyResponse:
    """Accept a prompt, evaluate policy, then return mock LLM output.

    The endpoint performs three responsibilities:
    1) Input contract validation through Pydantic models.
    2) Delegation to a decision service (business logic layer).
    3) Consistent HTTP responses for allow/block/error outcomes.
    """

    try:
        safety = is_prompt_safe(payload.prompt)

        if not safety.is_safe:
            # Return a structured 403 payload so clients can inspect the risk signal.
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content=ErrorResponse(
                    detail=safety.block_reason or "Prompt blocked by firewall policy.",
                    reason=safety.block_reason or "Prompt blocked by firewall policy.",
                    category=safety.category or "unknown",
                    risk_score=safety.risk_score,
                ).model_dump(),
            )

        # Mock downstream LLM response (placeholder for future provider integration).
        return ProxyResponse(response=f"Mock LLM response: {payload.prompt}")

    except HTTPException:
        # Re-raise known API exceptions unchanged to preserve intended status code.
        raise
    except Exception as exc:  # pragma: no cover - defensive fallback
        # Hide internal exception details from clients to avoid information leakage.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal firewall processing error.",
        ) from exc
