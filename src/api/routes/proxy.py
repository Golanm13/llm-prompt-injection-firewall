"""Proxy endpoint for receiving and filtering prompts before LLM execution."""

from fastapi import APIRouter, HTTPException, status

from src.schemas.proxy import ErrorResponse, ProxyRequest, ProxyResponse
from src.services.decision_logic import evaluate_prompt


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
        decision = evaluate_prompt(payload.prompt)

        if not decision.allowed:
            # 403 is used for policy-based rejection where request format is valid,
            # but business/security rules deny the content.
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=decision.reason)

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
