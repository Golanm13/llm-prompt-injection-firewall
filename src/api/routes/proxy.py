"""Proxy endpoint for receiving and filtering prompts before LLM execution."""

import src.main as app_main

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import JSONResponse

from src.schemas.proxy import ErrorResponse, ProxyRequest, ProxyResponse
from src.services.audit_logger import log_prompt_event
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
@app_main.limiter.limit("5/minute")
def proxy_prompt(request: Request, payload: ProxyRequest) -> ProxyResponse:
    """Accept a prompt, evaluate policy, then return mock LLM output.

    The endpoint performs three responsibilities:
    1) Input contract validation through Pydantic models.
    2) Delegation to a decision service (business logic layer).
    3) Consistent HTTP responses for allow/block/error outcomes.
    """

    try:
        client_ip = request.client.host if request.client else "unknown"
        safety = is_prompt_safe(payload.prompt)

        log_prompt_event(
            client_ip=client_ip,
            prompt_text=payload.prompt,
            is_safe=safety.is_safe,
            category=safety.category,
            risk_score=safety.risk_score,
        )

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

        gemini_response = app_main.generate_gemini_response(payload.prompt)
        return ProxyResponse(response=gemini_response)

    except HTTPException:
        # Re-raise known API exceptions unchanged to preserve intended status code.
        raise
    except Exception as exc:  # pragma: no cover - defensive fallback
        # Hide internal exception details from clients to avoid information leakage.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal firewall processing error.",
        ) from exc
