"""Application entrypoint for the LLM Firewall Proxy service.

Architecture overview (minimal but extensible):
- main.py: app bootstrap, environment loading, and global service wiring.
- api/routes: HTTP transport layer (FastAPI endpoints).
- schemas: request/response contracts (Pydantic models).
- services: business/security decision logic.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, status
from google import genai
from slowapi import Limiter
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

# טעינת משתני הסביבה מהמיקום הנכון
_ENV_PATH = Path(__file__).resolve().parents[1] / ".env"
load_dotenv(dotenv_path=_ENV_PATH)

GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")

# אתחול הלקוח של גוגל - אם אין מפתח, נזרוק שגיאה ברורה בריצה
if not GEMINI_API_KEY:
    raise ValueError("CRITICAL: GEMINI_API_KEY is not set in environment or .env file")

gemini_client = genai.Client(api_key=GEMINI_API_KEY)


def generate_gemini_response(prompt: str) -> str:
    """Generate a response from Gemini or raise a 503 if unavailable."""
    if gemini_client is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Gemini API is not configured.",
        )

    try:
        response = gemini_client.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompt,
        )
        text = getattr(response, "text", None)
        if text:
            return text
        return str(response)
    except Exception as exc:  # pragma: no cover - external API failure path
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Gemini API is temporarily unavailable: {str(exc)}",
        ) from exc


def create_app() -> FastAPI:
    """Factory to create and configure the FastAPI application instance."""
    app = FastAPI(
        title="LLM Firewall Proxy",
        version="0.1.0",
        description="Standalone application proxy that filters prompts before LLM access.",
    )

    app.state.limiter = limiter
    app.add_middleware(SlowAPIMiddleware)
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # הראוטינג המקורי של הפרויקט שלך
    from src.api.routes.proxy import router as proxy_router
    app.include_router(proxy_router)

    return app


app = create_app()