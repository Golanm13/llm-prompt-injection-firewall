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
import requests
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, status
from google import genai
from slowapi import Limiter
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

_ENV_PATH = Path(__file__).resolve().parents[1] / ".env"
load_dotenv(dotenv_path=_ENV_PATH)

GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")

if not GEMINI_API_KEY:
    raise ValueError("CRITICAL: GEMINI_API_KEY is not set in environment or .env file")

gemini_client = genai.Client(api_key=GEMINI_API_KEY)

def reset_firewall_audit_log() -> None:
    """Deletes the unified firewall audit log file at startup to clean previous environment sessions."""
    log_path = Path(__file__).resolve().parents[1] / "firewall_audit.jsonl"
    try:
        log_path.unlink(missing_ok=True)
    except OSError:
        pass

def _call_ollama_generation(prompt: str) -> str:
    """Fallback to local Ollama for answering the prompt when Gemini is unavailable."""
    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "llama3",
                "prompt": prompt,
                "stream": False
            },
            timeout=45
        )
        response.raise_for_status()
        return response.json().get("response", "").strip()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Both Gemini API and local Ollama generation failed: {str(exc)}",
        )

def generate_gemini_response(prompt: str) -> str:
    """Generate a response from Gemini or raise a 503 if unavailable."""
    if gemini_client is None:
        return _call_ollama_generation(prompt)

    try:
        response = gemini_client.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompt,
        )
        text = getattr(response, "text", None)
        if text:
            return text
        return str(response)
    except Exception as exc:  # Caught 429 / Quota / Network errors
        try:
            return _call_ollama_generation(prompt)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Gemini API is temporarily unavailable and Ollama fallback failed: {str(exc)}",
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
    app.add_event_handler("startup", reset_firewall_audit_log)

    # Include proxy route endpoints
    from src.api.routes.proxy import router as proxy_router
    app.include_router(proxy_router)

    return app


app = create_app()