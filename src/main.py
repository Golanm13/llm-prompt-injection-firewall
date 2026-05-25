"""Application entrypoint for the LLM Firewall Proxy service.

Architecture overview (minimal but extensible):
- main.py: app bootstrap and global middleware/routers wiring.
- api/routes: HTTP transport layer (FastAPI endpoints).
- schemas: request/response contracts (Pydantic models).
- services: business/security decision logic.
"""

from fastapi import FastAPI
from slowapi import Limiter
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address



limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")


def create_app() -> FastAPI:
    """Factory to create and configure the FastAPI application instance.

    A factory keeps startup wiring testable and flexible for future env-specific
    initialization (observability, auth middleware, dependency injection, etc.).
    """

    app = FastAPI(
        title="LLM Firewall Proxy",
        version="0.1.0",
        description="Standalone application proxy that filters prompts before LLM access.",
    )

    app.state.limiter = limiter
    app.add_middleware(SlowAPIMiddleware)
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # Register API routes.
    from src.api.routes.proxy import router as proxy_router

    app.include_router(proxy_router)

    return app


# ASGI application used by uvicorn (e.g., `uvicorn src.main:app --reload`).
app = create_app()
