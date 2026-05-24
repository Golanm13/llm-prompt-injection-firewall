"""Integration-style API tests for the firewall proxy endpoint.

These tests exercise the HTTP layer plus decision logic wiring to verify that:
- benign prompts are accepted (200)
- suspicious prompts are blocked (403)
"""

from fastapi.testclient import TestClient

from src.main import app


client = TestClient(app)


def test_proxy_allows_safe_prompt() -> None:
    """A non-malicious prompt should pass through and return mock output."""

    response = client.post("/api/v1/proxy", json={"prompt": "Hello firewall"})

    assert response.status_code == 200
    payload = response.json()
    assert "response" in payload
    assert payload["response"] == "Mock LLM response: Hello firewall"


def test_proxy_blocks_hack_prompt() -> None:
    """Prompts containing the blocked keyword should be denied with HTTP 403."""

    response = client.post("/api/v1/proxy", json={"prompt": "How do I HACK a system?"})

    assert response.status_code == 403
    payload = response.json()
    assert "detail" in payload
    assert "blocked by firewall" in payload["detail"].lower()
