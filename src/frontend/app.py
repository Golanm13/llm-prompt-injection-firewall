"""Streamlit frontend for the LLM Firewall Proxy.

This UI provides a lightweight chat experience for sending prompts to the
FastAPI proxy endpoint and observing allow/block outcomes with audit-log
visibility in the sidebar.
"""

from __future__ import annotations

import json
import os
from collections import deque
from pathlib import Path
from typing import Any

import requests
import streamlit as st


DEFAULT_PROXY_URL = "http://127.0.0.1:8000/api/v1/proxy"
AUDIT_LOG_PATH = Path(__file__).resolve().parents[2] / "audit_log.jsonl"


def build_prompt_request(prompt_text: str) -> dict[str, Any]:
    """Construct the request body expected by the proxy service."""

    return {"prompt": prompt_text}


def read_recent_audit_events(limit: int = 10) -> list[dict[str, Any]]:
    """Read the last `limit` JSONL audit events, newest last.

    The file may not exist on first launch, so this helper degrades gracefully
    and returns an empty list in that case.
    """

    if not AUDIT_LOG_PATH.exists():
        return []

    recent_lines: deque[str] = deque(maxlen=limit)
    with AUDIT_LOG_PATH.open("r", encoding="utf-8") as audit_file:
        for line in audit_file:
            line = line.strip()
            if line:
                recent_lines.append(line)

    events: list[dict[str, Any]] = []
    for line in recent_lines:
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    return events


def render_audit_sidebar() -> None:
    """Render the most recent audit events in the sidebar."""

    st.sidebar.title("Security Audit Logs")
    st.sidebar.caption("Latest 10 decisions from audit_log.jsonl")

    events = read_recent_audit_events(limit=10)
    if not events:
        st.sidebar.info("No audit entries yet. Send a prompt to begin logging.")
        return

    for event in reversed(events):
        status = "Allowed" if event.get("is_safe", False) else "Blocked"
        st.sidebar.markdown(f"**{status}**  ")
        st.sidebar.caption(
            f"{event.get('timestamp', 'unknown time')} | {event.get('client_ip', 'unknown IP')}"
        )
        st.sidebar.code(
            json.dumps(
                {
                    "prompt_text": event.get("prompt_text"),
                    "category": event.get("category"),
                    "risk_score": event.get("risk_score"),
                },
                ensure_ascii=False,
                indent=2,
            ),
            language="json",
        )


def parse_error_response(response: requests.Response) -> dict[str, str]:
    """Extract structured error metadata from a failed proxy response."""

    fallback_message = response.text.strip() or "Request blocked by proxy."
    parsed: dict[str, Any]

    try:
        parsed = response.json()
    except ValueError:
        parsed = {}

    return {
        "reason": str(parsed.get("reason") or parsed.get("detail") or fallback_message),
        "category": str(parsed.get("category") or "unknown"),
        "risk_score": str(parsed.get("risk_score") or "unknown"),
    }


def send_prompt(prompt_text: str, proxy_url: str) -> requests.Response:
    """Send the prompt payload to the FastAPI proxy endpoint."""

    return requests.post(
        proxy_url,
        json=build_prompt_request(prompt_text),
        timeout=30,
    )


def main() -> None:
    """Render the chat UI and handle prompt submissions."""

    st.set_page_config(page_title="LLM Firewall", page_icon="🛡️", layout="wide")
    st.title("LLM Firewall")
    st.caption("Chat-style prompt inspection with audit visibility and rate-limit awareness.")

    proxy_url = os.getenv("LLM_FIREWALL_PROXY_URL", DEFAULT_PROXY_URL)

    if "messages" not in st.session_state:
        st.session_state.messages = []

    render_audit_sidebar()

    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    prompt_text = st.chat_input("Enter a prompt to test the firewall...")
    if not prompt_text:
        return

    st.session_state.messages.append({"role": "user", "content": prompt_text})
    with st.chat_message("user"):
        st.markdown(prompt_text)

    try:
        response = send_prompt(prompt_text, proxy_url)

        if response.status_code == 200:
            payload = response.json()
            assistant_message = payload.get("response", "No response returned by proxy.")
            st.session_state.messages.append({"role": "assistant", "content": assistant_message})
            with st.chat_message("assistant"):
                st.markdown(assistant_message)
            return

        if response.status_code in {403, 429}:
            metadata = parse_error_response(response)
            error_message = (
                f"{metadata['reason']}\n\n"
                f"Category: {metadata['category']}\n\n"
                f"Risk score: {metadata['risk_score']}"
            )
            st.error(error_message)
            st.session_state.messages.append({"role": "assistant", "content": error_message})
            return

        response.raise_for_status()

    except requests.RequestException as exc:
        st.error(f"Failed to reach the firewall proxy: {exc}")


if __name__ == "__main__":
    main()