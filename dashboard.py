"""Streamlit observability dashboard for the firewall audit trail."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st


AUDIT_LOG_PATH = Path(__file__).resolve().parent / "firewall_audit.jsonl"


def read_audit_events() -> list[dict[str, Any]]:
    """Read all firewall audit events without failing on partial writes."""

    if not AUDIT_LOG_PATH.exists():
        return []

    parsed_events: list[dict[str, Any]] = []

    try:
        with AUDIT_LOG_PATH.open("r", encoding="utf-8", errors="ignore") as audit_file:
            for line in audit_file:
                stripped_line = line.strip()
                if not stripped_line:
                    continue

                try:
                    parsed_events.append(json.loads(stripped_line))
                except json.JSONDecodeError:
                    # Ignore a partially written tail line and keep the rest.
                    continue
    except OSError:
        return []

    return parsed_events


def build_display_frame(events: list[dict[str, Any]]) -> pd.DataFrame:
    """Normalize audit entries into a table-friendly data frame."""

    if not events:
        return pd.DataFrame(columns=["timestamp", "prompt", "decision", "category", "risk_score"])

    frame = pd.DataFrame(events)
    expected_columns = ["timestamp", "prompt", "decision", "category", "risk_score"]

    for column in expected_columns:
        if column not in frame.columns:
            frame[column] = None

    return frame[expected_columns]


def main() -> None:
    """Render the security observability dashboard."""

    st.set_page_config(page_title="Firewall Observability Dashboard", layout="wide")
    st.title("Firewall Observability Dashboard")
    st.caption("Live view of prompt-firewall decisions from firewall_audit.jsonl")

    if st.sidebar.button("Refresh now"):
        st.rerun()

    all_events = read_audit_events()
    recent_events = all_events[-20:]
    display_frame = build_display_frame(recent_events)

    total_requests = len(all_events)
    blocked_requests = sum(1 for event in all_events if event.get("decision") == "blocked")

    metric_columns = st.columns(2)
    metric_columns[0].metric("Total requests", total_requests)
    metric_columns[1].metric("Blocked requests", blocked_requests)

    st.subheader("Blocked Category Distribution")
    blocked_events = [event for event in all_events if event.get("decision") == "blocked"]
    blocked_categories = Counter(
        str(event.get("category") or "uncategorized") for event in blocked_events
    )

    if blocked_categories:
        st.bar_chart(pd.Series(blocked_categories).sort_values(ascending=False))
    else:
        st.info("No blocked categories yet.")

    st.subheader("20 Most Recent Events")
    if display_frame.empty:
        st.info("No audit events have been logged yet.")
    else:
        st.dataframe(display_frame.iloc[::-1], use_container_width=True, hide_index=True)


if __name__ == "__main__":
    main()