"""Audit logging for prompt firewall decisions.

This module appends structured JSON Lines records to a local audit log so the
proxy can preserve an append-only trail of prompt safety decisions.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Optional


FIREWALL_AUDIT_PATH = Path(__file__).resolve().parents[2] / "firewall_audit.jsonl"
_LOG_LOCK = Lock()

def log_prompt_event(client_ip: str, prompt_text: str, is_safe: bool, category: str | None, risk_score: str) -> None:
    """Logs firewall evaluation details asynchronously or via background tasks to a single unified file."""
    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "client_ip": client_ip,
        "prompt": prompt_text.strip(),
        "decision": "safe" if is_safe else "blocked",
        "category": category,
        "risk_score": risk_score
    }
    
    with _LOG_LOCK:
        with open(FIREWALL_AUDIT_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry) + "\n")