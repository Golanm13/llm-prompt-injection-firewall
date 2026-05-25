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


AUDIT_LOG_PATH = Path(__file__).resolve().parents[2] / "audit_log.jsonl"
_WRITE_LOCK = Lock()


def log_prompt_event(
    client_ip: str,
    prompt_text: str,
    is_safe: bool,
    category: Optional[str],
    risk_score: str,
) -> None:
    """Append a single prompt decision record to the audit log.

    The file is written in JSONL format to keep ingestion simple and maintain an
    append-only audit trail. A process-local lock prevents concurrent writes from
    interleaving lines.
    """

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "client_ip": client_ip,
        "prompt_text": prompt_text,
        "is_safe": is_safe,
        "category": category,
        "risk_score": risk_score,
    }

    serialized_event = json.dumps(event, ensure_ascii=False)

    with _WRITE_LOCK:
        with AUDIT_LOG_PATH.open("a", encoding="utf-8") as audit_file:
            audit_file.write(f"{serialized_event}\n")