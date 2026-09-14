"""In-memory session store. Nothing here is persisted; process exit clears it.

A session holds the original upload path, its findings, the local-only ``secrets``
map ({finding_id: raw_value}), and — once sanitized — the output path. The secrets
map never enters a response body and never leaves the process.
"""
from __future__ import annotations

import os
import uuid
from typing import Optional

# session_id -> dict(path, ext, findings, secrets, out_path, intent)
_SESSIONS: dict[str, dict] = {}


def create(path: str, ext: str, findings: list, secrets: dict, name: str = "") -> str:
    session_id = uuid.uuid4().hex[:12]
    _SESSIONS[session_id] = {
        "path": path,
        "ext": ext,
        "name": name,
        "findings": findings,
        "secrets": secrets,
        "out_path": None,
        "intent": None,
    }
    return session_id


def get(session_id: str) -> Optional[dict]:
    return _SESSIONS.get(session_id)


def set_output(session_id: str, out_path: str, intent: str) -> None:
    sess = _SESSIONS.get(session_id)
    if sess is not None:
        # Each sanitize/re-apply produces a new NamedTemporaryFile(delete=False).
        # Unlink the previous one so repeated Re-apply doesn't leak temp files.
        old = sess.get("out_path")
        if old and old != out_path:
            try:
                os.unlink(old)
            except OSError:
                pass
        sess["out_path"] = out_path
        sess["intent"] = intent


def exists(session_id: str) -> bool:
    return session_id in _SESSIONS
