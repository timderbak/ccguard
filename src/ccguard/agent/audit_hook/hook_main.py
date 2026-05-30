"""PostToolUse hook stdin parser + dispatcher (TUA-01).

Hot-path budget: <20ms wall-clock per invocation. To stay under budget we:

1. Parse stdin with stdlib ``json`` (no pydantic on the hook hot-path).
2. Compute the 16-hex fingerprint and **immediately drop the raw tool_input
   local** (``del tool_input``) — privacy intent made explicit (T-01-07).
3. INSERT one row into the local SQLite buffer (BEGIN IMMEDIATE; <5ms typical).
4. Hand off to :func:`maybe_spawn_flusher` which forks/spawns a detached
   subprocess. The hook itself never makes a network call.

Failure model: the entire body is wrapped in ``try/except Exception: return 0``.
A malformed stdin, an unwritable buffer, or any other failure surfaces as a
no-op fail-open — Claude Code's tool use is NEVER blocked by an audit failure
(T-01-05).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from ccguard.agent.audit_hook.buffer import ToolBufferDB
from ccguard.agent.audit_hook.fingerprint import compute_fingerprint
from ccguard.agent.audit_hook.flusher import maybe_spawn_flusher
from ccguard.agent.config import default_config_dir
from ccguard.agent.signals import extract_signals


def _result_status_from_response(
    tool_response: dict[str, Any],
) -> str:
    """Derive ``result_status`` from PostToolUse ``tool_response`` payload.

    Order is significant: an explicit error trumps an interrupt flag.
    """
    if tool_response.get("error") or tool_response.get("success") is False:
        return "error"
    if tool_response.get("interrupted"):
        return "blocked"
    return "success"


def main_cli(stdin_text: str | None = None) -> int:
    """Read PostToolUse stdin → fingerprint → buffer.insert → maybe_spawn_flusher.

    Always returns 0. Any internal failure is swallowed (fail-open).
    """
    try:
        if stdin_text is None:
            import sys

            stdin_text = sys.stdin.read()

        # 1. Parse — tolerate malformed JSON without raising.
        try:
            data = json.loads(stdin_text) if stdin_text.strip() else {}
        except json.JSONDecodeError:
            return 0
        if not isinstance(data, dict):
            return 0

        tool_name = data.get("tool_name") or "(unknown)"
        if not isinstance(tool_name, str):
            tool_name = "(unknown)"

        tool_input = data.get("tool_input") or {}
        if not isinstance(tool_input, dict):
            tool_input = {}

        tool_response = data.get("tool_response") or {}
        if not isinstance(tool_response, dict):
            tool_response = {}

        # 2. Fingerprint + extract signals, THEN drop raw tool_input (privacy
        #    invariant). Both consume the raw input in-process; only the 16-hex
        #    fingerprint and the signal IDs survive this scope.
        fp = compute_fingerprint(tool_name, tool_input)
        signals = extract_signals(tool_name, tool_input)
        del tool_input  # explicit — only `fp` + `signals` survive.

        # 3. Build event fields.
        ts = datetime.now(UTC).isoformat()
        decision = "allow"  # PostToolUse fires only after PreToolUse permitted.
        result_status = _result_status_from_response(tool_response)

        # 4. INSERT into buffer; capture row_count for flush-threshold check.
        buffer_path = default_config_dir() / "audit_buffer.db"
        with ToolBufferDB(buffer_path) as buf:
            buf.insert(
                ts=ts,
                tool_name=tool_name,
                fingerprint=fp,
                decision=decision,
                result_status=result_status,
                signals=signals,
            )
            row_count = buf.row_count()

        # 5. Maybe spawn detached flusher (outside CM — connection closed before fork).
        maybe_spawn_flusher(row_count_hint=row_count)
        return 0
    except Exception:
        # Fail-open: never propagate any error back to Claude Code.
        return 0
