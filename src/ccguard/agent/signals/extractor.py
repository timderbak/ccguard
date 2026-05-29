"""Per-event signal extraction entry point (Behavioral Detection, Stage 1).

``extract_signals`` is called on the PostToolUse hot path BEFORE the raw
``tool_input`` is discarded. It returns a list of catalog signal IDs and never
raises — any failure yields ``[]`` (fail-open, mirroring the audit hook).
"""
from __future__ import annotations

from typing import Any

from ccguard.agent.signals.catalog import CATALOG

# Tools whose tool_input carries a filesystem path we want to inspect.
_PATH_TOOLS = frozenset({"Read", "Write", "Edit", "MultiEdit", "NotebookEdit"})


def _normalized_text(tool_name: str, tool_input: dict[str, Any]) -> str:
    """Build a single lowercased text view of the invocation.

    Combines the Bash ``command`` and any file ``file_path`` so a single set of
    regexes covers both "ran a command touching X" and "edited file X".
    """
    parts: list[str] = []
    cmd = tool_input.get("command")
    if isinstance(cmd, str):
        parts.append(cmd)
    if tool_name in _PATH_TOOLS:
        fp = tool_input.get("file_path")
        if isinstance(fp, str):
            parts.append(fp)
    return "\n".join(parts).lower()


def extract_signals(tool_name: str, tool_input: dict[str, Any]) -> list[str]:
    """Return the IDs of every catalog signal that matches this invocation.

    Order follows ``CATALOG`` (stable). Returns ``[]`` on any error or when
    nothing matches. NEVER returns raw input — only signal IDs.
    """
    try:
        if not isinstance(tool_input, dict):
            return []
        text = _normalized_text(tool_name, tool_input)
        if not text.strip():
            return []
        return [s.id for s in CATALOG if s.pattern.search(text)]
    except Exception:
        return []
