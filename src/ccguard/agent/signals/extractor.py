"""Per-event signal extraction entry point (Behavioral Detection, Stage 1).

``extract_signals`` is called on the PostToolUse hot path BEFORE the raw
``tool_input`` is discarded. It returns a list of catalog signal IDs and never
raises — any failure yields ``[]`` (fail-open, mirroring the audit hook).

E4 adds server-pushed ``overrides`` — a list of {id, attack_technique, pattern,
description} dicts coming from the policy sync. Overrides with the same id as
a baked CATALOG signal REPLACE the baked entry (admin can hotfix a noisy
regex without a redeploy). Malformed override regexes are silently dropped.
"""
from __future__ import annotations

import re
from typing import Any, Iterable

from ccguard.agent.signals.catalog import CATALOG, Signal

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


def _build_active_catalog(
    overrides: Iterable[dict[str, Any]] | None,
) -> list[Signal]:
    """Merge baked CATALOG with server overrides.

    Overrides with the same ``id`` as a baked signal REPLACE the baked entry.
    New-id overrides are appended. Malformed entries (bad shape, regex that
    doesn't compile) are silently dropped — the admin's approve gate already
    re-compiled them, so this is defense in depth.
    """
    if not overrides:
        return list(CATALOG)
    out_by_id: dict[str, Signal] = {s.id: s for s in CATALOG}
    for entry in overrides:
        if not isinstance(entry, dict):
            continue
        sid = entry.get("id")
        pat = entry.get("pattern")
        atk = entry.get("attack_technique")
        desc = entry.get("description")
        if not all(isinstance(x, str) and x for x in (sid, pat, atk, desc)):
            continue
        try:
            compiled = re.compile(pat, re.IGNORECASE)
        except re.error:
            continue
        out_by_id[sid] = Signal(  # type: ignore[arg-type]
            id=sid,
            attack_technique=atk,
            pattern=compiled,
            description=desc,
        )
    return list(out_by_id.values())


def extract_signals(
    tool_name: str,
    tool_input: dict[str, Any],
    *,
    overrides: Iterable[dict[str, Any]] | None = None,
) -> list[str]:
    """Return the IDs of every catalog signal that matches this invocation.

    Order follows the (possibly merged) catalog. Returns ``[]`` on any error
    or when nothing matches. NEVER returns raw input — only signal IDs.

    ``overrides`` is the server-pushed catalog extension (E4). Each entry is
    a dict of {id, attack_technique, pattern, description}. Same-id entries
    take precedence over the baked CATALOG.
    """
    try:
        if not isinstance(tool_input, dict):
            return []
        text = _normalized_text(tool_name, tool_input)
        if not text.strip():
            return []
        active = _build_active_catalog(overrides)
        return [s.id for s in active if s.pattern.search(text)]
    except Exception:
        return []
