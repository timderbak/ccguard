"""Deterministic, privacy-preserving fingerprinting for tool-use audit (TUA-01).

The fingerprint is a 16-character hex digest of ``sha256(tool_name + ":" + token)``.
The `token` is derived from `tool_input` via per-tool normalization rules:

* Bash: first command before any pipe / `&&` / `||` / `;` / `&`, with flags and
  leading ``KEY=VALUE`` env-assignments stripped. Uses ``shlex`` so semicolons
  inside quoted strings are NOT treated as command separators.
* Edit / Write / Read / MultiEdit / NotebookEdit: ``os.path.basename`` of
  ``file_path`` (or ``notebook_path``). Full path is never hashed — privacy.
* Everything else (Task, Glob, Grep, WebFetch, WebSearch, ``mcp__*``, …):
  empty token. Fingerprint depends on ``tool_name`` only — `tool_input`
  content is intentionally ignored.

**Critical privacy invariant** (T-01-01): the raw `tool_input` value flows into
``hashlib.sha256`` only. It is NEVER returned, logged, printed, or stored.
The return value of :func:`compute_fingerprint` is exactly 16 hex characters and
contains no recoverable information about the original input beyond
grouping-equivalence.
"""

from __future__ import annotations

import hashlib
import os
import shlex
from typing import Any

_BASH_BREAKERS: frozenset[str] = frozenset({"|", "||", "&&", ";", "&"})

_FILE_TOOLS: frozenset[str] = frozenset(
    {"Edit", "Write", "Read", "MultiEdit", "NotebookEdit"}
)


def _normalize_bash(command: str) -> str:
    """Extract the leading program token from a bash command line.

    Drops flags, drops leading ``KEY=VALUE`` env-assignments, stops at the
    first shell control operator (``|``, ``||``, ``&&``, ``;``, ``&``).

    Malformed quoting falls back to a whitespace split rather than raising.
    """
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        tokens = command.split()

    head: list[str] = []
    for t in tokens:
        if t in _BASH_BREAKERS:
            break
        if t.startswith("-"):
            continue
        # Drop leading `KEY=VALUE` env assignments before the program name.
        if not head and "=" in t:
            key = t.split("=", 1)[0]
            if key.isidentifier():
                continue
        head.append(t)
        # Program token captured — done.
        if len(head) == 1:
            break

    if head:
        return " ".join(head)
    # Nothing extractable (e.g. command was just `&&` or empty after stripping).
    return command.strip()[:64]


def _normalize_token(tool_name: str, tool_input: dict[str, Any]) -> str:
    """Per-tool token extraction. Never returns raw tool_input content."""
    if tool_name == "Bash":
        return _normalize_bash(str(tool_input.get("command", "")))
    if tool_name in _FILE_TOOLS:
        path = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
        if not path:
            return ""
        return os.path.basename(str(path))
    # Task, Glob, Grep, WebFetch, WebSearch, all `mcp__*`, anything unknown:
    # fingerprint by tool_name only. We deliberately do NOT look at tool_input.
    return ""


def compute_fingerprint(tool_name: str, tool_input: dict[str, Any]) -> str:
    """Compute the 16-hex-char audit fingerprint for a tool invocation.

    The return value is exactly 16 characters from ``[0-9a-f]`` and is a
    deterministic function of ``tool_name`` and the per-tool normalized
    token. The raw ``tool_input`` dictionary is never returned, logged, or
    otherwise exposed — see module docstring for privacy invariant.
    """
    token = _normalize_token(tool_name, tool_input)
    raw = f"{tool_name}:{token}".encode()
    return hashlib.sha256(raw).hexdigest()[:16]
