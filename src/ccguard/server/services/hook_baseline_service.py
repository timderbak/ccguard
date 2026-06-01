"""TOFU baseline + drift detection for Claude Code hooks.

Sibling of :mod:`ccguard.server.services.mcp_baseline_service`; same overall
pattern (composite fingerprint, slot-based lookup, accept-flow), different
identity composition.

Design: ``docs/superpowers/specs/2026-06-01-hooks-tofu-baseline-design.md``
"""

from __future__ import annotations

import hashlib

# Sentinel that lets us distinguish "no file content hash (couldn't read /
# inline command)" from "explicit empty content hash". The empty-string case
# is reserved for inline shell commands; None means we have no information.
_NONE_SENTINEL = "\x00NONE\x00"


def compute_fingerprint(
    event_name: str,
    matcher: str,
    command_string: str,
    file_content_hash: str | None,
) -> str:
    """Composite sha256 hex (64 chars).

    Four pipe-separated components: event_name, matcher, command_string,
    and either the file_content_hash or a sentinel meaning "no hash available".

    The sentinel makes None and "" distinct so an inline ``bash -c`` hook
    (file_content_hash == "" by convention) won't share a fingerprint with
    a hook whose shim couldn't be read (file_content_hash is None).
    """
    fh = _NONE_SENTINEL if file_content_hash is None else file_content_hash
    raw = f"{event_name}|{matcher}|{command_string}|{fh}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()
