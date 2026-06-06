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

from ccguard.agent.signals.catalog import ACTION_SIGNAL_IDS, CATALOG, Signal

# Tools whose tool_input carries a filesystem path we want to inspect.
_PATH_TOOLS = frozenset({"Read", "Write", "Edit", "MultiEdit", "NotebookEdit"})

# Tools that WRITE to disk — the staging middle link (ТЗ-02). MultiEdit is a
# write too; included so an edit-burst to a hidden path is not a blind spot.
_WRITE_TOOLS = frozenset({"Write", "Edit", "MultiEdit", "NotebookEdit"})

# Temp/cache roots treated as suspicious staging locations even without a
# dotfile component in the path.
_TEMP_PREFIXES = ("/tmp/", "/var/tmp/", "/private/tmp/", "/private/var/tmp/")

# ТЗ-03: tools whose result is, by construction, external/untrusted content.
_EXTERNAL_CONTENT_TOOLS = frozenset({"WebFetch", "WebSearch"})

# ТЗ-03: a Read whose target sits under one of these path components is reading
# untrusted/external content (downloads, package caches, vendored deps) — as
# opposed to first-party project source. Single source of truth, easy to extend.
# Matched component-wise on the (lowercased) path, so case/parent dirs don't
# matter; temp roots are matched via ``_TEMP_PREFIXES``.
_UNTRUSTED_READ_COMPONENTS = frozenset(
    {"downloads", "node_modules", "site-packages", ".cache", ".cargo", ".npm"}
)

# ТЗ-04: write-target path components that mark a benign build/package CACHE.
# A write here is overwhelmingly build noise (npm/pip/cargo/pytest), allowlisted
# downstream. Single source of truth. NOTE: deliberately excludes /tmp and
# ~/Downloads — attackers stage there, so those stay detected.
_CACHE_WRITE_COMPONENTS = frozenset(
    {
        "node_modules",
        "site-packages",
        "__pycache__",
        ".cache",
        ".cargo",
        ".npm",
        ".pytest_cache",
        ".mypy_cache",
        ".tox",
    }
)
# A write into a VCS internal dir (git plumbing) — also benign build noise.
_VCS_WRITE_COMPONENTS = frozenset({".git"})


def _write_category_marker(file_path: str) -> str | None:
    """Return a benign-category marker for a write target, or None.

    ``fs.write.cache`` for package/build caches, ``fs.write.vcs`` for VCS dirs.
    Component-wise match on the lowercased path. Returns only a CATEGORY, never
    the path (privacy). Unusual hidden dirs (.ssh/.aws/.config) return None and
    stay fully detected.
    """
    comps = {c for c in file_path.lower().split("/") if c}
    if comps & _VCS_WRITE_COMPONENTS:
        return "fs.write.vcs"
    if comps & _CACHE_WRITE_COMPONENTS:
        return "fs.write.cache"
    return None


def _is_untrusted_read_path(file_path: str) -> bool:
    """True if a Read target is an external/untrusted source, not project source.

    Temp roots (``/tmp``…) or any path component in
    ``_UNTRUSTED_READ_COMPONENTS``. Ordinary project paths return False — the
    precision-over-coverage rule (ТЗ-03 §1): never flag first-party reads.
    """
    p = file_path.lower()
    if p.startswith(_TEMP_PREFIXES):
        return True
    return bool({c for c in p.split("/") if c} & _UNTRUSTED_READ_COMPONENTS)


def _external_content_signals(tool_name: str, tool_input: dict[str, Any]) -> list[str]:
    """Tool-gated external-content signal (ТЗ-03).

    WebFetch/WebSearch results are always external. A Read is external only when
    its ``file_path`` is an untrusted location. MCP results from arbitrary
    servers are NOT covered here — their externalness is not observable from the
    hook payload (TODO: a future ТЗ once server provenance is available).
    """
    if tool_name in _EXTERNAL_CONTENT_TOOLS:
        return ["content.read.external"]
    if tool_name == "Read":
        fp = tool_input.get("file_path")
        if isinstance(fp, str) and fp and _is_untrusted_read_path(fp):
            return ["content.read.external"]
    return []


def _is_hidden_path(file_path: str) -> bool:
    """True if the write target is a hidden or temp/unusual location.

    Hidden = any path component starts with ``.`` (``.cache/``, ``.ssh/``,
    dot-files), excluding the ``.``/``..`` navigation components. Temp = under a
    well-known scratch root. Used only to rate a write's staging-suspiciousness.
    """
    p = file_path.lower()
    if p.startswith(_TEMP_PREFIXES):
        return True
    for comp in file_path.split("/"):
        if comp in ("", ".", ".."):
            continue
        if comp.startswith("."):
            return True
    return False


def _write_signals(tool_name: str, tool_input: dict[str, Any]) -> list[str]:
    """Tool-gated staging-write signal (ТЗ-02).

    Emitted ONLY for write tools, decided by the target path shape — never via
    the content-regex loop, so a Read of a hidden path is never mistaken for a
    write. Missing/non-str ``file_path`` → no signal (fail-quiet).
    """
    if tool_name not in _WRITE_TOOLS:
        return []
    fp = tool_input.get("file_path")
    if not isinstance(fp, str) or not fp:
        return []
    out = ["fs.write.hidden"] if _is_hidden_path(fp) else ["fs.write.normal"]
    # ТЗ-04: append a benign-category marker (cache/vcs) alongside the base
    # signal so the staging orchestrator can allowlist build noise.
    marker = _write_category_marker(fp)
    if marker is not None:
        out.append(marker)
    return out


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
        # Action signals (fs.write.* / content.read.external) are tool-gated,
        # decided independently of the content-regex loop. Computed first so they
        # survive even when the normalized text is empty (e.g. WebFetch).
        out = _write_signals(tool_name, tool_input)
        out.extend(_external_content_signals(tool_name, tool_input))
        text = _normalized_text(tool_name, tool_input)
        if text.strip():
            active = _build_active_catalog(overrides)
            out.extend(
                s.id
                for s in active
                if s.id not in ACTION_SIGNAL_IDS and s.pattern.search(text)
            )
        return out
    except Exception:
        return []
