"""Prompt-injection scanning for files read via Claude's Read tool.

Used by two distinct hot paths:

* **PostToolUse** (``audit_hook.hook_main``) — scans the ``tool_response``
  content that Claude *just* read. Cannot block (too late) but emits a
  ``prompt_injection.read_file.*`` finding so admin sees a suspicious file
  was opened. Always-on, fail-open.
* **PreToolUse** (``enforce``) — opt-in via ``PromptInjectionConfig.read_pi_block``.
  Reads the same file from disk BEFORE Claude does, scans, and denies the
  Read call if PI markers found. Trades a small disk-read on the hot path
  for the ability to actually block.

Shared rules:

* Cap content at ``_MAX_BYTES`` (50 KB) — regex on a 5 MB README would
  blow the hook latency budget. PI engine already has ReDoS protection.
* Skip non-text extensions (PNG/JPG/PDF/binary) — they cannot carry
  text-shaped injection AND Reading them is rare-by-design.
* Use the default catalog only (no LlamaGuard) — deep scan in PostToolUse
  is wasted (cannot block) and in PreToolUse blows the 100ms SLA.
"""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

from ccguard.agent.prompt_injection_engine import ScanResult
from ccguard.agent.prompt_injection_engine import scan as pi_scan

if TYPE_CHECKING:
    # Только для аннотаций — импорт schemas.policy тянет pydantic (~200мс), а
    # этот модуль на горячем пути enforce. В рантайме cfg приходит как
    # FastPolicy-узел (атрибут-доступ).
    from ccguard.schemas.policy import PromptInjectionConfig

# 50 KB cap — large enough for any reasonable README/issue/instruction file,
# small enough to keep regex on the order of a few ms.
_MAX_BYTES = 50 * 1024

# Skip these extensions silently — they cannot meaningfully carry an
# instruction-shaped injection that Claude would interpret. Lowercased.
_SKIP_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".bmp",
        ".ico",
        ".pdf",
        ".zip",
        ".gz",
        ".bz2",
        ".xz",
        ".tar",
        ".7z",
        ".rar",
        ".so",
        ".dylib",
        ".dll",
        ".exe",
        ".bin",
        ".class",
        ".jar",
        ".pyc",
        ".woff",
        ".woff2",
        ".ttf",
        ".otf",
        ".mp3",
        ".mp4",
        ".wav",
        ".mov",
        ".avi",
    }
)


def is_scannable_path(path: str | os.PathLike[str]) -> bool:
    """Return ``False`` for paths with binary-ish extensions.

    Cheap pre-filter to avoid wasting hot-path budget on non-text files.
    A user who Reads a .pdf via Claude is rare; if it happens we just
    don't scan — the file content is binary noise anyway.
    """
    suffix = Path(str(path)).suffix.lower()
    return suffix not in _SKIP_EXTENSIONS


def extract_read_response_text(tool_response: Any) -> str:
    """Pull a text string out of a PostToolUse ``tool_response`` payload.

    Claude Code emits Read responses in two shapes seen in the wild:

    * ``{"content": "<file text>", ...}`` — dict envelope
    * ``"<file text>"`` — bare string (older client versions)

    Anything else (None, list, int) → empty string. Non-fatal — the caller
    just gets no text to scan.
    """
    if isinstance(tool_response, str):
        return tool_response
    if isinstance(tool_response, dict):
        raw = tool_response.get("content")
        if isinstance(raw, str):
            return raw
        # MCP shape: content is a list of {type:"text", text:"..."} blocks.
        if isinstance(raw, list):
            parts = [b.get("text") for b in raw if isinstance(b, dict) and isinstance(b.get("text"), str)]
            if parts:
                return "\n".join(parts)
        # Some clients nest under "result"/"text"; tolerate both.
        for key in ("result", "text", "output"):
            v = tool_response.get(key)
            if isinstance(v, str):
                return v
    # Top-level list of MCP content blocks (no dict envelope).
    if isinstance(tool_response, list):
        parts = [b.get("text") for b in tool_response if isinstance(b, dict) and isinstance(b.get("text"), str)]
        if parts:
            return "\n".join(parts)
    return ""


def read_file_truncated(file_path: str | os.PathLike[str]) -> str | None:
    """Read up to ``_MAX_BYTES`` from ``file_path`` as UTF-8 (errors=replace).

    Returns ``None`` if the file does not exist, is not a regular file, is
    unreadable (perms), or has a binary extension. Errors are swallowed —
    the caller treats ``None`` as "skip silently".
    """
    p = Path(str(file_path))
    if not is_scannable_path(p):
        return None
    try:
        if not p.is_file():
            return None
        with p.open("rb") as fh:
            raw = fh.read(_MAX_BYTES)
    except OSError:
        return None
    try:
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return None


def _scan_only_default_catalog(text: str, cfg: PromptInjectionConfig) -> ScanResult | None:
    """Run the PI engine without LlamaGuard regardless of cfg.

    Force-disable LlamaGuard for Read-tool scans:
    * PostToolUse — deep scan is useless (cannot block).
    * PreToolUse — deep scan blows the 100ms SLA on every Read.
    The user can still enable LlamaGuard for the PreToolUse injection check
    on Bash/MCP tool inputs; that's a separate code path.
    """
    if not cfg.enabled or not text:
        return None
    # Клон cfg с принудительно выключенным LlamaGuard. Лёгкий объект вместо
    # pydantic-модели: движок читает поля через атрибут-доступ, а конструировать
    # pydantic на горячем пути — те самые ~200мс, которые мы и убираем.
    scan_cfg = SimpleNamespace(
        enabled=True,
        severity=cfg.severity,
        regex_patterns=list(cfg.regex_patterns),
        allowlist_patterns=list(cfg.allowlist_patterns),
        llama_guard=SimpleNamespace(enabled=False),
    )
    try:
        return pi_scan(text, scan_cfg)
    except Exception:
        # Engine crash → treat as no-finding for the Read path. Engine-error
        # bookkeeping is handled by the PreToolUse Bash/MCP path elsewhere.
        return None


def scan_read_text(text: str, cfg: PromptInjectionConfig) -> ScanResult | None:
    """Truncate ``text`` to ``_MAX_BYTES`` chars then scan with default catalog.

    Cap is char-based (post-decode) rather than byte-based to keep the API
    simple — 50 KB of UTF-8 is at most 50K codepoints worst case in BMP.
    """
    if not text:
        return None
    truncated = text[:_MAX_BYTES]
    return _scan_only_default_catalog(truncated, cfg)


def build_rule_id(scan_result: ScanResult) -> str:
    """Map a generic ``prompt_injection.<category>`` rule_id to the Read-tool
    namespace ``prompt_injection.read_file.<category>``.

    The Read-tool namespace lets the server UI / services filter
    `prompt_injection.read_file.*` independently from PreToolUse injection
    findings on Bash/MCP inputs.
    """
    base = scan_result.rule_id
    # Strip the leading "prompt_injection." prefix if present and re-namespace.
    if base.startswith("prompt_injection."):
        rest = base[len("prompt_injection.") :]
        return f"prompt_injection.read_file.{rest}"
    # Fallback for unexpected shapes (admin custom, etc).
    return f"prompt_injection.read_file.{scan_result.category}"
