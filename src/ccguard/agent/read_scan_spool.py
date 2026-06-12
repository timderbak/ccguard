"""On-disk spool for read-content awaiting the LLM backstop (P5).

PostToolUse runs on a <20ms hot-path budget and must never make a network
call, so it cannot ship suspicious read content to the server inline. Instead
it drops the content here; the next inventory ``sync`` cycle drains the spool
and ships it via the existing ``/scan-content`` batch (scope=read_file).

Design choices:

* **Directory of files, not SQLite** — each spool entry is its own file named
  by the sha256 of its (masked) content, so concurrent PostToolUse processes
  never contend on a lock and identical content read twice collapses to one
  entry (the server also de-dupes by hash, this just saves an upload).
* **Masked + capped at write time** — content runs through ``mask_content`` and
  is truncated to the server's 100 KiB soft cap before it ever touches disk.
* **Username-scrubbed path** — the read path can be anywhere on the dev box;
  the leading home segment (which leaks the OS username) is scrubbed to ``~``.
* **Bounded** — at most ``_MAX_SPOOL_FILES`` entries; once full, new entries are
  dropped (fail-open) so a read-heavy session cannot fill the disk.

Every function is best-effort and never raises into the caller.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from pathlib import Path

from ccguard.agent.config import default_config_dir
from ccguard.agent.masking import mask_content

logger = logging.getLogger("ccguard.agent.read_scan_spool")

# Server soft cap is 100 KiB (it truncates above this); cap here so we never
# spool more than the server will scan.
_MAX_CONTENT_BYTES = 100 * 1024
# Bound the spool so a pathological session cannot fill the disk. Older entries
# are not evicted — once full we simply stop accepting new ones until a sync
# cycle drains it.
_MAX_SPOOL_FILES = 64

_SPOOL_DIRNAME = "read_scan_spool"

# Scrub a leading home segment that leaks the OS username:
#   /Users/<name>/...      (macOS)
#   /home/<name>/...       (Linux)
#   C:\Users\<name>\...    (Windows)
_HOME_POSIX = re.compile(r"^/(?:Users|home)/[^/]+/")
_HOME_WIN = re.compile(r"^[A-Za-z]:\\Users\\[^\\]+\\", re.IGNORECASE)


def spool_dir() -> Path:
    """Directory holding pending read-scan entries (created on demand)."""
    return default_config_dir() / _SPOOL_DIRNAME


def scrub_read_path(file_path: str) -> str:
    """Replace the home segment of an absolute read path with ``~/``.

    Keeps project/file structure (useful classifier context) but removes the
    OS username. Non-absolute or unrecognized paths are returned unchanged.
    """
    if not file_path:
        return file_path
    p = _HOME_POSIX.sub("~/", file_path)
    if p != file_path:
        return p
    return _HOME_WIN.sub("~/", file_path)


def spool(file_path: str, content: str) -> bool:
    """Persist one suspicious read for later LLM scanning. Returns True if written.

    Best-effort: any error (permissions, full spool, masking) returns False
    without raising. Content is masked + truncated; the entry is keyed by the
    masked content hash so duplicate reads coalesce.
    """
    try:
        if not content:
            return False
        masked = mask_content(content)
        encoded = masked.encode("utf-8", errors="replace")
        if len(encoded) > _MAX_CONTENT_BYTES:
            masked = encoded[:_MAX_CONTENT_BYTES].decode("utf-8", errors="replace")
        d = spool_dir()
        d.mkdir(parents=True, exist_ok=True)
        # Cap check — count existing entries; drop if full.
        existing = [p for p in d.iterdir() if p.suffix == ".json"]
        digest = hashlib.sha256(masked.encode("utf-8")).hexdigest()[:16]
        target = d / f"{digest}.json"
        if target.exists():
            return True  # identical content already queued — idempotent
        if len(existing) >= _MAX_SPOOL_FILES:
            logger.debug("read_scan_spool: full (%d); dropping entry", len(existing))
            return False
        payload = {"file_path": scrub_read_path(file_path), "content": masked}
        # Atomic write: temp in same dir + os.replace.
        tmp = d / f".{digest}.{os.getpid()}.tmp"
        tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, target)
        return True
    except Exception:  # noqa: BLE001 — spool must never break the audit hook
        return False


def drain(max_items: int = 50) -> list[tuple[str, str, Path]]:
    """Return up to ``max_items`` pending entries as ``(file_path, content, path)``.

    Does NOT delete — the caller deletes via :func:`delete` only after a
    successful upload so a failed sync re-ships next cycle. Unreadable / corrupt
    entries are deleted in place (they would never ship) and skipped.
    """
    out: list[tuple[str, str, Path]] = []
    try:
        d = spool_dir()
        if not d.is_dir():
            return out
        for path in sorted(d.iterdir()):
            if path.suffix != ".json":
                continue
            if len(out) >= max_items:
                break
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                fp = str(data.get("file_path", ""))
                content = data.get("content")
                if not isinstance(content, str) or not content:
                    raise ValueError("empty content")
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                # Corrupt entry — remove so it cannot wedge the spool.
                try:
                    path.unlink()
                except OSError:
                    pass
                continue
            out.append((fp, content, path))
    except Exception:  # noqa: BLE001
        return out
    return out


def delete(paths: list[Path]) -> None:
    """Remove drained entries after a successful upload. Errors ignored."""
    for p in paths:
        try:
            p.unlink()
        except OSError:
            pass


__all__ = ["spool", "drain", "delete", "spool_dir", "scrub_read_path"]
