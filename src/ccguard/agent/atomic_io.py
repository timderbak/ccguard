"""Atomic file-write helper for the ccguard agent.

POSIX-only by project design (no Windows special-case): uses
`tempfile.NamedTemporaryFile` in the same directory as the target and
`os.replace` for the atomic rename. The temp file is cleaned up on any
failure to leave the parent directory free of `.ccguard-tmp-*` leftovers.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

__all__ = ["atomic_write_bytes"]

_TMP_PREFIX = ".ccguard-tmp-"


def atomic_write_bytes(path: Path, data: bytes, *, mode: int = 0o644) -> None:
    """Atomically write `data` to `path`.

    - Creates `path.parent` if missing.
    - Writes via NamedTemporaryFile in `path.parent` (same filesystem so the
      `os.replace` is atomic).
    - fsync + close + os.replace.
    - On any exception the temp file is unlinked silently.
    - Final file permissions are set EXACTLY to ``mode`` via ``os.chmod`` —
      this is NOT umask-respecting. Default is ``0o644`` (preserves prior
      behavior for caller sites that produce non-sensitive content). Callers
      writing files that may contain secrets (e.g. ``~/.claude.json`` whose
      ``mcpServers[*].env`` carries admin-supplied API keys) MUST pass
      ``mode=0o600`` — see CR-02 (Phase 4 review).

    POSIX-only by project constraint — no Windows fallback path.
    """
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)

    tmp = tempfile.NamedTemporaryFile(
        mode="wb",
        dir=parent,
        delete=False,
        prefix=_TMP_PREFIX,
    )
    tmp_path = tmp.name
    try:
        try:
            tmp.write(data)
            tmp.flush()
            os.fsync(tmp.fileno())
        finally:
            tmp.close()
        # Set mode EXACTLY (not umask-respecting). Default 0o644; secrets-
        # bearing files MUST pass mode=0o600 from the call site.
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass
        raise
