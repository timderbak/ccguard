"""Detached subprocess flusher for the PostToolUse audit buffer (TUA-02).

Per RESEARCH Pitfall #1: the flusher MUST be a separate process. The PostToolUse
hook process exits within ~20ms — a daemon thread inside the hook process would
be killed before any network I/O completes. We fork (Unix double-fork) or, on
platforms without ``os.fork``, fall back to ``subprocess.Popen`` with
``start_new_session=True`` so the flusher survives the hook process exit.

Trigger policy (``_should_spawn``):
  * row_count >= 50 (immediate flush; we batch), OR
  * no recent flush evidence (pidfile missing OR mtime > 30s ago).

Concurrency guard: a single pidfile at ``~/.ccguard/audit_flush.lock`` is the
sole signal that "a flusher is or just was running". If its mtime is < 5s old,
``maybe_spawn_flusher`` no-ops.

Flush loop (``_run_flush_loop``):
  * drain up to 200 rows, build :class:`AuditBatchIn`, POST to
    ``/api/v1/audit`` with ``X-CCGuard-Token`` header.
  * On 2xx → ``delete_ids``; on failure → exp backoff (1s, 2s, 4s) up to 3
    attempts, then give up. Rows that didn't drain stay in the buffer for the
    next invocation.
  * After successful loop → ``buffer.trim_to_cap(10_000)`` (T-01-03 DoS guard).
"""

from __future__ import annotations

import contextlib
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Final

from ccguard.agent.audit_hook.buffer import ToolBufferDB
from ccguard.agent.config import default_config_dir

_BATCH_THRESHOLD: Final[int] = 50
_TIME_THRESHOLD_S: Final[int] = 30
_LOCK_FRESH_S: Final[int] = 5
_MAX_BATCH: Final[int] = 200
_BACKOFF_SECONDS: Final[tuple[int, ...]] = (1, 2, 4)
_MAX_ATTEMPTS: Final[int] = 3
_HTTP_TIMEOUT_S: Final[float] = 10.0


def _lock_path() -> Path:
    return default_config_dir() / "audit_flush.lock"


def _buffer_path() -> Path:
    return default_config_dir() / "audit_buffer.db"


def _should_spawn(
    row_count: int,
    *,
    lock: Path | None = None,
    now: float | None = None,
) -> bool:
    """Decide whether to spawn a flusher right now.

    True if:
      - ``row_count >= _BATCH_THRESHOLD``, OR
      - lockfile is missing (no flusher has ever run, or it was cleaned), OR
      - lockfile's mtime is older than ``_TIME_THRESHOLD_S`` (stale).
    """
    p = lock if lock is not None else _lock_path()
    n = now if now is not None else time.time()
    if row_count >= _BATCH_THRESHOLD:
        return True
    if not p.exists():
        return True
    try:
        age = n - p.stat().st_mtime
    except OSError:
        return True
    return age > _TIME_THRESHOLD_S


def _acquire_lock(
    *,
    lock: Path | None = None,
    now: float | None = None,
) -> bool:
    """Atomic pidfile create. Returns False if a fresh (<5s) lock already exists.

    Uses ``os.open`` with ``O_CREAT|O_EXCL`` so that two concurrent PostToolUse
    hooks racing past :func:`_should_spawn` cannot both succeed in acquiring
    the lock (CR-01: TOCTOU race → duplicate flusher → duplicate server rows).
    A stale lock (mtime older than ``_LOCK_FRESH_S``) is unlinked before the
    exclusive create so recovery still works.
    """
    p = lock if lock is not None else _lock_path()
    n = now if now is not None else time.time()
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.exists():
        try:
            age = n - p.stat().st_mtime
        except OSError:
            age = float("inf")
        if age < _LOCK_FRESH_S:
            return False
        # Stale lock — remove before O_EXCL create. If unlink fails (e.g. a
        # concurrent process just took over), the O_EXCL below will reject us
        # cleanly.
        with contextlib.suppress(OSError):
            p.unlink()
    try:
        fd = os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except (FileExistsError, OSError):
        return False  # lost the race or filesystem error
    try:
        os.write(fd, str(os.getpid()).encode())
    finally:
        os.close(fd)
    return True


def _spawn_subprocess() -> None:
    """Fallback path (no ``os.fork``): launch a new session via Popen."""
    subprocess.Popen(  # noqa: S603 — args are static module path
        [sys.executable, "-m", "ccguard.agent.audit_hook.flusher_main"],
        start_new_session=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
    )


def _double_fork_and_run() -> None:
    """Unix double-fork → grandchild runs ``_run_flush_loop`` then exits.

    The intermediate child ``setsid``'s to detach the grandchild from the
    controlling tty of the original hook process. Parent (the hook) returns
    immediately so it can exit and let Claude Code proceed.
    """
    try:
        pid = os.fork()
    except OSError:
        # fork failed — fall back to subprocess path so we don't drop the batch.
        _spawn_subprocess()
        return
    if pid > 0:
        # Parent (hook process) reaps the intermediate child synchronously so
        # we don't leave a zombie — _exit of the intermediate is microseconds.
        with contextlib.suppress(OSError):
            os.waitpid(pid, 0)
        return
    # --- intermediate child ---
    with contextlib.suppress(OSError):
        os.setsid()
    try:
        pid2 = os.fork()
    except OSError:
        os._exit(0)
    if pid2 > 0:
        # Intermediate child exits immediately; grandchild is now orphaned
        # and adopted by init, fully detached from the hook process.
        os._exit(0)
    # --- grandchild ---
    try:
        # Detach stdio so the flusher's output never reaches Claude Code's tty.
        with open(os.devnull, "rb") as devnull_in:
            os.dup2(devnull_in.fileno(), 0)
        with open(os.devnull, "wb") as devnull_out:
            os.dup2(devnull_out.fileno(), 1)
            os.dup2(devnull_out.fileno(), 2)
        _run_flush_loop()
    except Exception:
        pass
    finally:
        os._exit(0)


def maybe_spawn_flusher(row_count_hint: int) -> None:
    """Spawn a detached flusher iff thresholds met and no fresh lock exists.

    Safe to call from the PostToolUse hot path — returns in <1ms when no spawn
    is needed, and in <5ms when forking (kernel work only; flush itself happens
    in the grandchild).
    """
    if not _should_spawn(row_count_hint):
        return
    if not _acquire_lock():
        return
    if hasattr(os, "fork"):
        _double_fork_and_run()
    else:
        _spawn_subprocess()


# --- flusher body -----------------------------------------------------------


def _run_flush_loop() -> None:
    """Drain buffer → POST batches → delete confirmed rows → trim cap.

    Imported lazily inside the function body so the hot path (hook_main) does
    NOT pay the import cost of httpx / pydantic / yaml at fingerprint time.
    """
    import httpx

    from ccguard.agent.config import load_or_create
    from ccguard.agent.machine_id import derive_machine_id
    from ccguard.schemas.tool_use import (
        SCHEMA_VERSION_AUDIT,
        AuditBatchIn,
        ToolUseEventIn,
    )

    cfg, _ = load_or_create()
    server_url = cfg.server.url.rstrip("/")
    token = cfg.server.token
    machine_id = derive_machine_id(cfg.install_salt)

    headers = {
        "X-CCGuard-Token": token,
        "Content-Type": "application/json",
    }
    url = f"{server_url}/api/v1/audit"

    attempts = 0
    with ToolBufferDB(_buffer_path()) as buf:
        while buf.row_count() > 0 and attempts < _MAX_ATTEMPTS:
            rows = buf.drain(_MAX_BATCH)
            if not rows:
                break
            try:
                events = [
                    ToolUseEventIn(
                        ts=r["ts"],  # type: ignore[arg-type]  # pydantic parses ISO-8601 string
                        tool_name=r["tool_name"],
                        fingerprint=r["fingerprint"],
                        decision=r["decision"],  # type: ignore[arg-type]
                        result_status=r["result_status"],  # type: ignore[arg-type]
                    )
                    for r in rows
                ]
                batch = AuditBatchIn(
                    schema_version=SCHEMA_VERSION_AUDIT,
                    machine_id=machine_id,
                    events=events,
                )
            except Exception:
                # Malformed row(s) in the buffer — drop them so they don't wedge
                # the flusher forever. Better to lose a few events than block.
                buf.delete_ids([r["id"] for r in rows])
                continue

            try:
                with httpx.Client(timeout=_HTTP_TIMEOUT_S) as client:
                    resp = client.post(
                        url,
                        content=batch.model_dump_json(),
                        headers=headers,
                    )
                if 200 <= resp.status_code < 300:
                    buf.delete_ids([r["id"] for r in rows])
                    attempts = 0  # reset on success
                    continue
                raise RuntimeError(f"audit POST returned {resp.status_code}")
            except Exception:
                attempts += 1
                if attempts >= _MAX_ATTEMPTS:
                    break
                time.sleep(_BACKOFF_SECONDS[attempts - 1])

        # Cap-enforce regardless of attempt outcome.
        buf.trim_to_cap(10_000)
