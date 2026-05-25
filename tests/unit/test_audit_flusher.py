"""Detached flusher: spawn gating, lockfile, drain → POST → delete loop."""

from __future__ import annotations

import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest

from ccguard.agent.audit_hook import flusher
from ccguard.agent.audit_hook.buffer import ToolBufferDB


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    cc_home = tmp_path / ".ccguard"
    cc_home.mkdir()
    monkeypatch.setenv("CCGUARD_AGENT_HOME", str(cc_home))
    monkeypatch.setenv("HOME", str(tmp_path))
    return cc_home


# --- _should_spawn ----------------------------------------------------------


def test_should_spawn_threshold_met(_isolated_home: Path) -> None:
    assert flusher._should_spawn(row_count=100) is True


def test_should_spawn_no_lock_present(_isolated_home: Path) -> None:
    assert flusher._should_spawn(row_count=5) is True


def test_should_spawn_false_when_under_threshold_and_lock_fresh(
    _isolated_home: Path,
) -> None:
    lock = _isolated_home / "audit_flush.lock"
    lock.write_text("123")
    # mtime is "now"; below threshold and below 30s → False.
    assert flusher._should_spawn(row_count=10, now=time.time()) is False


def test_should_spawn_true_when_lock_is_stale(_isolated_home: Path) -> None:
    lock = _isolated_home / "audit_flush.lock"
    lock.write_text("123")
    # Force mtime older than 30s.
    old = time.time() - 120
    import os as _os

    _os.utime(lock, (old, old))
    assert flusher._should_spawn(row_count=10, now=time.time()) is True


def test_should_spawn_true_when_count_at_exactly_threshold(_isolated_home: Path) -> None:
    lock = _isolated_home / "audit_flush.lock"
    lock.write_text("123")  # fresh
    assert flusher._should_spawn(row_count=50, now=time.time()) is True


# --- _acquire_lock ----------------------------------------------------------


def test_acquire_lock_creates_pidfile(_isolated_home: Path) -> None:
    lock = _isolated_home / "audit_flush.lock"
    assert flusher._acquire_lock() is True
    assert lock.exists()
    assert lock.read_text().isdigit()


def test_acquire_lock_refuses_when_fresh(_isolated_home: Path) -> None:
    lock = _isolated_home / "audit_flush.lock"
    lock.write_text("999")
    # Just-written lock is fresh (<5s).
    assert flusher._acquire_lock() is False


def test_acquire_lock_overrides_stale(_isolated_home: Path) -> None:
    lock = _isolated_home / "audit_flush.lock"
    lock.write_text("999")
    import os as _os

    old = time.time() - 30
    _os.utime(lock, (old, old))
    assert flusher._acquire_lock() is True
    assert lock.read_text() == str(_os.getpid())


# --- maybe_spawn_flusher ----------------------------------------------------


def test_maybe_spawn_noop_when_no_threshold(
    _isolated_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lock = _isolated_home / "audit_flush.lock"
    lock.write_text("123")  # fresh
    forked = MagicMock()
    popened = MagicMock()
    monkeypatch.setattr(flusher, "_double_fork_and_run", forked)
    monkeypatch.setattr(flusher, "_spawn_subprocess", popened)
    flusher.maybe_spawn_flusher(row_count_hint=5)
    forked.assert_not_called()
    popened.assert_not_called()


def test_maybe_spawn_noop_when_lock_acquire_fails(
    _isolated_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(flusher, "_should_spawn", lambda *_a, **_k: True)
    monkeypatch.setattr(flusher, "_acquire_lock", lambda *_a, **_k: False)
    forked = MagicMock()
    monkeypatch.setattr(flusher, "_double_fork_and_run", forked)
    flusher.maybe_spawn_flusher(row_count_hint=100)
    forked.assert_not_called()


def test_maybe_spawn_uses_subprocess_when_no_fork(
    _isolated_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Remove fork attr to force fallback path.
    import os as _os

    monkeypatch.delattr(_os, "fork", raising=False)
    popen_mock = MagicMock()
    monkeypatch.setattr(flusher.subprocess, "Popen", popen_mock)
    flusher.maybe_spawn_flusher(row_count_hint=100)
    popen_mock.assert_called_once()
    args, kwargs = popen_mock.call_args
    assert args[0] == [sys.executable, "-m", "ccguard.agent.audit_hook.flusher_main"]
    assert kwargs["start_new_session"] is True
    assert kwargs["close_fds"] is True


def test_maybe_spawn_uses_fork_when_available(
    _isolated_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    forked = MagicMock()
    monkeypatch.setattr(flusher, "_double_fork_and_run", forked)
    monkeypatch.setattr(flusher, "_spawn_subprocess", MagicMock())
    flusher.maybe_spawn_flusher(row_count_hint=100)
    forked.assert_called_once()


# --- _run_flush_loop --------------------------------------------------------


def _seed_buffer(home: Path, n: int) -> None:
    db = home / "audit_buffer.db"
    ts = datetime.now(UTC).isoformat()
    with ToolBufferDB(db) as buf:
        for i in range(n):
            buf.insert(
                ts=ts,
                tool_name="Bash",
                fingerprint=f"{i:016x}",
                decision="allow",
                result_status="success",
            )


def _patch_config_and_machine(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub load_or_create + derive_machine_id to avoid touching real home."""
    from types import SimpleNamespace

    cfg = SimpleNamespace(
        server=SimpleNamespace(url="http://test", token="tok"),
        install_salt="salty",
    )
    monkeypatch.setattr(
        "ccguard.agent.config.load_or_create",
        lambda *_a, **_k: (cfg, Path("/tmp/nope")),
    )
    monkeypatch.setattr(
        "ccguard.agent.machine_id.derive_machine_id",
        lambda *_a, **_k: "machine-test",
    )


def test_run_flush_loop_drains_on_success(
    _isolated_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_buffer(_isolated_home, n=3)
    _patch_config_and_machine(monkeypatch)

    captured = {}

    class _MockClient:
        def __init__(self, *a: object, **k: object) -> None:
            pass

        def __enter__(self) -> _MockClient:
            return self

        def __exit__(self, *a: object) -> None:
            pass

        def post(self, url: str, *, content: bytes | str, headers: dict) -> httpx.Response:
            captured["url"] = url
            captured["headers"] = headers
            captured["content"] = content
            req = httpx.Request("POST", url)
            return httpx.Response(200, request=req, json={"accepted": True})

    monkeypatch.setattr(httpx, "Client", _MockClient)
    flusher._run_flush_loop()

    # Buffer drained.
    with ToolBufferDB(_isolated_home / "audit_buffer.db") as buf:
        assert buf.row_count() == 0
    assert captured["url"] == "http://test/api/v1/audit"
    assert captured["headers"]["X-CCGuard-Token"] == "tok"


def test_run_flush_loop_backs_off_on_failure(
    _isolated_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_buffer(_isolated_home, n=2)
    _patch_config_and_machine(monkeypatch)

    sleeps: list[float] = []
    monkeypatch.setattr(time, "sleep", lambda s: sleeps.append(s))

    call_count = {"n": 0}

    class _MockClient:
        def __init__(self, *a: object, **k: object) -> None:
            pass

        def __enter__(self) -> _MockClient:
            return self

        def __exit__(self, *a: object) -> None:
            pass

        def post(self, url: str, *, content: bytes | str, headers: dict) -> httpx.Response:
            call_count["n"] += 1
            req = httpx.Request("POST", url)
            return httpx.Response(500, request=req)

    monkeypatch.setattr(httpx, "Client", _MockClient)
    flusher._run_flush_loop()

    # Tried up to _MAX_ATTEMPTS (3) and backed off 1s then 2s (third attempt breaks before sleep).
    assert call_count["n"] == flusher._MAX_ATTEMPTS
    # Rows remain — we didn't successfully POST.
    with ToolBufferDB(_isolated_home / "audit_buffer.db") as buf:
        assert buf.row_count() == 2
    # Backoff schedule: at least 1s and 2s before the final attempt.
    assert sleeps[0] == 1
    assert sleeps[1] == 2


def test_run_flush_loop_chunks_over_max_batch(
    _isolated_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Seed > _MAX_BATCH to ensure multiple drains.
    _seed_buffer(_isolated_home, n=flusher._MAX_BATCH + 50)
    _patch_config_and_machine(monkeypatch)

    chunks: list[int] = []

    class _MockClient:
        def __init__(self, *a: object, **k: object) -> None:
            pass

        def __enter__(self) -> _MockClient:
            return self

        def __exit__(self, *a: object) -> None:
            pass

        def post(self, url: str, *, content: bytes | str, headers: dict) -> httpx.Response:
            import json as _json

            payload = _json.loads(content)
            chunks.append(len(payload["events"]))
            req = httpx.Request("POST", url)
            return httpx.Response(200, request=req, json={"accepted": True})

    monkeypatch.setattr(httpx, "Client", _MockClient)
    flusher._run_flush_loop()

    assert chunks[0] == flusher._MAX_BATCH
    assert sum(chunks) == flusher._MAX_BATCH + 50
    with ToolBufferDB(_isolated_home / "audit_buffer.db") as buf:
        assert buf.row_count() == 0


def test_run_flush_loop_calls_trim_to_cap(
    _isolated_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _seed_buffer(_isolated_home, n=1)
    _patch_config_and_machine(monkeypatch)

    trim_calls: list[int] = []
    original_trim = ToolBufferDB.trim_to_cap

    def _spy(self: ToolBufferDB, cap: int = 10_000) -> int:
        trim_calls.append(cap)
        return original_trim(self, cap)

    monkeypatch.setattr(ToolBufferDB, "trim_to_cap", _spy)

    class _OK:
        def __init__(self, *a: object, **k: object) -> None:
            pass

        def __enter__(self) -> _OK:
            return self

        def __exit__(self, *a: object) -> None:
            pass

        def post(self, url: str, *, content: bytes | str, headers: dict) -> httpx.Response:
            req = httpx.Request("POST", url)
            return httpx.Response(200, request=req, json={})

    monkeypatch.setattr(httpx, "Client", _OK)
    flusher._run_flush_loop()
    assert trim_calls == [10_000]
