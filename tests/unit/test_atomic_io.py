"""Tests for ccguard.agent.atomic_io.atomic_write_bytes."""

from __future__ import annotations

import os
import stat
import threading
from pathlib import Path

import pytest

from ccguard.agent.atomic_io import atomic_write_bytes


def test_writes_bytes_to_target(tmp_path: Path) -> None:
    target = tmp_path / "subdir" / "file.txt"
    atomic_write_bytes(target, b"hello world")
    assert target.read_bytes() == b"hello world"


def test_creates_parent_dirs(tmp_path: Path) -> None:
    target = tmp_path / "a" / "b" / "c" / "x.txt"
    atomic_write_bytes(target, b"x")
    assert target.exists()
    assert target.parent.is_dir()


def test_overwrites_existing(tmp_path: Path) -> None:
    target = tmp_path / "file.txt"
    target.write_bytes(b"old")
    atomic_write_bytes(target, b"new")
    assert target.read_bytes() == b"new"


def test_tempfile_in_same_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Tempfile must live in target's parent dir so os.replace is atomic."""
    target = tmp_path / "subdir" / "file.txt"
    target.parent.mkdir()

    seen_dirs: list[str] = []
    import tempfile as _tempfile

    real_ntf = _tempfile.NamedTemporaryFile

    def spy_ntf(*args, **kwargs):
        seen_dirs.append(kwargs.get("dir"))
        return real_ntf(*args, **kwargs)

    monkeypatch.setattr(_tempfile, "NamedTemporaryFile", spy_ntf)
    atomic_write_bytes(target, b"x")
    assert seen_dirs and str(seen_dirs[0]) == str(target.parent)


def test_no_leftover_tempfile_on_success(tmp_path: Path) -> None:
    target = tmp_path / "file.txt"
    atomic_write_bytes(target, b"x")
    leftovers = [p for p in tmp_path.iterdir() if p.name.startswith(".ccguard-tmp-")]
    assert leftovers == []


def test_cleanup_on_replace_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """On os.replace failure, temp file must be unlinked — no leftovers."""
    target = tmp_path / "file.txt"

    import ccguard.agent.atomic_io as atomic_io_mod

    def boom(src, dst):
        raise PermissionError("simulated")

    monkeypatch.setattr(atomic_io_mod.os, "replace", boom)

    with pytest.raises(PermissionError):
        atomic_write_bytes(target, b"x")

    leftovers = [p for p in tmp_path.iterdir() if p.name.startswith(".ccguard-tmp-")]
    assert leftovers == []
    # Target was never created
    assert not target.exists()


def test_concurrent_writes_no_corruption(tmp_path: Path) -> None:
    """Concurrent calls serialize via os.replace — last writer wins, no corruption."""
    target = tmp_path / "file.txt"
    payloads = [bytes([i]) * 1024 for i in range(1, 11)]

    def writer(data: bytes) -> None:
        atomic_write_bytes(target, data)

    threads = [threading.Thread(target=writer, args=(p,)) for p in payloads]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Final content equals exactly one of the payloads (no corruption / interleave)
    final = target.read_bytes()
    assert final in payloads
    assert len(final) == 1024


def test_default_perms_0o644_umask_respecting(tmp_path: Path) -> None:
    target = tmp_path / "file.txt"
    old_umask = os.umask(0o022)
    try:
        atomic_write_bytes(target, b"x")
    finally:
        os.umask(old_umask)
    mode = stat.S_IMODE(target.stat().st_mode)
    assert mode == 0o644
