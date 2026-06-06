"""Verify HookEntry carries file_path/file_content_hash/file_unreadable_reason
(under the existing repo-name attributes: command_file_path, command_file_hash,
plus the new file_unreadable_reason).
"""

from ccguard.schemas.inventory import HookEntry


def test_hook_entry_accepts_new_file_fields():
    entry = HookEntry(
        event="PreToolUse",
        matcher="Bash",
        type="command",
        command="/usr/local/bin/python /opt/script.py",
        source="/root/.claude/settings.json",
        is_ccguard_owned=False,
        command_file_path="/opt/script.py",
        command_file_hash="abc123def456",
        file_unreadable_reason=None,
    )
    assert entry.command_file_path == "/opt/script.py"
    assert entry.command_file_hash == "abc123def456"
    assert entry.file_unreadable_reason is None


def test_hook_entry_defaults_new_fields_to_none():
    entry = HookEntry(event="PreToolUse", type="command", source="/root/.claude/settings.json")
    assert entry.command_file_path is None
    assert entry.command_file_hash is None
    assert entry.file_unreadable_reason is None


# --- Helpers introduced for TOFU baseline (Task 2) ----------------------------

import hashlib
from pathlib import Path

from ccguard.agent.scan.hooks import _extract_shim_path, _hash_shim_file


def test_extract_shim_path_picks_script_arg(tmp_path):
    # "python /opt/script.py --flag" → "/opt/script.py" (file must exist)
    script = tmp_path / "script.py"
    script.write_text("# noop\n")
    cmd = f"/usr/local/bin/python {script} --flag"
    assert _extract_shim_path(cmd) == str(script)


def test_extract_shim_path_returns_none_for_inline_bash():
    # "bash -c 'echo hi'" → no real file
    assert _extract_shim_path("bash -c 'echo hi'") is None


def test_extract_shim_path_handles_quoted_paths(tmp_path):
    d = tmp_path / "some space"
    d.mkdir()
    script = d / "script.py"
    script.write_text("# noop\n")
    cmd = f'python "{script}"'
    assert _extract_shim_path(cmd) == str(script)


def test_extract_shim_path_returns_first_existing_path_token(tmp_path):
    script = tmp_path / "shim.sh"
    script.write_text("#!/bin/sh\necho hi\n")
    cmd = f"sh {script} arg1"
    assert _extract_shim_path(cmd) == str(script)


def test_hash_shim_file_returns_sha256_first_32(tmp_path):
    f = tmp_path / "x.py"
    f.write_bytes(b"hello world\n")
    expected = hashlib.sha256(b"hello world\n").hexdigest()[:32]
    h, reason = _hash_shim_file(str(f))
    assert h == expected
    assert reason is None


def test_hash_shim_file_missing(tmp_path):
    h, reason = _hash_shim_file(str(tmp_path / "nope.py"))
    assert h is None
    assert reason == "missing"


def test_hash_shim_file_too_large(tmp_path):
    f = tmp_path / "big.bin"
    f.write_bytes(b"x" * (300 * 1024))  # > 256 KB cap
    h, reason = _hash_shim_file(str(f))
    assert h is None
    assert reason == "too_large"


def test_hash_shim_file_permission_denied(tmp_path, monkeypatch):
    import builtins
    f = tmp_path / "locked.py"
    f.write_text("x")

    real_open = builtins.open

    def fake_open(path, *args, **kwargs):
        if str(path) == str(f):
            raise PermissionError("denied")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", fake_open)

    h, reason = _hash_shim_file(str(f))
    assert h is None
    assert reason == "permission_denied"
