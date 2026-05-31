"""Pure body generation tests for daemon OS registration."""
from __future__ import annotations

from pathlib import Path

import pytest

from ccguard.agent.daemon_install import (
    detect_executable,
    install_daemon,
    launchd_plist_body,
    macos_plist_path,
    systemd_unit_body,
    uninstall_daemon,
)


def test_launchd_plist_contains_label_and_argv():
    body = launchd_plist_body(["/foo/.venv/bin/python", "-m", "ccguard.agent.daemon"],
                              log_dir=Path("/var/log/ccguard"))
    assert "<string>com.ccguard.daemon</string>" in body
    assert "<string>/foo/.venv/bin/python</string>" in body
    assert "<string>-m</string>" in body
    assert "<string>ccguard.agent.daemon</string>" in body
    assert "<key>RunAtLoad</key>" in body
    assert "<key>KeepAlive</key>" in body
    assert "<string>/var/log/ccguard/daemon.out.log</string>" in body


def test_launchd_plist_xml_escapes_special_chars():
    body = launchd_plist_body(["/p<a>th/with&special"], log_dir=Path("/tmp"))
    assert "<string>/p&lt;a&gt;th/with&amp;special</string>" in body
    # Original chars must not appear unescaped inside argv.
    assert "<string>/p<a>" not in body


def test_systemd_unit_contains_execstart_and_restart():
    body = systemd_unit_body(["/foo/.venv/bin/python", "-m", "ccguard.agent.daemon"],
                             log_dir=Path("/var/log/ccguard"))
    assert "[Unit]" in body
    assert "[Service]" in body
    assert "Type=simple" in body
    assert "Restart=on-failure" in body
    assert "ExecStart=/foo/.venv/bin/python -m ccguard.agent.daemon" in body
    assert "StandardOutput=append:/var/log/ccguard/daemon.out.log" in body
    assert "WantedBy=default.target" in body


def test_systemd_unit_quotes_paths_with_spaces():
    body = systemd_unit_body(["/path with space/python", "-m", "ccguard.agent.daemon"],
                             log_dir=Path("/tmp"))
    # Path with space must be single-quoted.
    assert "ExecStart='/path with space/python' -m ccguard.agent.daemon" in body


def test_detect_executable_returns_runnable_argv():
    argv = detect_executable()
    assert len(argv) >= 1
    # First element is either the ccguard-daemon script or the python interpreter.
    assert argv[0].endswith("ccguard-daemon") or "python" in argv[0]


def test_install_daemon_dry_run_writes_file_but_skips_load(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    result = install_daemon(
        argv=["/x/python", "-m", "ccguard.agent.daemon"],
        log_dir=tmp_path / "logs",
        dry_run=True,
    )
    assert result["status"] == "dry_run"
    # On macOS plist file is written even in dry_run.
    if result.get("system") == "darwin":
        assert Path(result["plist_path"]).exists()  # type: ignore[arg-type]
    elif result.get("system") == "linux":
        assert Path(result["unit_path"]).exists()  # type: ignore[arg-type]


def test_uninstall_when_not_installed_returns_absent(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    result = uninstall_daemon(dry_run=True)
    if result.get("system") in ("darwin", "linux"):
        assert result["status"] == "absent"
