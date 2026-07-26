"""OS-level registration for ``ccguard-daemon`` (D2).

macOS → launchd user agent at ``~/Library/LaunchAgents/com.ccguard.daemon.plist``.
Linux → systemd-user unit at ``~/.config/systemd/user/ccguard-daemon.service``.

Pure body-generation is split from subprocess invocation so unit tests can
assert on the file contents without touching the host launchd/systemd.

Also exposes :func:`detect_executable` — by default returns ``sys.executable``
+ ``-m ccguard.agent.daemon``, which is the fix for the long-standing
wrapper bug (bare ``python3`` resolved to the system interpreter where
ccguard isn't installed → ``ModuleNotFoundError`` → hook block).
"""
from __future__ import annotations

import os
import platform
import subprocess
import sys
from pathlib import Path

_PLIST_LABEL = "com.ccguard.daemon"
_SYSTEMD_UNIT_NAME = "ccguard-daemon.service"


def detect_executable() -> list[str]:
    """Resolve the daemon entry-point as an ``execve``-ready argv list.

    Prefers ``ccguard-daemon`` script if present in the same bin as the
    current interpreter (``.venv/bin``); otherwise falls back to
    ``<python> -m ccguard.agent.daemon``. Both forms run the same code; the
    script form is slightly faster (one less Python startup hop).
    """
    py = Path(sys.executable)
    script = py.parent / "ccguard-daemon"
    if script.is_file() and os.access(script, os.X_OK):
        return [str(script)]
    return [str(py), "-m", "ccguard.agent.daemon"]


def launchd_plist_body(argv: list[str], log_dir: Path) -> str:
    """Build a launchd user-agent plist that runs ``argv`` on demand + restart.

    Restart strategy: ``KeepAlive=true`` → launchd respawns on crash.
    ``RunAtLoad=true`` → starts immediately when the user logs in.
    StdOut/StdErr go to ``<log_dir>/daemon.{out,err}.log``.
    """
    program_args_xml = "\n".join(
        f"        <string>{_xml_escape(a)}</string>" for a in argv
    )
    log_dir_str = _xml_escape(str(log_dir))
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{_PLIST_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
{program_args_xml}
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{log_dir_str}/daemon.out.log</string>
    <key>StandardErrorPath</key>
    <string>{log_dir_str}/daemon.err.log</string>
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
"""


def systemd_unit_body(argv: list[str], log_dir: Path) -> str:
    """Build a systemd-user unit that runs ``argv`` with Restart=on-failure."""
    exec_start = " ".join(_shell_escape(a) for a in argv)
    return f"""[Unit]
Description=ccguard agent background sync daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exec_start}
Restart=on-failure
RestartSec=10
StandardOutput=append:{log_dir}/daemon.out.log
StandardError=append:{log_dir}/daemon.err.log

[Install]
WantedBy=default.target
"""


def _xml_escape(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))


def _shell_escape(s: str) -> str:
    if not s or any(c in s for c in (" ", "\t", "'", '"', "\\")):
        return "'" + s.replace("'", "'\\''") + "'"
    return s


def macos_plist_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{_PLIST_LABEL}.plist"


def linux_systemd_unit_path() -> Path:
    """Return systemd unit path: system-wide for root, user-scoped otherwise.

    Why: на VPS-сценарии (root без linger) user-unit не виден стандартному
    systemd-инстансу, и daemon не переживает reboot. Для root кладём в
    /etc/systemd/system; для обычного пользователя — в ~/.config/systemd/user
    (так разработчику не нужен sudo).
    """
    if os.geteuid() == 0:
        return Path("/etc/systemd/system") / _SYSTEMD_UNIT_NAME
    return Path.home() / ".config" / "systemd" / "user" / _SYSTEMD_UNIT_NAME


def _systemctl_scope() -> list[str]:
    """systemctl args: пустой список (system) для root, ['--user'] иначе."""
    return [] if os.geteuid() == 0 else ["--user"]


def install_daemon(
    *,
    argv: list[str] | None = None,
    log_dir: Path | None = None,
    dry_run: bool = False,
) -> dict[str, object]:
    """Write the plist/unit and ask the OS to load it.

    ``dry_run=True`` skips ``launchctl``/``systemctl`` so the result can be
    asserted in tests without side effects.
    """
    argv = argv or detect_executable()
    from ccguard.agent.config import default_config_dir
    log_dir = log_dir or (default_config_dir() / "logs")
    log_dir.mkdir(parents=True, exist_ok=True)
    system = platform.system().lower()
    if "darwin" in system:
        return _install_launchd(argv, log_dir, dry_run=dry_run)
    if "linux" in system:
        return _install_systemd(argv, log_dir, dry_run=dry_run)
    return {"status": "unsupported", "system": system}


def uninstall_daemon(*, dry_run: bool = False) -> dict[str, object]:
    system = platform.system().lower()
    if "darwin" in system:
        return _uninstall_launchd(dry_run=dry_run)
    if "linux" in system:
        return _uninstall_systemd(dry_run=dry_run)
    return {"status": "unsupported", "system": system}


# --- macOS launchd --------------------------------------------------------


def _install_launchd(argv, log_dir, *, dry_run: bool) -> dict[str, object]:
    path = macos_plist_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(launchd_plist_body(argv, log_dir))
    out: dict[str, object] = {"system": "darwin", "plist_path": str(path), "loaded": False}
    if dry_run:
        out["status"] = "dry_run"
        return out
    uid = os.getuid()
    target = f"gui/{uid}"
    # Best-effort unload first to make install idempotent.
    subprocess.run(
        ["launchctl", "bootout", target, str(path)],
        capture_output=True, check=False,
    )
    rc = subprocess.run(
        ["launchctl", "bootstrap", target, str(path)],
        capture_output=True, check=False,
    )
    out["loaded"] = rc.returncode == 0
    out["status"] = "ok" if rc.returncode == 0 else "load_failed"
    if rc.returncode != 0:
        out["stderr"] = rc.stderr.decode("utf-8", errors="replace")[:500]
    return out


def _uninstall_launchd(*, dry_run: bool) -> dict[str, object]:
    path = macos_plist_path()
    out: dict[str, object] = {"system": "darwin", "plist_path": str(path)}
    if not path.exists():
        out["status"] = "absent"
        return out
    if dry_run:
        out["status"] = "dry_run"
        return out
    uid = os.getuid()
    target = f"gui/{uid}"
    subprocess.run(
        ["launchctl", "bootout", target, str(path)],
        capture_output=True, check=False,
    )
    path.unlink(missing_ok=True)
    out["status"] = "removed"
    return out


# --- Linux systemd --------------------------------------------------------


def _install_systemd(argv, log_dir, *, dry_run: bool) -> dict[str, object]:
    path = linux_systemd_unit_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(systemd_unit_body(argv, log_dir))
    out: dict[str, object] = {"system": "linux", "unit_path": str(path), "loaded": False}
    if dry_run:
        out["status"] = "dry_run"
        return out
    scope = _systemctl_scope()
    subprocess.run(["systemctl", *scope, "daemon-reload"],
                   capture_output=True, check=False)
    rc = subprocess.run(
        ["systemctl", *scope, "enable", "--now", _SYSTEMD_UNIT_NAME],
        capture_output=True, check=False,
    )
    out["loaded"] = rc.returncode == 0
    out["status"] = "ok" if rc.returncode == 0 else "load_failed"
    if rc.returncode != 0:
        out["stderr"] = rc.stderr.decode("utf-8", errors="replace")[:500]
    return out


def _uninstall_systemd(*, dry_run: bool) -> dict[str, object]:
    path = linux_systemd_unit_path()
    out: dict[str, object] = {"system": "linux", "unit_path": str(path)}
    if not path.exists():
        out["status"] = "absent"
        return out
    if dry_run:
        out["status"] = "dry_run"
        return out
    scope = _systemctl_scope()
    subprocess.run(
        ["systemctl", *scope, "disable", "--now", _SYSTEMD_UNIT_NAME],
        capture_output=True, check=False,
    )
    path.unlink(missing_ok=True)
    subprocess.run(["systemctl", *scope, "daemon-reload"],
                   capture_output=True, check=False)
    out["status"] = "removed"
    return out
