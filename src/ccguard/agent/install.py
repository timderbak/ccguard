"""install/uninstall: запись и удаление ccguard-хука в settings.json Claude Code."""

from __future__ import annotations

import contextlib
import json
import os
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from ccguard.agent.config import default_config_dir

Scope = Literal["user", "project", "managed"]

# Matcher'ы PreToolUse enforce-хука (v0.1).
HOOK_MATCHERS = ["Bash", "mcp__.*", "WebFetch", "WebSearch"]
HOOK_TIMEOUT = 5
SHIM_MARKER = "# ccguard-shim"  # маркер для идемпотентности
HOOK_TYPE = "command"

# Matcher'ы PostToolUse audit-хука (v0.2, TUA-01/TUA-02). `*` ловит все tool calls.
AUDIT_HOOK_MATCHERS = ["*"]
AUDIT_HOOK_TIMEOUT = 3
AUDIT_SHIM_MARKER = "# ccguard-audit-shim"


def _user_settings_path() -> Path:
    home = Path(os.environ.get("CLAUDE_HOME") or os.path.expanduser("~/.claude"))
    return home / "settings.json"


def _project_settings_path(project_dir: Path) -> Path:
    return project_dir / ".claude" / "settings.json"


def _managed_settings_path() -> Path:
    # Linux. Для других OS — отдельный вопрос; MVP сосредоточен на Linux.
    return Path("/etc/claude-code/managed-settings.json")


def settings_path_for_scope(scope: Scope, project_dir: Path | None = None) -> Path:
    if scope == "user":
        return _user_settings_path()
    if scope == "project":
        if project_dir is None:
            raise ValueError("project_dir required for scope=project")
        return _project_settings_path(project_dir)
    if scope == "managed":
        return _managed_settings_path()
    raise ValueError(f"unknown scope: {scope}")


def shim_path() -> Path:
    return default_config_dir() / "bin" / "ccguard-enforce"


def audit_shim_path() -> Path:
    return default_config_dir() / "bin" / "ccguard-audit"


def _shim_body() -> str:
    """Bash-shim: вызывает либо PyInstaller-бинарник, либо python-fallback.
    Fail-open при отсутствии бинарей."""
    return f"""#!/usr/bin/env bash
{SHIM_MARKER}
set -e

BIN="/opt/ccguard/bin/ccguard-enforce-bin"
if [ -x "$BIN" ]; then
    exec "$BIN" "$@"
fi

if command -v python3 >/dev/null 2>&1; then
    exec python3 -m ccguard.agent.enforce_main "$@"
fi

# Fail-open: ничего не нашли, разрешаем (логировать нечем).
exit 0
"""


def _audit_shim_body() -> str:
    """Bash-shim for PostToolUse audit hook. Fail-silent (audit is best-effort)."""
    return f"""#!/usr/bin/env bash
{AUDIT_SHIM_MARKER}
set -e

BIN="/opt/ccguard/bin/ccguard-audit-bin"
if [ -x "$BIN" ]; then
    exec "$BIN" "$@"
fi

if command -v python3 >/dev/null 2>&1; then
    exec python3 -m ccguard.agent.audit_main "$@"
fi

# Fail-silent: no audit binary available — let the tool call proceed unobserved.
exit 0
"""


def write_shim() -> Path:
    """Записать shim-скрипт и сделать его исполняемым."""
    p = shim_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(_shim_body())
    os.chmod(p, 0o755)
    return p


def write_audit_shim() -> Path:
    p = audit_shim_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(_audit_shim_body())
    os.chmod(p, 0o755)
    return p


def _backup(settings_file: Path) -> Path | None:
    if not settings_file.exists():
        return None
    backup_dir = default_config_dir() / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    backup_file = backup_dir / f"{settings_file.name}.{ts}.bak"
    shutil.copy2(settings_file, backup_file)
    return backup_file


def _read_settings(settings_file: Path) -> dict[str, Any]:
    if not settings_file.exists():
        return {}
    raw = settings_file.read_text().strip()
    if not raw:
        return {}
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError(f"{settings_file}: expected object at top level")
    return data


def _write_settings_atomic(settings_file: Path, data: dict[str, Any]) -> None:
    settings_file.parent.mkdir(parents=True, exist_ok=True)
    tmp = settings_file.with_suffix(settings_file.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    tmp.replace(settings_file)


def _is_our_hook(hook_spec: dict[str, Any], shim: Path) -> bool:
    return (
        hook_spec.get("type") == HOOK_TYPE
        and hook_spec.get("command") == str(shim)
    )


def _install_event(
    *,
    data: dict[str, Any],
    settings_file: Path,
    hook_event: str,
    matchers: list[str],
    shim: Path,
    timeout: int,
) -> int:
    """Write a hooks-section entry for one event kind (PreToolUse or PostToolUse).

    Returns count of hook entries actually appended (0 on idempotent re-run).
    """
    hooks_section = data.setdefault("hooks", {})
    if not isinstance(hooks_section, dict):
        raise ValueError(f"{settings_file}: hooks must be an object")

    event_list = hooks_section.setdefault(hook_event, [])
    if not isinstance(event_list, list):
        raise ValueError(f"{settings_file}: hooks.{hook_event} must be a list")

    added = 0
    for matcher in matchers:
        target_entry = None
        for entry in event_list:
            if isinstance(entry, dict) and entry.get("matcher") == matcher:
                target_entry = entry
                break
        if target_entry is None:
            target_entry = {"matcher": matcher, "hooks": []}
            event_list.append(target_entry)
        hooks_list = target_entry.setdefault("hooks", [])
        if not isinstance(hooks_list, list):
            raise ValueError(
                f"{settings_file}: hooks list malformed for {hook_event} matcher {matcher}"
            )
        if any(isinstance(h, dict) and _is_our_hook(h, shim) for h in hooks_list):
            continue
        hooks_list.append({"type": HOOK_TYPE, "command": str(shim), "timeout": timeout})
        added += 1
    return added


def install_hook(scope: Scope = "user", project_dir: Path | None = None) -> dict[str, Any]:
    """Прописать ccguard-хуки в settings.json:

    * PreToolUse: enforce-shim для HOOK_MATCHERS (v0.1 behavior preserved).
    * PostToolUse: audit-shim для AUDIT_HOOK_MATCHERS=['*'] (TUA-01/TUA-02).

    Идемпотентно: повторный install не дублирует записи.
    """
    shim = write_shim()
    audit_shim = write_audit_shim()
    settings_file = settings_path_for_scope(scope, project_dir)
    backup = _backup(settings_file)
    data = _read_settings(settings_file)

    added_pre = _install_event(
        data=data,
        settings_file=settings_file,
        hook_event="PreToolUse",
        matchers=HOOK_MATCHERS,
        shim=shim,
        timeout=HOOK_TIMEOUT,
    )
    added_post = _install_event(
        data=data,
        settings_file=settings_file,
        hook_event="PostToolUse",
        matchers=AUDIT_HOOK_MATCHERS,
        shim=audit_shim,
        timeout=AUDIT_HOOK_TIMEOUT,
    )

    _write_settings_atomic(settings_file, data)
    return {
        "settings_file": str(settings_file),
        "shim_path": str(shim),
        "audit_shim_path": str(audit_shim),
        # `hooks_added` historically meant PreToolUse hooks added (v0.1 contract).
        # Audit hook count is surfaced separately so v0.1 tests stay green.
        "hooks_added": added_pre,
        "audit_hooks_added": added_post,
        "backup": str(backup) if backup else None,
    }


def _uninstall_event(
    *,
    hooks_section: dict[str, Any],
    hook_event: str,
    shim: Path,
) -> int:
    """Remove our hook entries from one event list. Returns count removed."""
    event_list = hooks_section.get(hook_event)
    if not isinstance(event_list, list):
        return 0

    removed = 0
    new_list: list[Any] = []
    for entry in event_list:
        if not isinstance(entry, dict):
            new_list.append(entry)
            continue
        hooks_list = entry.get("hooks", [])
        if not isinstance(hooks_list, list):
            new_list.append(entry)
            continue
        filtered = []
        for h in hooks_list:
            if isinstance(h, dict) and _is_our_hook(h, shim):
                removed += 1
                continue
            filtered.append(h)
        if filtered:
            entry["hooks"] = filtered
            new_list.append(entry)
        # Если list стал пустым — удаляем всю запись с этим matcher.

    if new_list:
        hooks_section[hook_event] = new_list
    else:
        hooks_section.pop(hook_event, None)
    return removed


def uninstall_hook(scope: Scope = "user", project_dir: Path | None = None) -> dict[str, Any]:
    """Удалить наши записи. Чужие хуки не трогаем. Idempotent."""
    shim = shim_path()
    audit_shim = audit_shim_path()
    settings_file = settings_path_for_scope(scope, project_dir)
    if not settings_file.exists():
        return {"settings_file": str(settings_file), "hooks_removed": 0, "backup": None}

    backup = _backup(settings_file)
    data = _read_settings(settings_file)

    hooks_section = data.get("hooks")
    if not isinstance(hooks_section, dict):
        return {
            "settings_file": str(settings_file),
            "hooks_removed": 0,
            "backup": str(backup) if backup else None,
        }

    removed_pre = _uninstall_event(
        hooks_section=hooks_section, hook_event="PreToolUse", shim=shim
    )
    removed_post = _uninstall_event(
        hooks_section=hooks_section, hook_event="PostToolUse", shim=audit_shim
    )
    if not hooks_section:
        data.pop("hooks", None)

    _write_settings_atomic(settings_file, data)
    # Удаляем shim'ы (только если они наши — проверка маркера).
    for path, marker in ((shim, SHIM_MARKER), (audit_shim, AUDIT_SHIM_MARKER)):
        if path.exists() and marker in path.read_text():
            with contextlib.suppress(OSError):
                path.unlink()

    return {
        "settings_file": str(settings_file),
        "hooks_removed": removed_pre,
        "audit_hooks_removed": removed_post,
        "backup": str(backup) if backup else None,
    }


def _matchers_registered(
    hooks_section: dict[str, Any],
    hook_event: str,
    matchers: list[str],
    shim: Path,
) -> list[str]:
    """Return the subset of ``matchers`` NOT found under our shim for ``hook_event``."""
    event_list = hooks_section.get(hook_event, []) if isinstance(hooks_section, dict) else []
    missing: list[str] = []
    for matcher in matchers:
        found = False
        for entry in event_list if isinstance(event_list, list) else []:
            if not isinstance(entry, dict) or entry.get("matcher") != matcher:
                continue
            entry_hooks = entry.get("hooks", []) if isinstance(entry.get("hooks"), list) else []
            for h in entry_hooks:
                if isinstance(h, dict) and _is_our_hook(h, shim):
                    found = True
                    break
            if found:
                break
        if not found:
            missing.append(matcher)
    return missing


def verify_installation(scope: Scope = "user", project_dir: Path | None = None) -> dict[str, Any]:
    """Tamper-detection: оба хука на месте, ведут на наши shim'ы, disableAllHooks=false."""
    shim = shim_path()
    audit_shim = audit_shim_path()
    settings_file = settings_path_for_scope(scope, project_dir)
    issues: list[str] = []
    if not settings_file.exists():
        issues.append(f"settings file missing: {settings_file}")
        return {"ok": False, "issues": issues, "audit_hook_registered": False}

    data = _read_settings(settings_file)
    if data.get("disableAllHooks") is True:
        issues.append("disableAllHooks=true")

    hooks_section = data.get("hooks", {}) if isinstance(data.get("hooks"), dict) else {}

    missing_pre = _matchers_registered(hooks_section, "PreToolUse", HOOK_MATCHERS, shim)
    if missing_pre:
        issues.append(f"hook missing for matchers: {','.join(missing_pre)}")

    missing_audit = _matchers_registered(
        hooks_section, "PostToolUse", AUDIT_HOOK_MATCHERS, audit_shim
    )
    audit_hook_registered = not missing_audit
    if missing_audit:
        issues.append(f"audit hook missing for matchers: {','.join(missing_audit)}")

    if not shim.exists():
        issues.append(f"shim missing at {shim}")
    elif SHIM_MARKER not in shim.read_text():
        issues.append(f"shim at {shim} doesn't carry ccguard marker (tampered?)")

    if not audit_shim.exists():
        issues.append(f"audit shim missing at {audit_shim}")
    elif AUDIT_SHIM_MARKER not in audit_shim.read_text():
        issues.append(f"audit shim at {audit_shim} doesn't carry ccguard marker (tampered?)")

    return {
        "ok": not issues,
        "issues": issues,
        "audit_hook_registered": audit_hook_registered,
    }
