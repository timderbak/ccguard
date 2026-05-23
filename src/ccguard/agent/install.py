"""install/uninstall: запись и удаление ccguard-хука в settings.json Claude Code."""

from __future__ import annotations

import json
import os
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from ccguard.agent.config import default_config_dir

Scope = Literal["user", "project", "managed"]

# Matcher'ы, на которые навешиваем наш enforce-хук.
HOOK_MATCHERS = ["Bash", "mcp__.*", "WebFetch", "WebSearch"]
HOOK_TIMEOUT = 5
SHIM_MARKER = "# ccguard-shim"  # маркер для идемпотентности
HOOK_TYPE = "command"


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


def write_shim() -> Path:
    """Записать shim-скрипт и сделать его исполняемым."""
    p = shim_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(_shim_body())
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


def install_hook(scope: Scope = "user", project_dir: Path | None = None) -> dict[str, Any]:
    """Прописать ccguard-хук в settings.json для всех matcher'ов из HOOK_MATCHERS.
    Идемпотентно: повторный install не дублирует записи."""
    shim = write_shim()
    settings_file = settings_path_for_scope(scope, project_dir)
    backup = _backup(settings_file)
    data = _read_settings(settings_file)

    hooks_section = data.setdefault("hooks", {})
    if not isinstance(hooks_section, dict):
        raise ValueError(f"{settings_file}: hooks must be an object")

    pre_tool_use = hooks_section.setdefault("PreToolUse", [])
    if not isinstance(pre_tool_use, list):
        raise ValueError(f"{settings_file}: hooks.PreToolUse must be a list")

    added = 0
    for matcher in HOOK_MATCHERS:
        # Ищем существующую запись с тем же matcher.
        target_entry = None
        for entry in pre_tool_use:
            if isinstance(entry, dict) and entry.get("matcher") == matcher:
                target_entry = entry
                break
        if target_entry is None:
            target_entry = {"matcher": matcher, "hooks": []}
            pre_tool_use.append(target_entry)
        hooks_list = target_entry.setdefault("hooks", [])
        if not isinstance(hooks_list, list):
            raise ValueError(f"{settings_file}: hooks list malformed for matcher {matcher}")
        # Если наш хук уже там — пропускаем.
        if any(isinstance(h, dict) and _is_our_hook(h, shim) for h in hooks_list):
            continue
        hooks_list.append(
            {"type": HOOK_TYPE, "command": str(shim), "timeout": HOOK_TIMEOUT}
        )
        added += 1

    _write_settings_atomic(settings_file, data)
    return {
        "settings_file": str(settings_file),
        "shim_path": str(shim),
        "hooks_added": added,
        "backup": str(backup) if backup else None,
    }


def uninstall_hook(scope: Scope = "user", project_dir: Path | None = None) -> dict[str, Any]:
    """Удалить наши записи. Чужие хуки не трогаем. Idempotent."""
    shim = shim_path()
    settings_file = settings_path_for_scope(scope, project_dir)
    if not settings_file.exists():
        return {"settings_file": str(settings_file), "hooks_removed": 0, "backup": None}

    backup = _backup(settings_file)
    data = _read_settings(settings_file)

    hooks_section = data.get("hooks")
    if not isinstance(hooks_section, dict):
        return {"settings_file": str(settings_file), "hooks_removed": 0, "backup": str(backup) if backup else None}

    pre_tool_use = hooks_section.get("PreToolUse")
    if not isinstance(pre_tool_use, list):
        return {"settings_file": str(settings_file), "hooks_removed": 0, "backup": str(backup) if backup else None}

    removed = 0
    new_pre_tool_use: list[Any] = []
    for entry in pre_tool_use:
        if not isinstance(entry, dict):
            new_pre_tool_use.append(entry)
            continue
        hooks_list = entry.get("hooks", [])
        if not isinstance(hooks_list, list):
            new_pre_tool_use.append(entry)
            continue
        filtered = []
        for h in hooks_list:
            if isinstance(h, dict) and _is_our_hook(h, shim):
                removed += 1
                continue
            filtered.append(h)
        if filtered:
            entry["hooks"] = filtered
            new_pre_tool_use.append(entry)
        # Если list стал пустым — удаляем всю запись с этим matcher.

    if new_pre_tool_use:
        hooks_section["PreToolUse"] = new_pre_tool_use
    else:
        hooks_section.pop("PreToolUse", None)
    if not hooks_section:
        data.pop("hooks", None)

    _write_settings_atomic(settings_file, data)
    # Удаляем shim (если он есть и принадлежит нам).
    if shim.exists() and SHIM_MARKER in shim.read_text():
        try:
            shim.unlink()
        except OSError:
            pass

    return {
        "settings_file": str(settings_file),
        "hooks_removed": removed,
        "backup": str(backup) if backup else None,
    }


def verify_installation(scope: Scope = "user", project_dir: Path | None = None) -> dict[str, Any]:
    """Tamper-detection: убедиться, что хук на месте, ведёт на наш shim, disableAllHooks=false."""
    shim = shim_path()
    settings_file = settings_path_for_scope(scope, project_dir)
    issues: list[str] = []
    if not settings_file.exists():
        issues.append(f"settings file missing: {settings_file}")
        return {"ok": False, "issues": issues}

    data = _read_settings(settings_file)
    if data.get("disableAllHooks") is True:
        issues.append("disableAllHooks=true")

    hooks_section = data.get("hooks", {})
    pre = hooks_section.get("PreToolUse", []) if isinstance(hooks_section, dict) else []
    missing_matchers: list[str] = []
    for matcher in HOOK_MATCHERS:
        found = False
        for entry in pre if isinstance(pre, list) else []:
            if not isinstance(entry, dict) or entry.get("matcher") != matcher:
                continue
            for h in entry.get("hooks", []) if isinstance(entry.get("hooks"), list) else []:
                if isinstance(h, dict) and _is_our_hook(h, shim):
                    found = True
                    break
            if found:
                break
        if not found:
            missing_matchers.append(matcher)
    if missing_matchers:
        issues.append(f"hook missing for matchers: {','.join(missing_matchers)}")

    if not shim.exists():
        issues.append(f"shim missing at {shim}")
    elif SHIM_MARKER not in shim.read_text():
        issues.append(f"shim at {shim} doesn't carry ccguard marker (tampered?)")

    return {"ok": not issues, "issues": issues}
