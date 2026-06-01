"""machine_detail UI: раскрываемые карточки хуков + структурированные находки.

Сценарий: на машине пользователя стоит ccguard (4 PreToolUse от ccguard + 1
PostToolUse audit-shim) и параллельно 3 чужих хука (плагины/личные скрипты).

UI должен:
  - помечать ccguard-owned хуки явно
  - предупреждать про unknown хуки
  - в settings_sources показывать exists + hooks_count
  - в Находках раскрывать description с командой и источником
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.server.db.models import (
    FindingRecord,
    InventorySnapshot,
    Machine,
)
from ccguard.server.main import create_app
from ccguard.server.services.auth_service import create_session, hash_password


def _setup_env(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("CCGUARD_ADMIN_PASSWORD_HASH", hash_password("hunter2"))
    monkeypatch.setenv("CCGUARD_DB_URL", f"sqlite:///{tmp_path}/web.db")
    monkeypatch.setenv("CCGUARD_SESSION_SECRET", "test-secret")


def _ccguard_hook(matcher: str) -> dict:
    return {
        "event": "PreToolUse",
        "matcher": matcher,
        "type": "command",
        "command": "/root/.ccguard/bin/ccguard-enforce",
        "source": "/root/.claude/settings.json",
        "is_ccguard_owned": True,
    }


def _audit_hook() -> dict:
    return {
        "event": "PostToolUse",
        "matcher": "*",
        "type": "command",
        "command": "/root/.ccguard/bin/ccguard-audit",
        "source": "/root/.claude/settings.json",
        "is_ccguard_owned": True,
    }


def _unknown_hook(matcher: str | None, cmd: str) -> dict:
    return {
        "event": "PreToolUse",
        "matcher": matcher,
        "type": "command",
        "command": cmd,
        "source": "/root/.claude/settings.json",
        "is_ccguard_owned": False,
    }


def _inventory_payload() -> dict:
    return {
        "schema_version": 1,
        "machine_id": "m1",
        "timestamp": datetime.now(UTC).isoformat(),
        "agent_version": "0.2.0",
        "os": "linux",
        "settings_sources": [
            {
                "path": "/root/.claude/settings.json",
                "scope": "user",
                "exists": True,
                "hooks_count": 8,
                "size_bytes": 1735,
            },
            {
                "path": "/.claude/settings.json",
                "scope": "project",
                "exists": False,
                "hooks_count": 0,
                "size_bytes": 0,
            },
            {
                "path": "/etc/claude-code/managed-settings.json",
                "scope": "managed",
                "exists": False,
                "hooks_count": 0,
                "size_bytes": 0,
            },
        ],
        "hooks": [
            _ccguard_hook("Bash"),
            _ccguard_hook("Write"),
            _ccguard_hook("Edit"),
            _ccguard_hook("WebFetch"),
            _audit_hook(),
            _unknown_hook("Bash", "/usr/local/bin/claude-mem-statusline"),
            _unknown_hook(None, "python /root/.foo/handler.py"),
            _unknown_hook("Bash|Write", "/opt/plugins/log-everything.sh"),
        ],
        "mcp_servers": [],
        "skills": [],
        "plugins": [],
        "permissions": {"allow": [], "deny": [], "ask": [], "dangerously_skip_detected": False},
        "agents": [],
        "commands": [],
        "env_keys": [],
        "claude_code_version": None,
    }


def _hooks_unknown_finding(cmd: str, matcher: str | None, source: str) -> dict:
    desc = (
        f"Найден хук PreToolUse (matcher: {matcher or '*'}) с командой "
        f"`{cmd}` в {source}. Это не ccguard-shim. Если ты сам "
        "установил его — добавь в allowlist. Если не помнишь — удали."
    )
    return {
        "rule_id": "hooks.unknown",
        "severity": "warn",
        "title": f"Неизвестный хук PreToolUse/{matcher or '*'}",
        "description": desc,
        "source": source,
        "recommendation": "Добавить в hooks.allowlist_commands или удалить из settings.json.",
        "matched_value": cmd,
    }


def test_machine_detail_shows_settings_sources_with_status(monkeypatch, tmp_path):  # type: ignore[no-untyped-def]
    _setup_env(monkeypatch, tmp_path)
    with TestClient(create_app()) as client:
        engine = client.app.state.engine
        now = datetime.now(UTC)
        with Session(engine) as s:
            s.add(Machine(machine_id="m1", machine_label="dev-laptop",
                          first_seen=now, last_seen=now, agent_version="0.2.0"))
            s.add(InventorySnapshot(
                machine_id="m1",
                received_at=now,
                payload_json=json.dumps(_inventory_payload()),
            ))
            sid = create_session(s, user_id="admin")
        r = client.get("/machines/m1", cookies={"ccg_session": sid})
        assert r.status_code == 200, r.text
        body = r.text
        # Heading for the renamed section.
        assert "Источники конфигурации" in body
        # Existing file path rendered.
        assert "/root/.claude/settings.json" in body
        # Hooks count badge for existing file.
        assert "hooks: 8" in body
        # Missing file path also visible (sorted after existing ones).
        assert "/etc/claude-code/managed-settings.json" in body


def test_machine_detail_shows_hook_details_with_marker(monkeypatch, tmp_path):  # type: ignore[no-untyped-def]
    _setup_env(monkeypatch, tmp_path)
    with TestClient(create_app()) as client:
        engine = client.app.state.engine
        now = datetime.now(UTC)
        with Session(engine) as s:
            s.add(Machine(machine_id="m1", machine_label="dev-laptop",
                          first_seen=now, last_seen=now, agent_version="0.2.0"))
            s.add(InventorySnapshot(
                machine_id="m1",
                received_at=now,
                payload_json=json.dumps(_inventory_payload()),
            ))
            sid = create_session(s, user_id="admin")
        r = client.get("/machines/m1", cookies={"ccg_session": sid})
        assert r.status_code == 200, r.text
        body = r.text
        # Section heading for hooks.
        assert "Хуки Claude Code" in body
        # The ccguard-owned marker is visible somewhere in the rendered page.
        assert "ccguard" in body.lower()
        # Specific matcher and command from the inventory should be inline.
        assert "Bash|Write" in body  # unknown hook matcher
        assert "/root/.ccguard/bin/ccguard-enforce" in body
        assert "/usr/local/bin/claude-mem-statusline" in body
        # Warning banner for unknown hooks.
        assert "не установлены через ccguard" in body or "unknown" in body.lower()


def test_machine_detail_shows_hooks_unknown_finding_payload(monkeypatch, tmp_path):  # type: ignore[no-untyped-def]
    _setup_env(monkeypatch, tmp_path)
    with TestClient(create_app()) as client:
        engine = client.app.state.engine
        now = datetime.now(UTC)
        with Session(engine) as s:
            s.add(Machine(machine_id="m1", machine_label="dev-laptop",
                          first_seen=now, last_seen=now, agent_version="0.2.0"))
            snap = InventorySnapshot(
                machine_id="m1",
                received_at=now,
                payload_json=json.dumps(_inventory_payload()),
            )
            s.add(snap)
            s.flush()
            # Three hooks.unknown findings — one per unknown hook in inventory.
            f1 = _hooks_unknown_finding(
                "/usr/local/bin/claude-mem-statusline",
                "Bash",
                "/root/.claude/settings.json",
            )
            f2 = _hooks_unknown_finding(
                "python /root/.foo/handler.py",
                None,
                "/root/.claude/settings.json",
            )
            f3 = _hooks_unknown_finding(
                "/opt/plugins/log-everything.sh",
                "Bash|Write",
                "/root/.claude/settings.json",
            )
            for fin in (f1, f2, f3):
                s.add(FindingRecord(
                    machine_id="m1",
                    inventory_id=snap.id or 0,
                    rule_id=fin["rule_id"],
                    severity=fin["severity"],
                    discovered_at=now,
                    payload_json=json.dumps(fin),
                ))
            sid = create_session(s, user_id="admin")
        r = client.get("/machines/m1", cookies={"ccg_session": sid})
        assert r.status_code == 200, r.text
        body = r.text
        # The finding card must surface the actual command + matcher + source —
        # not just "hooks.unknown".
        assert "/usr/local/bin/claude-mem-statusline" in body
        assert "python /root/.foo/handler.py" in body
        assert "/opt/plugins/log-everything.sh" in body
        # Three warn-level findings rendered.
        assert body.count("hooks.unknown") >= 3
