"""E2E: полный цикл агент-сервер внутри docker-compose.

Запускается в контейнере ccguard-agent, который через docker network
ходит в ccguard-server. Переменные окружения CCGUARD_SERVER_URL и
CCGUARD_TOKEN задаются compose-файлом.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import httpx
import pytest

SERVER_URL = os.environ.get("CCGUARD_SERVER_URL", "http://server:8080")
TOKEN = os.environ.get("CCGUARD_TOKEN", "demo-token-replace-me")
HEADERS = {"X-CCGuard-Token": TOKEN}


pytestmark = pytest.mark.e2e


@pytest.fixture(scope="module", autouse=True)
def _setup_agent_config(tmp_path_factory: pytest.TempPathFactory) -> None:
    """Положить config.yaml с реальным сервером."""
    home = tmp_path_factory.mktemp("ccguard_home")
    os.environ["CCGUARD_AGENT_HOME"] = str(home)
    cfg_yaml = f"""\
server:
  url: {SERVER_URL}
  token: {TOKEN}
install_salt: e2e-salt-fixed
machine_label: e2e-test
audit:
  max_bytes: 1048576
  backup_count: 2
policy:
  cache_path: {home}/policy.yaml
sync:
  interval_minutes: 60
"""
    (home / "config.yaml").write_text(cfg_yaml)


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["python", "-m", "ccguard.agent.cli", *args],
        capture_output=True,
        text=True,
        check=False,
    )


def test_health_endpoint() -> None:
    r = httpx.get(f"{SERVER_URL}/health", timeout=5.0)
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_scan_command_works() -> None:
    res = _run_cli("scan", "--format", "json")
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert data["machine_id"]
    assert any(s["name"] == "shell-mcp" for s in data["mcp_servers"])


def test_sync_and_machine_visible_on_server() -> None:
    res = _run_cli("sync")
    assert res.returncode == 0, f"sync failed: stdout={res.stdout} stderr={res.stderr}"
    body = json.loads(res.stdout)
    assert body["inventory_posted"] is True
    assert body["policy_updated"] is True

    # Сервер должен теперь знать про эту машину.
    r = httpx.get(f"{SERVER_URL}/api/v1/machines", headers=HEADERS, timeout=5.0)
    assert r.status_code == 200
    machines = r.json()["machines"]
    assert any(m["machine_label"] == "e2e-test" for m in machines)


def test_check_finds_violations_after_sync() -> None:
    """После sync у нас есть policy → check находит грязные MCP."""
    _run_cli("sync")
    res = _run_cli("check", "--format", "json")
    # exit code: 2 (block) ожидаем, потому что policy.example.yaml имеет block
    # для денеилиста и mcp shell-mcp у нас грязный.
    assert res.returncode in (1, 2), f"unexpected: rc={res.returncode}\n{res.stdout}"
    findings = json.loads(res.stdout)
    rule_ids = {f["rule_id"] for f in findings}
    assert "mcp_servers.denylist" in rule_ids or "mcp_servers.url_denylist" in rule_ids


def test_install_then_uninstall_idempotent() -> None:
    r1 = _run_cli("install")
    assert r1.returncode == 0, r1.stderr
    # повторный install — никаких новых hooks_added
    r2 = _run_cli("install")
    body = json.loads(r2.stdout)
    assert body["hooks_added"] == 0

    # симуляция enforce с deny-payload (rm -rf /)
    enforce_payload = json.dumps(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"},
        }
    )
    enforce_res = subprocess.run(
        ["python", "-m", "ccguard.agent.enforce_main"],
        input=enforce_payload,
        capture_output=True,
        text=True,
        check=False,
    )
    assert enforce_res.returncode == 0
    out = enforce_res.stdout.strip()
    assert out, "deny должен дать JSON в stdout"
    decision = json.loads(out)
    assert decision["hookSpecificOutput"]["permissionDecision"] == "deny"

    # симуляция enforce с allow-payload (ls)
    allow_payload = json.dumps(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
        }
    )
    allow_res = subprocess.run(
        ["python", "-m", "ccguard.agent.enforce_main"],
        input=allow_payload,
        capture_output=True,
        text=True,
        check=False,
    )
    assert allow_res.returncode == 0
    assert allow_res.stdout.strip() == ""

    # uninstall и повторно
    u1 = _run_cli("uninstall")
    assert u1.returncode == 0
    u2 = _run_cli("uninstall")
    assert json.loads(u2.stdout)["hooks_removed"] == 0


def test_secrets_not_leaked_to_server() -> None:
    """В findings на сервере не должно быть секретов."""
    # Подложить settings.json с псевдо-секретом в env MCP.
    claude_home = Path(os.environ["CLAUDE_HOME"])
    s = json.loads((claude_home / "settings.json").read_text())
    s["mcpServers"]["secret-env"] = {
        "command": "true",
        "env": {"API_KEY": "sk-VeryRealLooking1234567890Token"},
    }
    (claude_home / "settings.json").write_text(json.dumps(s))

    _run_cli("sync")
    r = httpx.get(f"{SERVER_URL}/api/v1/machines", headers=HEADERS, timeout=5.0)
    machines = r.json()["machines"]
    target_id = [m["machine_id"] for m in machines if m["machine_label"] == "e2e-test"][0]

    r2 = httpx.get(f"{SERVER_URL}/api/v1/machines/{target_id}", headers=HEADERS, timeout=5.0)
    body_str = r2.text
    assert "sk-VeryRealLooking" not in body_str
    # Имена ключей — допустимо (только имя, не значение).
    assert "API_KEY" in body_str
