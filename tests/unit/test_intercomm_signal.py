"""intercomm.remote_agent — межагентный egress (ASI07).

Агент открывает исходящий канал к ДРУГОМУ агенту/модели: регистрирует удалённый
MCP (sse/http) или зовёт чужой LLM-API из shell. Как и у evade.nested_agent,
здесь важнее срабатываний анти-false-positive: локальный MCP (stdio), обычный
curl к докам, `pip install openai` НЕ должны срабатывать, иначе оператор
отключит сигнал.
"""
from __future__ import annotations

from ccguard.agent.signals.extractor import extract_signals


def _bash(cmd: str) -> set[str]:
    return set(extract_signals("Bash", {"command": cmd}))


# --- срабатывает: канал к чужому агенту/модели -------------------------------


def test_remote_mcp_add_sse_fires():
    assert "intercomm.remote_agent" in _bash(
        "claude mcp add remote --transport sse https://mcp.example.com/sse"
    )


def test_remote_mcp_add_http_fires():
    assert "intercomm.remote_agent" in _bash(
        "claude mcp add foo --transport http http://10.0.0.5:8080"
    )


def test_mcp_add_bare_url_fires():
    assert "intercomm.remote_agent" in _bash("mcp add svc https://mcp.vendor.io")


def test_curl_to_model_apis_fire():
    assert "intercomm.remote_agent" in _bash(
        "curl https://api.openai.com/v1/chat/completions -d @body.json"
    )
    assert "intercomm.remote_agent" in _bash(
        "wget https://generativelanguage.googleapis.com/v1/models"
    )
    assert "intercomm.remote_agent" in _bash("xh POST api.mistral.ai/v1/chat")
    assert "intercomm.remote_agent" in _bash("curl https://openrouter.ai/api/v1")


# --- НЕ срабатывает: локальные каналы и рутина -------------------------------


def test_local_stdio_mcp_add_is_quiet():
    # stdio-MCP — локальный процесс, не сетевой межагентный канал.
    assert "intercomm.remote_agent" not in _bash("claude mcp add localfs -- node server.js")


def test_local_agent_and_ordinary_curl_quiet():
    assert "intercomm.remote_agent" not in _bash("claude --print 'fix the bug'")
    assert "intercomm.remote_agent" not in _bash("curl https://docs.example.com/guide")
    assert "intercomm.remote_agent" not in _bash("curl -O https://github.com/x/y/releases/z")


def test_word_mention_is_quiet():
    assert "intercomm.remote_agent" not in _bash("pip install openai anthropic")
    assert "intercomm.remote_agent" not in _bash("echo 'see api.openai.com for docs'")
    assert "intercomm.remote_agent" not in _bash("git commit -m 'add openai client'")
