"""evade.nested_agent — запуск сессии AI-агента вне наблюдения ccguard.

Наш хук встроен в тот экземпляр Claude Code, что на хосте. Агент, запущенный
внутри контейнера/пода, работает в чистой среде без наших хуков — классический
уход из-под наблюдения через вложенную среду (сценарий «создам докер, а в нём
ещё одну сессию»).

Здесь важнее срабатываний — анти-false-positive: обычный локальный запуск
агента (он-то как раз ПОД наблюдением) и рутинная работа с docker НЕ должны
поднимать сигнал, иначе оператор его отключит.
"""
from __future__ import annotations

from ccguard.agent.signals.extractor import extract_signals


def _bash(cmd: str) -> set[str]:
    return set(extract_signals("Bash", {"command": cmd}))


# --- срабатывает: агент во вложенной среде -----------------------------------


def test_docker_run_claude_fires():
    assert "evade.nested_agent" in _bash("docker run -it ubuntu claude --print 'go'")


def test_docker_run_other_agents_fire():
    assert "evade.nested_agent" in _bash("docker run img aider --yes")
    assert "evade.nested_agent" in _bash("docker run node cursor-agent")
    assert "evade.nested_agent" in _bash("podman run img codex exec")
    assert "evade.nested_agent" in _bash("docker run img opencode run")


def test_docker_exec_into_running_container_fires():
    assert "evade.nested_agent" in _bash("docker exec -it devbox claude")


def test_podman_and_kubectl_fire():
    assert "evade.nested_agent" in _bash("podman run --rm img claude -p 'x'")
    assert "evade.nested_agent" in _bash("kubectl exec pod-123 -- claude --print hi")


def test_docker_compose_run_fires():
    assert "evade.nested_agent" in _bash("docker compose run app aider")


# --- НЕ срабатывает: локальный агент под наблюдением и рутинный docker --------


def test_local_agent_launch_is_quiet():
    # Локальный claude — под нашими хуками, это норма, не уход из-под наблюдения.
    assert "evade.nested_agent" not in _bash("claude --print 'fix the bug'")
    assert "evade.nested_agent" not in _bash("aider src/main.py")
    assert "evade.nested_agent" not in _bash("cursor-agent")


def test_ordinary_docker_is_quiet():
    # Рутинная работа с контейнерами без запуска агента — тишина.
    assert "evade.nested_agent" not in _bash("docker run -it ubuntu bash")
    assert "evade.nested_agent" not in _bash("docker build -t myapp .")
    assert "evade.nested_agent" not in _bash("docker ps -a")
    assert "evade.nested_agent" not in _bash("docker run --rm postgres:16")
    assert "evade.nested_agent" not in _bash("docker compose up -d")


def test_ssh_user_named_like_agent_is_quiet():
    # ssh намеренно НЕ покрыт: `ssh codex@host` (пользователь с таким именем) —
    # частый ложный случай. Контейнерный вектор явнее, с него и начинаем.
    assert "evade.nested_agent" not in _bash("ssh codex@build-host uptime")


def test_word_mention_is_quiet():
    # Упоминание слова вне запуска в контейнере — не сигнал.
    assert "evade.nested_agent" not in _bash("echo 'run claude in docker later'")
    assert "evade.nested_agent" not in _bash("git commit -m 'add aider config'")
