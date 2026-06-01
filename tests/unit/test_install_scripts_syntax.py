"""Smoke-tests for the remote-install scripts and docker-compose.remote.yml.

Эти тесты ловят синтаксические опечатки в bash-скриптах и YAML до того,
как мы попытаемся катить их на чужой VPS. Они НЕ запускают сами скрипты
(там docker/ssh/pip) — только проверяют, что:

  * ``bash -n`` не находит синтаксических ошибок;
  * ``docker-compose.remote.yml`` парсится как валидный YAML;
  * docker-compose-конфиг ссылается на нужные env-переменные сервера;
  * скрипты установлены executable.

Реальный smoke (``docker compose up``) делается утром на VPS.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = [
    REPO_ROOT / "scripts" / "install-server.sh",
    REPO_ROOT / "scripts" / "install-agent.sh",
]
COMPOSE_FILE = REPO_ROOT / "docker" / "docker-compose.remote.yml"


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_script_exists_and_executable(script: Path) -> None:
    assert script.exists(), f"missing: {script}"
    # +x для удобства; на CI/Win может не сохраниться, но локально требуем.
    if os.name == "posix":
        assert os.access(script, os.X_OK), f"not executable: {script} (chmod +x)"


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_script_bash_syntax(script: Path) -> None:
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("bash not available")
    result = subprocess.run(
        [bash, "-n", str(script)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, (
        f"bash -n failed for {script.name}:\n{result.stderr}"
    )


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_script_shebang(script: Path) -> None:
    first = script.read_text(encoding="utf-8").splitlines()[0]
    assert first.startswith("#!"), f"{script.name}: нет shebang"
    assert "bash" in first, f"{script.name}: shebang должен быть на bash"


def test_compose_file_is_valid_yaml() -> None:
    assert COMPOSE_FILE.exists(), f"missing: {COMPOSE_FILE}"
    data = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    assert "services" in data
    assert "ccguard-server" in data["services"], "service ccguard-server обязателен"


def test_compose_uses_real_server_env_vars() -> None:
    """Server читает CCGUARD_TOKENS / CCGUARD_ADMIN_PASSWORD_HASH /
    CCGUARD_SESSION_SECRET. Если перепутаем имена — рассинхрон обнаружится тут.
    """
    text = COMPOSE_FILE.read_text(encoding="utf-8")
    required_envs = [
        "CCGUARD_TOKENS",
        "CCGUARD_ADMIN_PASSWORD_HASH",
        "CCGUARD_SESSION_SECRET",
        "CCGUARD_DB_URL",
        "CCGUARD_POLICY_PATH",
    ]
    for var in required_envs:
        assert var in text, f"compose не выставляет {var} — сервер не запустится"


def test_compose_healthcheck_targets_real_endpoint() -> None:
    """Сервер отдаёт /health (не /api/health). Без healthcheck нельзя
    дождаться запуска, поэтому проверяем явно."""
    text = COMPOSE_FILE.read_text(encoding="utf-8")
    assert "/health" in text
    assert "/api/health" not in text, "у сервера нет /api/health — это /health"


def test_compose_validates_with_docker(tmp_path: Path) -> None:
    """Если docker compose доступен — попросим его распарсить файл.
    Иначе skip (docker не обязателен на dev-машине разработчика тестов).
    """
    if not shutil.which("docker"):
        pytest.skip("docker not available")
    # docker compose требует env-переменные — подсунем заглушки.
    env_file = tmp_path / "fake.env"
    env_file.write_text(
        "CCGUARD_TOKENS=tok\n"
        "CCGUARD_ADMIN_PASSWORD_HASH=hash\n"
        "CCGUARD_SESSION_SECRET=sess\n"
        "CCGUARD_SERVER_PORT=8080\n",
        encoding="utf-8",
    )
    # Compose требует существующий config-файл для bind-mount; создадим заглушку.
    fake_config = tmp_path / "server_policy.yaml"
    fake_config.write_text("meta: {revision: 0}\n", encoding="utf-8")
    result = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            str(COMPOSE_FILE),
            "--env-file",
            str(env_file),
            "config",
            "--quiet",
        ],
        capture_output=True,
        text=True,
        check=False,
        cwd=str(REPO_ROOT),
    )
    if result.returncode != 0:
        # Самая частая причина — docker compose plugin отсутствует или старая
        # версия не понимает synthax. Не падаем тест — fail только при явных
        # YAML/schema ошибках.
        stderr = result.stderr.lower()
        if "command not found" in stderr or "unknown command" in stderr:
            pytest.skip(f"docker compose unavailable: {result.stderr.strip()}")
        pytest.fail(f"docker compose config failed:\n{result.stderr}")
