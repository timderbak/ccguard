"""Готовый конфиг для массовой раскатки — то, что вставляют в образ или в GPO.

Ставить агента руками на каждой машине в организации нельзя: людей сотни, и
любой пропущенный ноутбук — это ровно та машина, на которой ничего не видно.
Поэтому раскатка идёт средствами, которые у ИБ уже есть — доменные политики
(GPO), профили управления устройствами (MDM), Ansible, образ рабочей станции.
Всем им нужно одно и то же: **готовый блок конфигурации** и путь, куда его
положить. Сервер знает свой адрес и структуру хуков — значит, собрать этот
блок должен он, а не человек по инструкции из wiki.

Собирается три вещи:

* содержимое ``managed-settings.json`` — файла Claude Code, который лежит под
  правами администратора и потому не может быть отредактирован самим
  разработчиком; именно он делает защиту устойчивой, а не просто заметной;
* конфиг агента с адресом сервера;
* скрипт установки для тех, кто раскатывает через Ansible или образ.

Два решения, которые стоит объяснить:

**Токен не вшивается.** В выдаче стоит подстановочное значение, а не реальный
токен. Один токен на весь образ означает, что его утечка даёт право писать
данные за любую машину флота, а отзыв — останавливает весь флот разом.
Подставлять токен должно то же средство раскатки, из своего хранилища секретов;
у GPO, MDM и Ansible такое хранилище есть у всех.

**Отпечаток конфига считается заранее.** Сервер сразу знает, какой отпечаток
хуков должны докладывать машины с этим конфигом. Дальше это бесплатно
превращается в проверку: машина докладывает другой отпечаток — значит на ней
не тот конфиг, который раскатывали. Считается той же функцией, что и на
агенте, иначе сверка давала бы вечное расхождение на ровном месте.
"""
from __future__ import annotations

import json
import logging
import shlex
from pathlib import Path
from typing import Any

from sqlmodel import Session

from ccguard.agent import harden as _harden
from ccguard.agent import heartbeat as _heartbeat
from ccguard.server.services import settings_service

log = logging.getLogger(__name__)

# Ключ настройки с публичным адресом сервера. Если не задан, адрес берётся из
# запроса — но за обратным прокси это часто внутренний адрес, поэтому в выдаче
# такой случай помечается явно, а не выдаётся за истину.
SERVER_URL_KEY = "deploy.server_url"

# Подстановочное значение вместо токена — см. докстринг модуля.
TOKEN_PLACEHOLDER = "__CCGUARD_AGENT_TOKEN__"

# Куда корпоративная раскатка кладёт файлы агента. Путь фиксированный: он же
# зашит в шимы как приоритетный (``/opt/ccguard/bin/ccguard-*-bin``), поэтому
# самостоятельный бинарник подхватывается без правки конфигурации.
INSTALL_ROOTS: dict[str, str] = {
    "linux": "/opt/ccguard",
    "darwin": "/opt/ccguard",
    "win32": "C:\\Program Files\\ccguard",
}

# Куда кладётся конфиг агента (адрес сервера и токен).
AGENT_CONFIG_PATHS: dict[str, str] = {
    "linux": "/etc/ccguard/config.yaml",
    "darwin": "/etc/ccguard/config.yaml",
    "win32": "C:\\ProgramData\\ccguard\\config.yaml",
}

SUPPORTED_PLATFORMS = ("linux", "darwin", "win32")
# Скрипт установки — bash. Для Windows раскатка идёт средствами домена, и
# выдавать туда неработающий скрипт хуже, чем честно его не выдавать.
_SCRIPT_PLATFORMS = ("linux", "darwin")

_PLATFORM_TITLES = {
    "linux": "Linux",
    "darwin": "macOS",
    "win32": "Windows",
}


def shim_paths(platform: str) -> tuple[Path, Path]:
    """Пути к шимам при корпоративной установке (единые для всех машин)."""
    root = INSTALL_ROOTS.get(platform)
    if root is None:
        raise ValueError(f"платформа не поддерживается: {platform!r}")
    sep = "\\" if platform == "win32" else "/"
    return (
        Path(f"{root}{sep}bin{sep}ccguard-enforce"),
        Path(f"{root}{sep}bin{sep}ccguard-audit"),
    )


def resolve_server_url(session: Session, *, fallback: str | None = None) -> tuple[str, bool]:
    """Публичный адрес сервера и признак «взят не из настройки, а угадан»."""
    configured = settings_service.get_setting(session, SERVER_URL_KEY)
    if configured:
        return configured.rstrip("/"), False
    return (fallback or "http://localhost:8000").rstrip("/"), True


def build_managed_settings(platform: str) -> dict[str, Any]:
    """Содержимое ``managed-settings.json`` для этой платформы.

    Собирается тем же построителем, что и обычная установка, — иначе
    корпоративный и локальный варианты со временем разошлись бы по структуре,
    и отпечатки перестали бы совпадать без всякой атаки.
    """
    enforce_shim, audit_shim = shim_paths(platform)
    return _harden.build_managed_settings(enforce_shim, audit_shim)


def expected_hooks_hash(platform: str) -> str | None:
    """Отпечаток, который должны докладывать машины с этим конфигом."""
    return _heartbeat.hooks_hash_of_settings(build_managed_settings(platform))


def build_agent_config(server_url: str) -> str:
    """Конфиг агента. Токен намеренно оставлен подстановкой — см. докстринг."""
    return (
        "# ccguard — конфигурация агента (раскатывается централизованно).\n"
        f"# Токен подставляет средство раскатки из своего хранилища секретов:\n"
        f"# именно поэтому здесь {TOKEN_PLACEHOLDER}, а не реальное значение.\n"
        "server:\n"
        f"  url: {server_url}\n"
        f"  token: {TOKEN_PLACEHOLDER}\n"
    )


def _install_script(platform: str, server_url: str) -> str | None:
    """Скрипт установки для Ansible / образа рабочей станции."""
    if platform not in _SCRIPT_PLATFORMS:
        return None
    managed = _harden.managed_settings_path(platform)
    if managed is None:
        return None
    root = INSTALL_ROOTS[platform]
    cfg = AGENT_CONFIG_PATHS[platform]
    managed_body = json.dumps(build_managed_settings(platform), indent=2)
    group = "wheel" if platform == "darwin" else "root"
    q_managed = shlex.quote(managed)
    q_cfg = shlex.quote(cfg)
    return f"""#!/usr/bin/env bash
# ccguard — установка агента на рабочую машину. Запускать с правами root.
#
# Конфиг Claude Code кладётся в файл, принадлежащий root: разработчик под своей
# учётной записью изменить его не может — на этом и держится устойчивость
# защиты, а не только её заметность.
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then echo "нужны права root" >&2; exit 1; fi

# Токен берётся из окружения — вшивать его в образ нельзя: утечка одного
# значения дала бы право писать данные за любую машину флота.
: "${{CCGUARD_AGENT_TOKEN:?задайте CCGUARD_AGENT_TOKEN перед запуском}}"

install -d -m 0755 {shlex.quote(root)}/bin
install -d -m 0755 {shlex.quote(str(Path(cfg).parent))}
install -d -m 0755 {shlex.quote(str(Path(managed).parent))}

# 1. Конфиг агента: адрес сервера + токен из окружения.
cat > {q_cfg} <<'CCGUARD_CFG_EOF'
{build_agent_config(server_url)}CCGUARD_CFG_EOF
sed -i.bak "s|{TOKEN_PLACEHOLDER}|${{CCGUARD_AGENT_TOKEN}}|" {q_cfg}
rm -f {q_cfg}.bak
chown root:{group} {q_cfg}
chmod 0600 {q_cfg}

# 2. Хуки Claude Code в файле под правами администратора.
cat > {q_managed} <<'CCGUARD_MANAGED_EOF'
{managed_body}
CCGUARD_MANAGED_EOF
chown root:{group} {q_managed}
chmod 0644 {q_managed}

echo "ccguard: конфигурация раскатана."
echo "Осталось положить исполняемые файлы агента в {root}/bin и запустить службу."
"""


def build_bundle(
    session: Session, *, platform: str, fallback_url: str | None = None
) -> dict[str, Any]:
    """Всё, что нужно средству раскатки для одной платформы."""
    if platform not in SUPPORTED_PLATFORMS:
        raise ValueError(f"платформа не поддерживается: {platform!r}")
    server_url, guessed = resolve_server_url(session, fallback=fallback_url)
    managed = build_managed_settings(platform)
    enforce_shim, audit_shim = shim_paths(platform)
    return {
        "platform": platform,
        "platform_title": _PLATFORM_TITLES[platform],
        "server_url": server_url,
        # Признак «адрес не задан в настройках, а определён по запросу». За
        # обратным прокси это часто внутренний адрес, и агенты по нему не
        # достучатся — молча выдавать такое за истину нельзя.
        "server_url_guessed": guessed,
        "install_root": INSTALL_ROOTS[platform],
        "managed_settings_path": _harden.managed_settings_path(platform),
        "managed_settings": managed,
        "managed_settings_json": json.dumps(managed, indent=2, ensure_ascii=False),
        "agent_config_path": AGENT_CONFIG_PATHS[platform],
        "agent_config": build_agent_config(server_url),
        "enforce_shim": str(enforce_shim),
        "audit_shim": str(audit_shim),
        # Отпечаток, который должны докладывать машины с этим конфигом. По нему
        # видно, что на машине лежит именно то, что раскатывали.
        "expected_hooks_hash": _heartbeat.hooks_hash_of_settings(managed),
        "install_script": _install_script(platform, server_url),
        "token_placeholder": TOKEN_PLACEHOLDER,
    }


def config_drift(session: Session, *, platform: str = "linux") -> list[dict[str, Any]]:
    """Машины, чей отпечаток хуков не совпадает с раскатанным конфигом.

    Проверка почти бесплатная: отпечаток машины уже приходит с сигналом о
    работе, ожидаемый считается из того же конфига, который сервер и раздал.
    Машины без отпечатка сюда НЕ попадают — «не доложила» и «доложила другое»
    это разные утверждения, и смешивать их значит выдавать неизвестность за
    расхождение.
    """
    from sqlmodel import select

    from ccguard.server.db.models import Machine

    expected = expected_hooks_hash(platform)
    if expected is None:
        return []
    out: list[dict[str, Any]] = []
    for m in session.exec(select(Machine)):
        if m.hooks_hash and m.hooks_hash != expected:
            out.append({
                "machine_id": m.machine_id,
                "reported": m.hooks_hash,
                "expected": expected,
                "last_seen": m.last_seen,
            })
    return out
