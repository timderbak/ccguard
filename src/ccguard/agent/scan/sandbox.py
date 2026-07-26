"""Сканер песочницы (sandbox — изолированной среды исполнения) Claude Code.

Песочница — периметр вокруг агента: что писать на диск, куда ходить по сети
(egress-allowlist), какие команды бегают ВНЕ изоляции. Настраивается в
settings.json на всех scope'ах, managed-конфиг может залочить. Мы собираем
ЭФФЕКТИВНОЕ состояние — то, что реально действует после слияния scope'ов, —
чтобы сервер следил за его дрейфом и ловил ОСЛАБЛЕНИЕ периметра (кто-то
выключил песочницу, расширил allowlist, разрешил команды вне изоляции).

Приоритет scope как у Claude Code (по убыванию силы):

    managed  >  project_local  >  project  >  user

Для каждого поля берём значение из самого приоритетного scope, где оно задано
(override, а не объединение). Для списков (egress-allowlist, writable-пути)
Claude Code тоже берёт значение по приоритету, а не объединяет их — так и
делаем; упрощение честное и предсказуемое. Значения не собираются, только сам
факт настройки (для egress — имена доменов: это не секрет, а как раз то, что
ИБ должна видеть).
"""
from __future__ import annotations

from typing import Any

from ccguard.agent.scan.settings import ParsedSettings
from ccguard.schemas import SandboxState

# Сила scope: чем больше число, тем «главнее слово». Совпадает с порядком
# слияния settings.json у Claude Code (managed выигрывает всё).
_SCOPE_PRIORITY: dict[str, int] = {
    "user": 1,
    "project": 2,
    "project_local": 3,
    "managed": 4,
}


def _as_bool(v: Any) -> bool | None:
    """Только настоящий JSON-boolean считаем заданным; прочее → None (не задано).

    Строку "false" или число сюда не пускаем: в конфиге ослабление задают
    именно булевым ключом, а угадывание «truthy» породило бы ложные срабатывания.
    """
    return v if isinstance(v, bool) else None


def _as_str_list(v: Any) -> list[str] | None:
    """Список строк из JSON-массива; None — если ключа нет или он не массив."""
    if not isinstance(v, list):
        return None
    return [str(x) for x in v]


def _as_str(v: Any) -> str | None:
    return v if isinstance(v, str) and v else None


def scan_sandbox(parsed: list[ParsedSettings]) -> SandboxState | None:
    """Собрать эффективное состояние песочницы из всех settings.json.

    Возвращает ``None``, если ни в одном scope нет ни блока ``sandbox``, ни
    ``permissions.defaultMode`` — сообщать нечего, и отчёт остаётся компактным.
    Сервер трактует ``None`` как «песочница не собрана» (старый агент или не
    настроена) и ничего по ней не проверяет.
    """
    # Идём от слабого scope к сильному: более приоритетное значение затирает
    # менее приоритетное, поэтому в конце в state лежит эффективное состояние.
    ordered = sorted(
        parsed,
        key=lambda p: _SCOPE_PRIORITY.get(p.source.scope, 0),
    )

    configured = False
    state = SandboxState()
    saw_default_mode = False

    for p in ordered:
        if p.data is None:
            continue
        scope = p.source.scope

        # permissions.defaultMode — та же ось «сила периметра», хоть и вне блока
        # sandbox. Собираем отдельно, чтобы поймать конфиг с bypassPermissions
        # даже там, где песочница вовсе не настроена.
        perms = p.data.get("permissions")
        if isinstance(perms, dict):
            dm = _as_str(perms.get("defaultMode"))
            if dm is not None:
                state.default_mode = dm
                saw_default_mode = True

        sb = p.data.get("sandbox")
        if not isinstance(sb, dict):
            continue
        configured = True

        enabled = _as_bool(sb.get("enabled"))
        if enabled is not None:
            state.enabled = enabled
            state.source_scope = scope

        fiu = _as_bool(sb.get("failIfUnavailable"))
        if fiu is not None:
            state.fail_if_unavailable = fiu

        auc = _as_bool(sb.get("allowUnsandboxedCommands"))
        if auc is not None:
            state.allow_unsandboxed_commands = auc

        wns = _as_bool(sb.get("enableWeakerNestedSandbox"))
        if wns is not None:
            state.weaker_nested_sandbox = wns

        wni = _as_bool(sb.get("enableWeakerNetworkIsolation"))
        if wni is not None:
            state.weaker_network_isolation = wni

        excluded = _as_str_list(sb.get("excludedCommands"))
        if excluded is not None:
            state.excluded_commands = excluded

        net = sb.get("network")
        if isinstance(net, dict):
            allowed = _as_str_list(net.get("allowedDomains"))
            if allowed is not None:
                state.network_allowed_domains = allowed
            denied = _as_str_list(net.get("deniedDomains"))
            if denied is not None:
                state.network_denied_domains = denied
            amdo = _as_bool(net.get("allowManagedDomainsOnly"))
            if amdo is not None:
                state.network_allow_managed_domains_only = amdo

        fs = sb.get("filesystem")
        if isinstance(fs, dict):
            aw = _as_str_list(fs.get("allowWrite"))
            if aw is not None:
                state.filesystem_allow_write = aw
            dr = _as_str_list(fs.get("denyRead"))
            if dr is not None:
                state.filesystem_deny_read = dr
            disabled = _as_bool(fs.get("disabled"))
            if disabled is not None:
                state.filesystem_disabled = disabled

    if not configured and not saw_default_mode:
        return None

    state.configured = configured
    return state
