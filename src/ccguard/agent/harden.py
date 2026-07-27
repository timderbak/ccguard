"""Hardened tier (privilege boundary) — the ONE anti-tamper layer that provides
real tamper-RESISTANCE rather than evidence.

It pins the ccguard hooks in Claude Code's root-owned MANAGED settings file and
makes the enforce/audit shim + policy root-owned and immutable. A same-user
attacker then cannot remove the hook (the managed file is behind a privilege
boundary it can't cross) nor swap the shim/policy (immutable + root-owned).

Confirmed against Claude Code v2.1.178: it reads a policy/MDM ``managed-settings.json``
as a distinct settings source from system paths (macOS
``/Library/Application Support/ClaudeCode``, Linux ``/etc/claude-code``).

Honest residuals (see docs/anti-tamper.md):
* The enforce shim still execs a python interpreter, so whatever that
  interpreter imports must ALSO be out of the user's reach. Pass ``runtime_root``
  to :func:`harden_plan` and the agent's environment is root-owned and
  read-only for the user, which closes the module-shadowing hole. A
  self-contained binary was measured as an alternative and rejected: it made the
  check roughly twice as SLOW (see ``scripts/measure-hook-latency.sh``) for the
  same guarantee. Without ``runtime_root`` the hole stays open — the shim is
  protected, the code it runs is not.
* Whether a managed hook survives a user ``disableAllHooks: true`` is not
  documented by Anthropic. ccguard's A3 rule independently hard-denies WRITING
  ``disableAllHooks``, so the same-user agent cannot set it — but confirm with a
  field-test.

Applying the plan needs root and is environment-specific, so this module
GENERATES a reviewable plan / sudo script (pure, fully tested). The operator
applies it on the endpoint — live enforcement is a privileged field-test
(mirrors how daemon_install separates pure body generation from real install).
"""
from __future__ import annotations

import json
import shlex
from dataclasses import dataclass, field
from pathlib import Path

from ccguard.agent import install as _install

# Confirmed against Claude Code v2.1.178 (policy/MDM managed-settings source).
_MANAGED_PATHS: dict[str, str] = {
    "darwin": "/Library/Application Support/ClaudeCode/managed-settings.json",
    "linux": "/etc/claude-code/managed-settings.json",
    "win32": "C:\\Program Files\\ClaudeCode\\managed-settings.json",
}
# Owning group for root-owned assets differs by OS.
_ROOT_GROUP: dict[str, str] = {"darwin": "wheel", "linux": "root"}

# Платформы, где у Claude Code есть OS-песочница (Seatbelt / bubblewrap). На
# нативном Windows её нет, и там forceful failIfUnavailable=true заблокировал бы
# запуск самого Claude Code — поэтому sandbox-lock туда не кладём.
_SANDBOX_PLATFORMS: frozenset[str] = frozenset({"darwin", "linux"})

# Домен, без которого Claude Code не работает: LLM-API + preflight WebFetch
# (docs: data-usage). Всегда добавляется в egress-allowlist, чтобы default-deny
# не «окирпичил» сам инструмент.
_REQUIRED_EGRESS_DOMAIN = "api.anthropic.com"


def managed_settings_path(platform: str) -> str | None:
    """OS path of Claude Code's root-owned managed/policy settings file."""
    return _MANAGED_PATHS.get(platform)


def _apply_sandbox_lock(
    data: dict,
    *,
    platform: str,
    egress_allowlist: list[str] | None,
    proxy_port: int | None = None,
) -> None:
    """Прошить в managed-settings несносимую песочницу (владеем периметром).

    Managed-настройки выигрывают у user/project/env И командной строки (docs:
    server-managed-settings — «No other settings level can override them, including
    command line arguments»), поэтому агент под тем же пользователем не может ни
    выключить песочницу, ни воспользоваться ``--dangerously-skip-permissions``.

    Ключевое, что делает это НАДЁЖНЫМ, а не косметикой: OS-песочница — жёсткая
    граница, которую bypassPermissions НЕ снимает (docs: sandboxing / permission-
    modes — он лишь пропускает подтверждения, а Seatbelt/bubblewrap остаётся). Плюс
    ``disableBypassPermissionsMode: "disable"`` в managed-настройках вообще
    запрещает этот флаг. ``failIfUnavailable: true`` — fail-closed: нет песочницы →
    Claude Code не запускается (осознанный выбор threat-model).

    Против злонамеренного человека С sudo это НЕ несносимо (он владеет root) —
    там работает tamper-evidence: снятие lock следующий скан увидит как выключенную
    песочницу, и ``sandbox_baseline`` выдаст ``sandbox.weakened`` (critical).

    ``disableBypassPermissionsMode`` кладём на ВСЕХ платформах (защищает хуки даже
    там, где песочницы нет). Сам sandbox-блок — только где Claude Code его
    поддерживает: на win32 forceful failIfUnavailable заблокировал бы инструмент.
    """
    # Запрет bypass-режима работает и без песочницы — защищает хуки на любой ОС.
    data.setdefault("permissions", {})["disableBypassPermissionsMode"] = "disable"
    if platform not in _SANDBOX_PLATFORMS:
        return
    sandbox: dict = {
        "enabled": True,
        "failIfUnavailable": True,        # fail-closed security gate
        "allowUnsandboxedCommands": False,  # без лазейки «выполнить вне изоляции»
    }
    # Egress-allowlist сужаем ТОЛЬКО если оператор задал свой список — тогда это
    # default-deny с гарантированно добавленным Anthropic API (иначе окирпичим).
    # Пустой список → egress не трогаем (день-в-день не ломаем npm/git/pip).
    if egress_allowlist:
        domains = list(dict.fromkeys([_REQUIRED_EGRESS_DOMAIN, *egress_allowlist]))
        sandbox["network"] = {"allowedDomains": domains, "allowManagedDomainsOnly": True}
    # Направить egress песочницы на локальный ccguard-прокси (наблюдаемость).
    # По умолчанию OFF: указать порт, где прокси не слушает, обрубило бы весь
    # egress — включается только когда оператор field-test'ом убедился, что
    # прокси работает (см. egress_proxy.serve). См. `ccguard egress-proxy`.
    if proxy_port is not None:
        sandbox.setdefault("network", {})["httpProxyPort"] = proxy_port
    data["sandbox"] = sandbox


def build_managed_settings(
    enforce_shim: Path,
    audit_shim: Path,
    *,
    platform: str = "linux",
    lock_sandbox: bool = True,
    egress_allowlist: list[str] | None = None,
    proxy_port: int | None = None,
) -> dict:
    """The managed-settings.json content pinning the ccguard hooks.

    Reuses the SAME hook-builder as a normal install (:func:`install._install_event`)
    so the managed and user installs can never drift in structure.

    При ``lock_sandbox`` (по умолчанию) дополнительно прошивает несносимую
    OS-песочницу + запрет bypass-режима — «владеем периметром», а не только
    инвентаризуем его. См. :func:`_apply_sandbox_lock`. ``proxy_port`` (по
    умолчанию None = не задан) направляет egress песочницы на локальный
    ccguard-прокси — включать только после field-test прокси.
    """
    data: dict = {}
    marker = Path("managed-settings.json")
    _install._install_event(
        data=data,
        settings_file=marker,
        hook_event="PreToolUse",
        matchers=_install.HOOK_MATCHERS,
        shim=enforce_shim,
        timeout=_install.HOOK_TIMEOUT,
    )
    _install._install_event(
        data=data,
        settings_file=marker,
        hook_event="PostToolUse",
        matchers=_install.AUDIT_HOOK_MATCHERS,
        shim=audit_shim,
        timeout=_install.AUDIT_HOOK_TIMEOUT,
    )
    if lock_sandbox:
        _apply_sandbox_lock(
            data, platform=platform, egress_allowlist=egress_allowlist,
            proxy_port=proxy_port,
        )
    return data


def immutability_argv(path: str, platform: str) -> list[str] | None:
    """Command to set the OS immutable flag (clearing it needs root / Recovery)."""
    if platform == "linux":
        return ["chattr", "+i", path]
    if platform == "darwin":
        return ["chflags", "schg", path]
    return None  # Windows: ACL/registry-based, not modeled here.


@dataclass
class HardenStep:
    desc: str
    kind: str  # "write_file" | "run"
    argv: list[str] = field(default_factory=list)
    path: str = ""
    content: str = ""
    mode: str = ""


def runtime_lock_steps(runtime_root: Path, *, platform: str) -> list[HardenStep]:
    """Забрать у пользователя право писать в то, что запускает шим.

    Закрывает остаточный риск, ради которого раньше планировался самостоятельный
    исполняемый файл: шим защищён правами администратора, но запускает он
    интерпретатор с модулями, лежащими в обычном каталоге. Атакующий под тем же
    пользователем не может подменить шим — зато может подменить модуль, который
    шим вызовет, и защита исполнит его код.

    Права закрывают ровно ту же дыру, что и самостоятельный файл, и при этом
    ничего не стоят по времени. Замер (``scripts/measure-hook-latency.sh``)
    показал, что упаковка в самостоятельный файл делает проверку примерно
    вдвое МЕДЛЕННЕЕ обычного запуска — платить двумястами миллисекунд на каждом
    вызове инструмента за ту же гарантию нельзя.

    Каталог не делается неизменяемым: обновлять агента всё равно нужно, а
    неизменяемый флаг на дереве файлов превращает обновление в ручную операцию
    с правами администратора на каждой машине.
    """
    group = _ROOT_GROUP.get(platform, "root")
    owner = f"root:{group}"
    root = str(runtime_root)
    return [
        HardenStep(desc=f"root-own agent runtime {root}", kind="run",
                   argv=["chown", "-R", owner, root]),
        # Пользователю остаётся чтение и запуск, запись — только администратору.
        HardenStep(desc=f"drop user write access to {root}", kind="run",
                   argv=["chmod", "-R", "go-w", root]),
    ]


def harden_plan(
    *,
    platform: str,
    enforce_shim: Path,
    audit_shim: Path,
    policy_path: Path,
    runtime_root: Path | None = None,
) -> list[HardenStep]:
    """Ordered privileged steps to harden the endpoint. Pure — generates the
    plan; it is APPLIED with root (see :func:`render_script`).

    ``runtime_root`` — каталог, откуда запускается агент (окружение с его
    модулями). Если передан, право записи в него забирается у пользователя:
    иначе защищённый шим запускает код, который пользователь может переписать.
    """
    managed = managed_settings_path(platform)
    if managed is None:
        raise ValueError(f"hardened tier not supported on platform {platform!r}")
    group = _ROOT_GROUP.get(platform, "root")
    owner = f"root:{group}"
    managed_dir = str(Path(managed).parent)
    content = json.dumps(
        build_managed_settings(enforce_shim, audit_shim, platform=platform), indent=2
    )

    steps: list[HardenStep] = []
    # PREFLIGHT (Linux): fail-closed песочница без рабочего бэкенда bubblewrap
    # заблокирует запуск Claude Code — а managed-файл ещё и делается immutable,
    # то есть кирпич будет несносимым. Поэтому ДО записи lock'а проверяем, что
    # bwrap есть; если нет — script аварийно выходит, ничего не записав. macOS
    # (Seatbelt) встроен, проверка не нужна. Срабатывает только когда lock реально
    # fail-closed (иначе брикнуть нечем).
    if platform == "linux" and '"failIfUnavailable": true' in content:
        steps.append(HardenStep(
            desc="preflight: bubblewrap доступен (иначе fail-closed sandbox заблокирует Claude Code)",
            kind="run",
            argv=[
                "sh", "-c",
                "command -v bwrap >/dev/null 2>&1 || { echo 'ccguard: bubblewrap "
                "(bwrap) не найден — sandbox fail-closed заблокирует Claude Code. "
                "Установите bubblewrap и повторите.' >&2; exit 2; }",
            ],
        ))
    steps += [
        HardenStep(desc=f"create managed-settings dir {managed_dir}", kind="run",
                   argv=["mkdir", "-p", managed_dir]),
        HardenStep(desc="pin ccguard hooks in root-owned managed-settings.json",
                   kind="write_file", path=managed, content=content, mode="0644"),
    ]
    # Root-own + lock each asset behind the privilege boundary.
    locked: list[tuple[str, str]] = [
        (managed, "0644"),
        (str(enforce_shim), "0555"),
        (str(audit_shim), "0555"),
        (str(policy_path), "0444"),
    ]
    for path, mode in locked:
        steps.append(HardenStep(desc=f"root-own {path}", kind="run",
                                argv=["chown", owner, path]))
        steps.append(HardenStep(desc=f"restrict perms on {path}", kind="run",
                                argv=["chmod", mode, path]))
        imm = immutability_argv(path, platform)
        if imm is not None:
            steps.append(HardenStep(desc=f"make {path} immutable", kind="run", argv=imm))
    # Последним — среда запуска: защищать шим и оставлять запускаемый им код
    # открытым на запись значит закрыть дверь и оставить окно.
    if runtime_root is not None:
        steps.extend(runtime_lock_steps(runtime_root, platform=platform))
    return steps


def render_script(plan: list[HardenStep]) -> str:
    """Render the plan as a reviewable bash script to run with sudo on the
    endpoint. File writes use a quoted heredoc; runs are the raw argv."""
    lines = [
        "#!/usr/bin/env bash",
        "# ccguard hardened tier — run as root (sudo). Review before running.",
        "set -euo pipefail",
        'if [ "$(id -u)" -ne 0 ]; then echo "must run as root (sudo)" >&2; exit 1; fi',
        "",
    ]
    for s in plan:
        lines.append(f"# {s.desc}")
        if s.kind == "write_file":
            q = shlex.quote(s.path)
            lines.append(f"cat > {q} <<'CCGUARD_MANAGED_EOF'")
            lines.append(s.content)
            lines.append("CCGUARD_MANAGED_EOF")
            if s.mode:
                lines.append(f"chmod {s.mode} {q}")
        else:
            lines.append(" ".join(shlex.quote(a) for a in s.argv))
        lines.append("")
    return "\n".join(lines)
