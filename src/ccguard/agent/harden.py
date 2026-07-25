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


def managed_settings_path(platform: str) -> str | None:
    """OS path of Claude Code's root-owned managed/policy settings file."""
    return _MANAGED_PATHS.get(platform)


def build_managed_settings(enforce_shim: Path, audit_shim: Path) -> dict:
    """The managed-settings.json content pinning the ccguard hooks.

    Reuses the SAME hook-builder as a normal install (:func:`install._install_event`)
    so the managed and user installs can never drift in structure.
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
    content = json.dumps(build_managed_settings(enforce_shim, audit_shim), indent=2)

    steps: list[HardenStep] = [
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
