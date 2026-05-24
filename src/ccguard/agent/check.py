"""Policy engine для `ccguard check`: применение policy к inventory → findings."""

from __future__ import annotations

import fnmatch
import re
from urllib.parse import urlparse

from ccguard.agent.masking import mask_secrets
from ccguard.schemas import (
    AgentEntry,
    Finding,
    HookEntry,
    InventoryReport,
    McpServerEntry,
    PermissionsSnapshot,
    Policy,
    SkillEntry,
)


def _host_matches(host: str, pattern: str) -> bool:
    """`*.example.com` мэтчит foo.example.com и foo.bar.example.com.
    Точные паттерны без `*` мэтчат только при полном совпадении."""
    pattern = pattern.lower()
    host = host.lower()
    if "*" in pattern:
        return fnmatch.fnmatchcase(host, pattern)
    return host == pattern


def _url_to_host(url: str | None) -> str | None:
    if not url:
        return None
    try:
        parsed = urlparse(url)
        return parsed.hostname
    except ValueError:
        return None


def _check_mcp_servers(inv: InventoryReport, policy: Policy) -> list[Finding]:
    out: list[Finding] = []
    pol = policy.mcp_servers
    for srv in inv.mcp_servers:
        # 1. denylist по имени
        if srv.name in pol.denylist_names:
            out.append(_mcp_finding(srv, pol.severity, "mcp_servers.denylist", "имя в denylist"))
            continue
        # 2. deny_all_unknown + не в allowlist
        if pol.deny_all_unknown and srv.name not in pol.allowlist_names:
            out.append(
                _mcp_finding(
                    srv,
                    pol.severity,
                    "mcp_servers.unknown",
                    "сервер не в allowlist (включён режим whitelist)",
                )
            )
            continue
        # 3. URL-паттерны (только если url есть)
        if srv.url:
            host = _url_to_host(srv.url) or srv.url
            for pat in pol.denylist_url_patterns:
                # pattern может содержать схему: http://*
                if pat.startswith("http://") and srv.url.startswith("http://"):
                    out.append(
                        _mcp_finding(
                            srv,
                            pol.severity,
                            "mcp_servers.url_denylist",
                            f"URL мэтчит denylist-паттерн {pat}",
                        )
                    )
                    break
                if "*" in pat and fnmatch.fnmatchcase(host, pat):
                    out.append(
                        _mcp_finding(
                            srv,
                            pol.severity,
                            "mcp_servers.url_denylist",
                            f"host {host} мэтчит {pat}",
                        )
                    )
                    break
    return out


def _mcp_finding(srv: McpServerEntry, sev, rule_id: str, why: str) -> Finding:  # type: ignore[no-untyped-def]
    return Finding(
        rule_id=rule_id,
        severity=sev,
        title=f"MCP-сервер заблокирован политикой: {srv.name}",
        description=f"{why}. transport={srv.transport}, url={srv.url or '-'}",
        source=srv.source,
        recommendation=f"Удалить '{srv.name}' из mcpServers или согласовать с security.",
        matched_value=mask_secrets(srv.name),
    )


def _check_hooks(inv: InventoryReport, policy: Policy) -> list[Finding]:
    out: list[Finding] = []
    pol = policy.hooks
    for h in inv.hooks:
        if pol.allowlist_commands:
            cmd = h.command or h.url or ""
            allowed = any(allowed in cmd for allowed in pol.allowlist_commands)
            if not allowed and pol.deny_unknown:
                out.append(_hook_finding(h, pol.severity, "hooks.unknown", "хук не в allowlist"))
        elif pol.deny_unknown:
            out.append(
                _hook_finding(
                    h,
                    pol.severity,
                    "hooks.unknown",
                    "хук не в allowlist (allowlist пуст, deny_unknown=true)",
                )
            )
    return out


def _hook_finding(h: HookEntry, sev, rule_id: str, why: str) -> Finding:  # type: ignore[no-untyped-def]
    cmd = h.command or h.url or "(?)"
    return Finding(
        rule_id=rule_id,
        severity=sev,
        title=f"Неизвестный хук {h.event}/{h.matcher or '*'}",
        description=f"{why}. type={h.type}, target={cmd}",
        source=h.source,
        recommendation="Добавить в hooks.allowlist_commands или удалить из settings.json.",
        matched_value=mask_secrets(cmd),
    )


def _check_skills(inv: InventoryReport, policy: Policy) -> list[Finding]:
    out: list[Finding] = []
    pol = policy.skills
    for s in inv.skills:
        if s.name in pol.allowlist_names:
            continue
        if pol.trusted_dir_hashes and s.dir_hash in pol.trusted_dir_hashes:
            continue
        if pol.deny_all_unknown or pol.allowlist_names or pol.trusted_dir_hashes:
            out.append(_skill_finding(s, pol.severity, "skills.untrusted"))
    return out


def _skill_finding(s: SkillEntry, sev, rule_id: str) -> Finding:  # type: ignore[no-untyped-def]
    return Finding(
        rule_id=rule_id,
        severity=sev,
        title=f"Скилл не доверен: {s.name}",
        description=(
            f"Имя не в allowlist и dir_hash ({s.dir_hash[:12]}…) не в trusted_dir_hashes. "
            f"origin={s.origin}"
        ),
        source=s.path,
        recommendation="Удалить скилл, добавить имя в skills.allowlist_names или хэш в trusted_dir_hashes.",
        matched_value=mask_secrets(s.name),
    )


def _check_permissions(inv: InventoryReport) -> list[Finding]:
    out: list[Finding] = []
    if inv.permissions.dangerously_skip_detected:
        out.append(
            Finding(
                rule_id="permissions.dangerously_skip",
                severity="block",
                title="Обнаружен --dangerously-skip-permissions",
                description="В rc-файлах юзера найден алиас/обёртка с --dangerously-skip-permissions",
                source="~/.bashrc | ~/.zshrc | ~/.profile",
                recommendation="Убрать --dangerously-skip-permissions из shell-конфигов.",
            )
        )
    return out


def _check_settings_parse_errors(inv: InventoryReport) -> list[Finding]:
    out: list[Finding] = []
    for s in inv.settings_sources:
        if s.parse_error:
            out.append(
                Finding(
                    rule_id="settings.parse_error",
                    severity="warn",
                    title=f"Битый settings.json: {s.path}",
                    description=f"Не удалось распарсить: {s.parse_error}",
                    source=s.path,
                    recommendation="Исправить JSON или удалить файл.",
                )
            )
    return out


def _check_agents(inv: InventoryReport, policy: Policy) -> list[Finding]:
    out: list[Finding] = []
    pol = policy.agents
    deny_tools = set(pol.denylist_tools)
    for a in inv.agents:
        if a.name in pol.denylist_names:
            out.append(_agent_finding(a, pol.severity, "agents.denylist", "имя в denylist"))
            continue
        if pol.deny_all_unknown and a.name not in pol.allowlist_names:
            if pol.trusted_file_hashes and a.file_hash in pol.trusted_file_hashes:
                continue
            out.append(
                _agent_finding(
                    a,
                    pol.severity,
                    "agents.unknown",
                    "агент не в allowlist (whitelist-режим)",
                )
            )
            continue
        if deny_tools and a.tools:
            forbidden = sorted(deny_tools.intersection(a.tools))
            if forbidden:
                out.append(
                    _agent_finding(
                        a,
                        pol.severity,
                        "agents.forbidden_tool",
                        f"в tools запрещённые: {', '.join(forbidden)}",
                    )
                )
                continue
        if pol.trusted_file_hashes and a.file_hash not in pol.trusted_file_hashes:
            if not pol.allowlist_names or a.name not in pol.allowlist_names:
                out.append(
                    _agent_finding(
                        a,
                        pol.severity,
                        "agents.untrusted_hash",
                        f"file_hash ({a.file_hash[:12]}…) не в trusted_file_hashes",
                    )
                )
    return out


def _agent_finding(a: AgentEntry, sev, rule_id: str, why: str) -> Finding:  # type: ignore[no-untyped-def]
    return Finding(
        rule_id=rule_id,
        severity=sev,
        title=f"Кастомный субагент: {a.name}",
        description=f"{why}. tools={a.tools or '-'}, model={a.model or '-'}",
        source=a.path,
        recommendation=(
            "Удалить агента из ~/.claude/agents/, добавить имя в agents.allowlist_names "
            "или хэш в trusted_file_hashes."
        ),
        matched_value=mask_secrets(a.name),
    )


def _check_env(inv: InventoryReport, policy: Policy) -> list[Finding]:
    out: list[Finding] = []
    pol = policy.env
    if not pol.denylist_patterns:
        return out
    compiled = []
    for pat in pol.denylist_patterns:
        try:
            compiled.append((pat, re.compile(pat)))
        except re.error:
            continue
    allow = set(pol.allowlist_names)
    for name in inv.env_keys:
        if name in allow:
            continue
        for pat_src, regex in compiled:
            if regex.search(name):
                out.append(
                    Finding(
                        rule_id="env.denylist",
                        severity=pol.severity,
                        title=f"Чувствительная env-переменная: {name}",
                        description=(
                            f"Имя {name!r} мэтчит denylist-паттерн {pat_src!r}. "
                            "Значение не инвентаризировалось, но сам факт хранения "
                            "секретов в settings.json небезопасен."
                        ),
                        source="settings.json:env",
                        recommendation=(
                            "Убрать переменную из settings.json. Использовать секрет-менеджер."
                        ),
                        matched_value=name,
                    )
                )
                break
    return out


def check_inventory(inv: InventoryReport, policy: Policy) -> list[Finding]:
    """Собрать все findings из применения policy к inventory."""
    out: list[Finding] = []
    out.extend(_check_mcp_servers(inv, policy))
    out.extend(_check_hooks(inv, policy))
    out.extend(_check_skills(inv, policy))
    out.extend(_check_agents(inv, policy))
    out.extend(_check_env(inv, policy))
    out.extend(_check_permissions(inv))
    out.extend(_check_settings_parse_errors(inv))
    return out


def exit_code_for_findings(findings: list[Finding]) -> int:
    """0 = clean, 1 = есть warn, 2 = есть block (для CI)."""
    if any(f.severity == "block" for f in findings):
        return 2
    if any(f.severity == "warn" for f in findings):
        return 1
    return 0
