"""enforce: горячий путь хука. Читает stdin, применяет policy, выводит hook-формат."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
import sys
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

import yaml

from ccguard.agent.audit import make_audit_logger, write_audit
from ccguard.schemas import (
    AuditEntry,
    EnforceDecision,
    EnforceHookInput,
    Policy,
)


def _fingerprint(tool_input: dict) -> str:
    """sha256(json sorted)[:16] — компактный детерминированный fingerprint."""
    raw = json.dumps(tool_input, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


@lru_cache(maxsize=4)
def _load_policy(path: str) -> Policy | None:
    """Загрузить policy из файла. lru_cache по path кэширует на время процесса
    (для CLI-вызова это эффективно: процесс короткоживущий)."""
    p = Path(path)
    if not p.exists():
        return None
    try:
        data = yaml.safe_load(p.read_text()) or {}
        return Policy.model_validate(data)
    except Exception:
        return None


def _compile_regexes(patterns: list[str]) -> list[re.Pattern[str]]:
    out: list[re.Pattern[str]] = []
    for p in patterns:
        try:
            out.append(re.compile(p))
        except re.error:
            continue
    return out


def _host_match(host: str, pattern: str) -> bool:
    if "*" in pattern:
        return fnmatch.fnmatchcase(host.lower(), pattern.lower())
    return host.lower() == pattern.lower()


def _decide_bash(command: str, policy: Policy) -> EnforceDecision:
    pol = policy.commands
    for pat in _compile_regexes(pol.always_deny):
        if pat.search(command):
            return EnforceDecision(
                permission="deny",
                reason=f"always_deny: {pat.pattern}",
                rule_id="commands.always_deny",
            )
    if pol.allowlist_patterns:
        compiled = _compile_regexes(pol.allowlist_patterns)
        if not any(p.search(command) for p in compiled):
            return EnforceDecision(
                permission="deny",
                reason="команда не в commands.allowlist_patterns",
                rule_id="commands.allowlist",
            )
    for pat in _compile_regexes(pol.denylist_patterns):
        if pat.search(command):
            return EnforceDecision(
                permission="deny",
                reason=f"denylist: {pat.pattern}",
                rule_id="commands.denylist",
            )
    return EnforceDecision(permission="allow", reason="ok")


def _decide_mcp(tool_name: str, policy: Policy) -> EnforceDecision:
    parts = tool_name.split("__")
    if len(parts) < 2:
        return EnforceDecision(permission="allow", reason="ok")
    server = parts[1]
    pol = policy.mcp_servers
    if server in pol.denylist_names:
        return EnforceDecision(
            permission="deny",
            reason=f"mcp server '{server}' в denylist",
            rule_id="mcp_servers.denylist",
        )
    if pol.deny_all_unknown and server not in pol.allowlist_names:
        return EnforceDecision(
            permission="deny",
            reason=f"mcp server '{server}' не в allowlist (whitelist mode)",
            rule_id="mcp_servers.unknown",
        )
    return EnforceDecision(permission="allow", reason="ok")


def _decide_web(tool_input: dict, policy: Policy) -> EnforceDecision:
    url = tool_input.get("url")
    if not isinstance(url, str) or not url:
        return EnforceDecision(permission="allow", reason="no url")
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return EnforceDecision(permission="allow", reason="malformed url")
    if not host:
        return EnforceDecision(permission="allow", reason="no host")
    pol = policy.network
    for pat in pol.denylist_hosts:
        if _host_match(host, pat):
            return EnforceDecision(
                permission="deny",
                reason=f"host '{host}' мэтчит denylist '{pat}'",
                rule_id="network.denylist",
            )
    if pol.deny_all_unknown:
        if not any(_host_match(host, pat) for pat in pol.allowlist_hosts):
            return EnforceDecision(
                permission="deny",
                reason=f"host '{host}' не в allowlist (whitelist mode)",
                rule_id="network.unknown",
            )
    return EnforceDecision(permission="allow", reason="ok")


def decide(payload: EnforceHookInput, policy: Policy) -> EnforceDecision:
    """Маршрутизация по tool_name на конкретный матчер. Только PreToolUse релевантно."""
    if payload.hook_event_name != "PreToolUse":
        return EnforceDecision(permission="allow", reason="not PreToolUse")

    tool = payload.tool_name
    ti = payload.tool_input
    if tool == "Bash":
        cmd = ti.get("command", "")
        if not isinstance(cmd, str):
            return EnforceDecision(permission="allow", reason="malformed Bash.command")
        return _decide_bash(cmd, policy)
    if tool.startswith("mcp__"):
        return _decide_mcp(tool, policy)
    if tool in ("WebFetch", "WebSearch"):
        return _decide_web(ti, policy)
    return EnforceDecision(permission="allow", reason="tool not in enforce scope")


def render_hook_response(decision: EnforceDecision) -> str:
    """Сериализация в hook-формат Claude Code. allow → пустой stdout."""
    if decision.permission == "allow":
        return ""
    return json.dumps(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": f"ccguard: {decision.rule_id or 'unknown'} — {decision.reason}",
            },
            "suppressOutput": False,
        }
    )


def run_enforce(
    stdin_text: str,
    policy_path: Path,
    audit_path: Path,
    block_fail_mode: str = "open",
    audit_max_bytes: int = 10 * 1024 * 1024,
    audit_backup_count: int = 5,
) -> tuple[int, str]:
    """Точка входа для enforce. Возвращает (exit_code, stdout_text)."""
    audit_logger = make_audit_logger(audit_path, audit_max_bytes, audit_backup_count)
    now = datetime.now(UTC)

    # 1. Parse stdin
    try:
        data = json.loads(stdin_text) if stdin_text.strip() else {}
        payload = EnforceHookInput.model_validate(data)
    except Exception as e:
        # Битый stdin: fail-open + audit.
        write_audit(
            audit_logger,
            AuditEntry(
                timestamp=now,
                tool_name="(invalid_input)",
                decision="allow",
                rule_id=None,
                reason=f"stdin parse error: {e}",
                fail_open=True,
                tool_input_fingerprint="invalid",
            ),
        )
        return 0, ""

    # 2. Load policy
    policy = _load_policy(str(policy_path))
    if policy is None:
        fp = _fingerprint(payload.tool_input)
        if block_fail_mode == "closed":
            decision = EnforceDecision(
                permission="deny",
                reason="ccguard: fail-closed (policy unavailable)",
                rule_id="policy.unavailable",
                fail_open=False,
            )
            write_audit(
                audit_logger,
                AuditEntry(
                    timestamp=now,
                    tool_name=payload.tool_name,
                    decision="deny",
                    rule_id="policy.unavailable",
                    reason=decision.reason,
                    fail_open=False,
                    tool_input_fingerprint=fp,
                ),
            )
            return 0, render_hook_response(decision)
        # fail-open
        write_audit(
            audit_logger,
            AuditEntry(
                timestamp=now,
                tool_name=payload.tool_name,
                decision="allow",
                rule_id=None,
                reason="policy unavailable, fail-open",
                fail_open=True,
                tool_input_fingerprint=fp,
            ),
        )
        return 0, ""

    # 3. Decide
    decision = decide(payload, policy)
    fp = _fingerprint(payload.tool_input)
    write_audit(
        audit_logger,
        AuditEntry(
            timestamp=now,
            tool_name=payload.tool_name,
            decision=decision.permission,
            rule_id=decision.rule_id,
            reason=decision.reason,
            fail_open=False,
            tool_input_fingerprint=fp,
        ),
    )
    return 0, render_hook_response(decision)


def main_cli(
    config_path: Path | None = None,
    policy_path: Path | None = None,
    stdin_text: str | None = None,
) -> int:
    """CLI-обёртка. Читает stdin и пишет stdout, использует AgentConfig."""
    from ccguard.agent.config import default_config_dir, load_or_create

    cfg, _ = load_or_create(config_path)
    p_path = policy_path or cfg.resolved_cache_path()
    audit_path = default_config_dir() / "audit.log"
    block_fail_mode = cfg.policy.block_fail_mode or "open"

    text = stdin_text if stdin_text is not None else sys.stdin.read()
    exit_code, stdout_text = run_enforce(
        text,
        policy_path=p_path,
        audit_path=audit_path,
        block_fail_mode=block_fail_mode,
        audit_max_bytes=cfg.audit.max_bytes,
        audit_backup_count=cfg.audit.backup_count,
    )
    if stdout_text:
        sys.stdout.write(stdout_text)
    return exit_code
