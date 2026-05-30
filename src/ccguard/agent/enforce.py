"""enforce: горячий путь хука. Читает stdin, применяет policy, выводит hook-формат."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import logging
import re
import sys
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

import yaml

from ccguard.agent.audit import make_audit_logger, write_audit
from ccguard.agent.findings_hook.buffer import emit_finding
from ccguard.agent.prompt_injection_engine import ScanResult
from ccguard.agent.prompt_injection_engine import scan as pi_scan
from ccguard.schemas import (
    AuditEntry,
    EnforceDecision,
    EnforceHookInput,
    Policy,
)

log = logging.getLogger(__name__)

# Phase 5 / 05-03: fields scanned by prompt_injection step. Order matters —
# _extract_pi_payload concatenates in this order so callers see deterministic
# matched_pattern positions when LlamaGuard / regex reports offsets.
_PI_PAYLOAD_FIELDS = ("command", "prompt", "instructions", "description", "content")


def _extract_pi_payload(tool_input: dict) -> str:
    """Concatenate the known string fields of ``tool_input`` for PI scanning.

    Non-string values are silently skipped (defensive: Claude Code tool schemas
    occasionally pass int/None for some fields, and the PI engine takes ``str``).
    Returns ``""`` when no recognized fields exist — the engine short-circuits
    on empty text.
    """
    parts: list[str] = []
    for key in _PI_PAYLOAD_FIELDS:
        v = tool_input.get(key)
        if isinstance(v, str):
            parts.append(v)
    return "\n".join(parts)


def _fingerprint(tool_input: dict) -> str:
    """sha256(json sorted)[:16] — компактный детерминированный fingerprint."""
    raw = json.dumps(tool_input, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


@lru_cache(maxsize=4)
def _load_policy_cached(path: str, mtime_ns: int) -> Policy | None:
    """Underlying cached loader keyed on (path, mtime_ns).

    WR-08: keying on ``mtime_ns`` is what makes the cache safe across
    process re-use — when Claude Code keeps the hook process warm and
    the policy file is rewritten on disk by a new publish, the next
    call sees a different mtime and re-parses. ``mtime_ns=0`` carries
    the "file does not exist" case so the cache still helps the
    no-policy branch.
    """
    p = Path(path)
    if not p.exists():
        return None
    try:
        data = yaml.safe_load(p.read_text()) or {}
        return Policy.model_validate(data)
    except Exception:
        return None


def _load_policy(path: str) -> Policy | None:
    """Загрузить policy из файла.

    WR-08: lru_cache по (path, mtime_ns) — кэш инвалидируется при
    перезаписи файла, что важно если Claude Code держит hook-процесс
    горячим между PreToolUse вызовами и админ опубликовал новую
    политику. Без mtime в ключе кэш возвращал бы устаревшую политику до
    конца жизни процесса.
    """
    p = Path(path)
    try:
        mtime_ns = p.stat().st_mtime_ns if p.exists() else 0
    except OSError:
        mtime_ns = 0
    return _load_policy_cached(path, mtime_ns)


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


def _apply_enforcement_mode(decision: EnforceDecision, policy: Policy) -> EnforceDecision:
    """Honor ``policy.enforcement_mode`` (Stage 5b).

    ``observe`` flips deny → allow while preserving ``rule_id`` and prefixing
    the reason with an ``observe-mode`` tag so downstream audit can detect
    that this was a would-have-blocked call. ``allow`` decisions and any mode
    we don't explicitly recognize are passed through unchanged — unknown
    modes default to the safe ``enforce`` behavior.
    """
    if decision.permission != "deny":
        return decision
    mode = getattr(policy, "enforcement_mode", "enforce")
    if mode != "observe":
        return decision
    return EnforceDecision(
        permission="allow",
        reason=f"observe-mode override (would deny: {decision.reason})",
        rule_id=decision.rule_id,
        fail_open=decision.fail_open,
    )


def decide(payload: EnforceHookInput, policy: Policy) -> EnforceDecision:
    """Маршрутизация по tool_name на конкретный матчер. Только PreToolUse релевантно.

    Stage 5b: после расчёта решения вызывается :func:`_apply_enforcement_mode`,
    который флипает deny → allow при ``policy.enforcement_mode == "observe"``.
    """
    return _apply_enforcement_mode(_decide_inner(payload, policy), policy)


def _decide_inner(payload: EnforceHookInput, policy: Policy) -> EnforceDecision:
    """Inner dispatch — pre-Stage-5b ``decide`` body, no mode override."""
    if payload.hook_event_name != "PreToolUse":
        return EnforceDecision(permission="allow", reason="not PreToolUse")

    # --- Phase 5 / 05-03: prompt-injection step ---
    # Runs BEFORE existing _decide_* dispatch so a block-severity injection match
    # short-circuits with deny. warn/info severity matches emit a finding and
    # fall through to existing rules (so v0.1 enforcement still applies).
    pi_cfg = policy.prompt_injection
    if pi_cfg.enabled:
        text = _extract_pi_payload(payload.tool_input)
        pi_result: ScanResult | None
        try:
            pi_result = pi_scan(text, pi_cfg)
        except Exception as exc:  # engine crash → fail-mode driven
            if policy.block_fail_mode == "closed":
                return EnforceDecision(
                    permission="deny",
                    reason=f"prompt-injection engine error (fail-closed): {exc!r}",
                    rule_id="prompt_injection.engine_error",
                )
            # WR-01: fail-open path now ALSO emits an info finding so the
            # central server has visibility on engine crashes across the
            # fleet (cf. LG model-missing marker). Carry only the exception
            # class name — no message/traceback to avoid leaking user-text
            # snippets embedded in re.error/etc.
            log.warning("prompt_injection engine crashed (fail-open): %r", exc)
            try:
                emit_finding(
                    rule_id="prompt_injection.engine_crash",
                    severity="info",
                    title="Prompt-injection engine crashed (fail-open)",
                    source="regex",
                    matched_pattern=type(exc).__name__,
                    tool_name=payload.tool_name,
                )
            except Exception:
                # emit_finding is best-effort: a buffer-write failure must
                # not turn a successful fail-open into a deny.
                pass
            pi_result = None

        if pi_result is not None:
            # model_missing marker (D-3): NOT a real detection, never blocks.
            # Emitted at info severity regardless of policy.severity.
            if pi_result.rule_id == "prompt_injection.llama_guard.model_missing":
                emit_finding(
                    rule_id=pi_result.rule_id,
                    severity="info",
                    title="LlamaGuard model unavailable on Ollama",
                    source=pi_result.source,
                    matched_pattern=pi_result.matched_pattern,
                    tool_name=payload.tool_name,
                )
                # fall through to existing pipeline
            else:
                emit_finding(
                    rule_id=pi_result.rule_id,
                    severity=pi_cfg.severity,
                    title=f"Prompt-injection match ({pi_result.category})",
                    source=pi_result.source,
                    matched_pattern=pi_result.matched_pattern,
                    tool_name=payload.tool_name,
                )
                if pi_cfg.severity == "block":
                    return EnforceDecision(
                        permission="deny",
                        reason=f"prompt-injection: {pi_result.category}",
                        rule_id=pi_result.rule_id,
                    )
                # warn / info → fall through to existing pipeline
    # --- end Phase 5 step ---

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
