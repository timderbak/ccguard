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
from typing import Any
from urllib.parse import urlparse

import yaml

from ccguard.agent.audit import make_audit_logger, write_audit
from ccguard.agent.bash_url_parser import extract_urls_from_command
from ccguard.agent.findings_hook.buffer import emit_finding
from ccguard.agent.network_utils import detect_ip_as_host, is_private_ip
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


@lru_cache(maxsize=512)
def _compile_one(pattern: str) -> re.Pattern[str] | None:
    """LRU-кэш одной regex'ы для горячего пути PreToolUse.

    Latency-budget P1: dangerous_patterns содержат 8+ правил, и в стационарном
    режиме все они одни и те же между вызовами — без кэша мы бы пересобирали
    их на каждый PreToolUse. ``lru_cache`` на pattern-строке надёжно работает,
    так как regex-строка иммутабельна и хешируема.

    Возвращает ``None`` на невалидной regex (как и ``_compile_regexes``), чтобы
    плохое правило в политике не валило весь хук.
    """
    try:
        return re.compile(pattern)
    except re.error:
        return None


def _host_match(host: str, pattern: str) -> bool:
    if "*" in pattern:
        return fnmatch.fnmatchcase(host.lower(), pattern.lower())
    return host.lower() == pattern.lower()


def _decide_bash(command: str, policy: Policy) -> EnforceDecision:
    pol = policy.commands

    # P1 / Dangerous Bash Patterns: проверяем СНАЧАЛА — у этих правил есть
    # «почему опасно» и «что делать», и они должны побеждать always_deny /
    # denylist в reason'е (понятнее для пользователя).
    # Severity=warn копится в warning_signals и пробрасывается дальше — НЕ
    # блокирует, но попадает в audit/finding.
    warning_signals: list[str] = []
    for rule in pol.dangerous_patterns:
        compiled = _compile_one(rule.pattern)
        if compiled is None:
            continue
        if not compiled.search(command):
            continue
        rid = f"dangerous.{rule.id}"
        if rule.severity == "block":
            return EnforceDecision(
                permission="deny",
                reason=f"{rule.title}. {rule.reason} {rule.remediation}",
                rule_id=rid,
                warning_signals=warning_signals,
            )
        # warn — копим, но не возвращаем сразу: пусть остальные правила
        # тоже отработают (включая последующий block в denylist).
        warning_signals.append(rid)

    # P1 / Suspicious network calls: если команда вытаскивает URL через
    # curl/wget/http/nc — проверяем хост по тому же каталогу, что и WebFetch.
    # Делаем ПОСЛЕ dangerous_patterns (у них своя структурированная reason),
    # но ПЕРЕД always_deny/denylist (хотим показать понятный «почему» вместо
    # голого regex).
    urls = extract_urls_from_command(command)
    for u in urls:
        decision, net_warnings = _check_network_target(u, policy)
        for w in net_warnings:
            if w not in warning_signals:
                warning_signals.append(w)
        if decision is not None and decision.permission == "deny":
            # Возвращаем deny с warning_signals (как накопили + те, что
            # пришли из _check_network_target).
            return EnforceDecision(
                permission="deny",
                reason=decision.reason,
                rule_id=decision.rule_id,
                warning_signals=warning_signals,
            )

    for pat in _compile_regexes(pol.always_deny):
        if pat.search(command):
            return EnforceDecision(
                permission="deny",
                reason=f"always_deny: {pat.pattern}",
                rule_id="commands.always_deny",
                warning_signals=warning_signals,
            )
    if pol.allowlist_patterns:
        compiled = _compile_regexes(pol.allowlist_patterns)
        if not any(p.search(command) for p in compiled):
            return EnforceDecision(
                permission="deny",
                reason="команда не в commands.allowlist_patterns",
                rule_id="commands.allowlist",
                warning_signals=warning_signals,
            )
    for pat in _compile_regexes(pol.denylist_patterns):
        if pat.search(command):
            return EnforceDecision(
                permission="deny",
                reason=f"denylist: {pat.pattern}",
                rule_id="commands.denylist",
                warning_signals=warning_signals,
            )
    return EnforceDecision(
        permission="allow",
        reason="ok",
        warning_signals=warning_signals,
    )


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


def _parse_url(url: str) -> tuple[str, str] | None:
    """Возвращает (hostname, host_path) или None если URL не разобран.

    ``host_path`` = ``hostname + path`` (без схемы/query) — для URL-aware
    fnmatch вроде ``discord.com/api/webhooks/*``.

    Также принимает голый host (``1.2.3.4`` / ``example.com:8080``) —
    оборачиваем в http:// чтобы urlparse корректно вытащил hostname.
    """
    if not isinstance(url, str) or not url:
        return None
    candidate = url
    if "://" not in candidate:
        candidate = "http://" + candidate
    try:
        parsed = urlparse(candidate)
    except ValueError:
        return None
    host = (parsed.hostname or "").lower()
    if not host:
        return None
    path = parsed.path or ""
    return host, f"{host}{path}"


def _suspicious_match(rule: Any, host: str, host_path: str) -> bool:
    """Проверить SuspiciousHostRule против hostname/host_path.

    Спец-id'шники для детекторов (``egress/ip-as-host``, ``egress/private-ip``)
    обходят pattern-match и зовут хелперы из network_utils.
    """
    if rule.id == "egress/ip-as-host":
        return detect_ip_as_host(host)
    if rule.id == "egress/private-ip":
        return is_private_ip(host)
    pat = rule.pattern
    if rule.type == "glob":
        # URL-aware: если в pattern есть '/', матчим против host_path,
        # иначе только против host.
        target = host_path if "/" in pat else host
        return fnmatch.fnmatchcase(target.lower(), pat.lower())
    if rule.type == "regex":
        compiled = _compile_one(pat)
        if compiled is None:
            return False
        target = host_path if "/" in pat else host
        return bool(compiled.search(target))
    return False


def _check_network_target(
    url: str, policy: Policy
) -> tuple[EnforceDecision | None, list[str]]:
    """Проверить URL/host против network policy.

    Возвращает ``(decision_or_None, warning_signals)``:

    * ``decision`` != None → терминальное решение (deny от denylist /
      whitelist mode / suspicious block). Вызывающий должен сразу его вернуть.
    * ``decision`` is None → нет блока, но могут быть warning_signals
      (suspicious severity=warn). Вызывающий копит их и решает дальше.
    """
    warnings: list[str] = []
    parsed = _parse_url(url)
    if parsed is None:
        return None, warnings
    host, host_path = parsed
    pol = policy.network
    for pat in pol.denylist_hosts:
        if _host_match(host, pat):
            return (
                EnforceDecision(
                    permission="deny",
                    reason=f"host '{host}' мэтчит denylist '{pat}'",
                    rule_id="network.denylist",
                ),
                warnings,
            )
    if pol.deny_all_unknown:
        if not any(_host_match(host, pat) for pat in pol.allowlist_hosts):
            return (
                EnforceDecision(
                    permission="deny",
                    reason=f"host '{host}' не в allowlist (whitelist mode)",
                    rule_id="network.unknown",
                ),
                warnings,
            )
    # Suspicious host catalog.
    # Если host явно в allowlist — пропускаем suspicious checks (admin сказал OK).
    if any(_host_match(host, pat) for pat in pol.allowlist_hosts):
        return None, warnings
    for rule in pol.suspicious_host_rules:
        if not _suspicious_match(rule, host, host_path):
            continue
        rid = f"network.suspicious.{rule.id}"
        if rule.severity == "block":
            return (
                EnforceDecision(
                    permission="deny",
                    reason=f"{rule.title}. {rule.reason} {rule.remediation}",
                    rule_id=rid,
                    warning_signals=warnings,
                ),
                warnings,
            )
        # warn — копим и идём дальше (другие правила могут заблочить).
        if rid not in warnings:
            warnings.append(rid)
    return None, warnings


def _decide_web(tool_input: dict, policy: Policy) -> EnforceDecision:
    url = tool_input.get("url")
    if not isinstance(url, str) or not url:
        return EnforceDecision(permission="allow", reason="no url")
    decision, warnings = _check_network_target(url, policy)
    if decision is not None:
        return decision
    return EnforceDecision(permission="allow", reason="ok", warning_signals=warnings)


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
        warning_signals=decision.warning_signals,
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
    _emit_dangerous_findings(decision, payload, policy)
    return 0, render_hook_response(decision)


def _emit_dangerous_findings(
    decision: EnforceDecision,
    payload: EnforceHookInput,
    policy: Policy,
) -> None:
    """Pipe dangerous.* блок-решения и warn-сигналы в findings_buffer.

    Делается ПОСЛЕ записи в audit и обязательно best-effort: buffer-fail не
    должен превратить успешный allow/deny в crash хука.

    Emit'им:
    * Сам block (decision.rule_id startswith "dangerous.")
    * Каждый warning_signal (severity=warn правила, которые не блокировали).
    * Observe-mode override deny→allow тоже emit'им, если rule_id остался
      dangerous.* — иначе SOC потеряет видимость в observe-режиме.

    Подкачиваем title/reason/remediation из policy.commands.dangerous_patterns,
    чтобы матч rule_id → правило. Если правила нет (custom rule_id) — emit'им
    минимальный finding с rule_id и фрагментом команды.
    """
    try:
        cmd = ""
        if payload.tool_name == "Bash":
            raw = payload.tool_input.get("command", "")
            if isinstance(raw, str):
                cmd = raw[:200]

        by_id: dict[str, Any] = {
            f"dangerous.{r.id}": r for r in policy.commands.dangerous_patterns
        }

        emitted_ids: set[str] = set()

        def _emit(rule_id: str, severity: str) -> None:
            if rule_id in emitted_ids:
                return
            emitted_ids.add(rule_id)
            rule = by_id.get(rule_id)
            title = (
                rule.title
                if rule is not None
                else f"Опасная Bash-команда ({rule_id})"
            )
            try:
                emit_finding(
                    rule_id=rule_id,
                    severity=severity,
                    title=title,
                    source="dangerous_bash",
                    matched_pattern=cmd or rule_id,
                    tool_name=payload.tool_name,
                )
            except Exception:
                # buffer недоступен → silent fail, hook остаётся живым.
                pass

        # block-уровень: decision.rule_id может быть dangerous.* при deny ИЛИ
        # при observe-mode override (permission=allow, rule_id сохранён).
        rid = decision.rule_id or ""
        if rid.startswith("dangerous."):
            _emit(rid, "block")

        for w in decision.warning_signals:
            _emit(w, "warn")
    except Exception:
        # Defensive — finding emission НЕ должен ломать enforce.
        return


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
