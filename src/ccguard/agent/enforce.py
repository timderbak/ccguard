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

from ccguard.agent import read_pi_scan as read_pi_scan_mod
from ccguard.agent.audit import make_audit_logger, write_audit
from ccguard.agent.bash_url_parser import extract_urls_from_command
from ccguard.agent.signals.cred_exfil import detect_cred_exfil
from ccguard.agent.findings_hook.buffer import emit_finding
from ccguard.agent.network_utils import detect_ip_as_host, is_private_ip
from ccguard.agent.prompt_injection_engine import ScanResult
from ccguard.agent.prompt_injection_engine import scan as pi_scan
from ccguard.agent.signals.destructive import detect_destructive
from ccguard.agent.signals.normalize import normalize_command
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


# Hard-deny rules: actions that are NEVER legitimate from an AI coding agent.
# These BLOCK out of the box — independent of policy and enforcement_mode (observe
# does not flip them). Kept deliberately tiny and zero-FP. Matched against the
# de-obfuscated search text so encoded variants are caught too.
_HARD_DENY_RULES: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (
        re.compile(
            # /dev/tcp|udp reverse shell — require the HOST/PORT shape so the device
            # path as a real channel (redirect, tee, dd, cat) fires while a bare
            # `grep /dev/tcp/ docs` (no host/port) does NOT. Red-team-hardened.
            r"/dev/(?:tcp|udp)/[^/\s]+/\d+"
            # nc/ncat/netcat shell-exec: -e AND long forms --exec/--sh-exec/--lua-exec
            r"|\b(?:nc|ncat|netcat)\b[^\n]*\s(?:-e\b|--exec\b|--sh-exec\b|--lua-exec\b)"
            # named-pipe shell to a network tool (nc / openssl s_client / socat)
            r"|mkfifo\b[^\n]*\|\s*(?:n?cat?|openssl\s+s_client|socat)\b"
            # socat shell-exec: EXEC: and SYSTEM: address types (require the colon)
            r"|socat\b[^\n]*\b(?:exec|system):"
            r"|(?:ba)?sh\s+-i\b[^\n]*>&"
            # gawk/awk /inet/ network reverse shell
            r"|\bg?awk\b[^\n]*/inet/(?:tcp|udp)/"
            # node.js socket → child_process
            r"|\bnode\b[^\n]*(?:net\.(?:connect|createconnection)|require\(['\"]net['\"]\))"
            r"[^\n]*(?:child_process|spawn|exec)"
            # php socket → shell
            r"|\bphp\b[^\n]*(?:fsockopen|pfsockopen|stream_socket_client)"
            r"[^\n]*(?:proc_open|shell_exec|`|/bin/|exec)"
            # lua socket → shell
            r"|\blua[0-9.]*\b[^\n]*socket[^\n]*(?:io\.popen|os\.execute)"
            # perl/ruby socket → shell
            r"|\b(?:perl|ruby)\b[^\n]*(?:socket|tcpsocket|fsockopen|io::socket)"
            r"[^\n]*(?:exec|/bin/(?:sh|bash)|io\.popen|->open|system)"
            # python socket → shell (inline -c or heredoc): connect + a shell-spawn
            r"|socket[^\n]*\.connect\([^\n]*(?:os\.dup2|pty\.spawn"
            r"|os\.system\(['\"]?(?:/bin/)?(?:sh|bash)"
            r"|subprocess\.\w+\(\s*\[?['\"](?:/bin/)?(?:sh|bash))"
            # pty.spawn of a shell — the classic reverse-shell TTY upgrade
            r"|pty\.spawn\(\s*\(?\s*['\"]?(?:/bin/)?(?:sh|bash)\b"
            # GTFOBins / cheat-sheet additions (mirror of c2.reverse_shell)
            r"|\btelnet\b[^\n]*\|[^\n]*(?:/bin/)?(?:ba)?sh[^\n]*\|[^\n]*\btelnet\b"
            r"|mkfifo\b[^\n]*\|\s*telnet"
            r"|\bxterm\b[^\n]*-display\s+\d{1,3}(?:\.\d{1,3}){3}:"
            r"|(?:new-object\s+)?(?:system\.)?net\.sockets\.tcpclient"
            r"|\bpowercat\b[^\n]*-l\b[^\n]*-ep\b|\bpowercat\b[^\n]*\s-e\s"
            r"|net\.Dial\(\s*['\"]tcp['\"][^\n]*exec\.Command\(\s*['\"]?(?:/bin/)?(?:ba)?sh"
            r"|exec\.Command\(\s*['\"](?:/bin/)?(?:ba)?sh[^\n]*net\.Dial"
            r"|TcpStream::connect[^\n]*(?:from_raw_fd|Command::new\(\s*['\"](?:/bin/)?(?:ba)?sh)",
            re.IGNORECASE,
        ),
        "hard.reverse_shell",
        "Reverse shell — интерактивный C2-канал. Это действие никогда не легитимно "
        "и заблокировано из коробки (независимо от режима).",
    ),
    (
        re.compile(
            r"disableallhooks|\bccguard\s+(uninstall|disable|stop|remove)\b"
            r"|\b(uninstall|remove)\s+ccguard\b"
            # anti-tamper: rm/mv/chattr/shred/truncate/redirect-overwrite of the
            # ccguard hook shim or its own config — never legitimate from the agent.
            r"|(?:rm|rmdir|mv|chattr|shred|truncate|unlink|chmod)\b[^\n]*"
            r"(?:\.ccguard[/\\]|ccguard-(?:enforce|audit))"
            r"|>\s*[^\n|]*ccguard-(?:enforce|audit)\b"
            # strip the ccguard hook out of the Claude settings via jq/sed, or
            # delete the hooks block wholesale (which removes the ccguard hook)
            r"|(?:jq|sed)\b[^\n]*ccguard[^\n]*\.claude[/\\]settings"
            r"|(?:jq|sed)\b[^\n]*\.claude[/\\]settings[^\n]*ccguard"
            r"|jq\b[^\n]*del\(\s*\.hooks"
            r"|systemctl\s+(?:--user\s+)?(?:stop|disable|mask)\s+\S*ccguard"
            r"|launchctl\s+(?:unload|bootout|remove)\b[^\n]*ccguard"
            r"|(pkill|killall|kill)\b[^\n]*\b(falcon|crowdstrike|osquery|auditd|sentinelone|ccguard)\b",
            re.IGNORECASE,
        ),
        "hard.disable_security",
        "Попытка отключить ccguard / EDR-сенсор (impair defenses). Заблокировано "
        "из коробки — снять защиту можно только через консоль, не командой агента.",
    ),
)


# File-write tools. Their PreToolUse `content` is the agent's OWN output being
# persisted — NOT untrusted input being acted on — so the prompt-injection block
# step is skipped for them (else writing a security doc / PI test-fixture / the
# PI catalog itself would self-block). They get the target-based hard-deny only.
_WRITE_TOOLS: tuple[str, ...] = ("Write", "Edit", "MultiEdit")

# Write/Edit hard-deny target: dropping a key into ~/.ssh/authorized_keys is
# attacker-key persistence — never legitimate from an AI coding agent. Target is
# what matters (any content is bad), so this is path-based and FP≈0. Matches the
# file anywhere in the path (`~/`, absolute, relative), `/` or `\` separators.
_HARD_DENY_WRITE_TARGET: re.Pattern[str] = re.compile(
    r"(?:^|[/\\])\.ssh[/\\]authorized_keys2?$", re.IGNORECASE
)

# anti-tamper: ccguard's OWN internals — the agent has no legitimate reason to
# write its policy/config/shim (that is admin-console territory). FP≈0.
_HARD_DENY_CCGUARD_TARGET: re.Pattern[str] = re.compile(
    r"(?:^|[/\\])\.ccguard[/\\](?:policy|config)\.ya?ml$"
    r"|ccguard-(?:enforce|audit)(?:-bin)?$",
    re.IGNORECASE,
)
# Claude settings file that carries the PreToolUse hook entries.
_CLAUDE_SETTINGS: re.Pattern[str] = re.compile(
    r"(?:^|[/\\])\.claude[/\\]settings(?:\.local)?\.json$", re.IGNORECASE
)


def _decide_write(tool_input: dict) -> EnforceDecision:
    """Write/Edit hard-deny (blocks even in observe): attacker-key persistence
    (~/.ssh/authorized_keys) and ANTI-TAMPER — the agent disabling its own
    protection by editing ccguard's config/shim or stripping the ccguard hook out
    of the Claude settings. Everything else passes through."""
    fp = tool_input.get("file_path")
    if not isinstance(fp, str) or not fp:
        return EnforceDecision(permission="allow", reason="no file_path")
    target = fp.strip()
    if _HARD_DENY_WRITE_TARGET.search(target):
        return EnforceDecision(
            permission="deny",
            reason=(
                "Запись в ~/.ssh/authorized_keys — установка attacker-ключа "
                "(persistence / backdoor). Заблокировано из коробки: это действие "
                "никогда не легитимно для AI-агента."
            ),
            rule_id="hard.ssh_authorized_keys_write",
            hard_deny=True,
        )
    if _HARD_DENY_CCGUARD_TARGET.search(target):
        return EnforceDecision(
            permission="deny",
            reason=(
                "Правка собственного конфига/шима ccguard — попытка снять защиту "
                "(anti-tamper). Заблокировано из коробки: ccguard настраивается "
                "только через консоль, не командой агента."
            ),
            rule_id="hard.ccguard_self_tamper",
            hard_deny=True,
        )
    # Editing the Claude settings.json in a way that touches the ccguard hook
    # entry = removing/neutering enforcement. Precise: a generic config edit is
    # allowed; only one whose touched region mentions ccguard is blocked.
    if _CLAUDE_SETTINGS.search(target):
        # Precise: a generic settings edit is fine; only one whose REMOVED region
        # (old_string) mentions ccguard while the replacement doesn't is tamper.
        # A full Write overwrite can't be told from a legit fresh config, so it is
        # NOT blocked here (documented residual — same-user architectural limit).
        old = tool_input.get("old_string")
        new = tool_input.get("new_string")
        old_has = isinstance(old, str) and "ccguard" in old.lower()
        edit_removes = old_has and not (isinstance(new, str) and "ccguard" in new.lower())
        if edit_removes:
            return EnforceDecision(
                permission="deny",
                reason=(
                    "Изменение Claude settings.json, удаляющее/меняющее ccguard-хук "
                    "(снятие enforcement). Заблокировано из коробки (anti-tamper)."
                ),
                rule_id="hard.ccguard_hook_tamper",
                hard_deny=True,
            )
    return EnforceDecision(permission="allow", reason="ok")


def _bash_hard_deny(search_text: str) -> EnforceDecision | None:
    """Never-legitimate Bash actions that block regardless of policy/mode.

    Shared by :func:`_decide_bash` (normal path) and :func:`_hard_deny_only`
    (policy-unavailable path) so the two can never diverge. ``search_text`` is
    the raw command joined with its de-obfuscated form. Needs no policy — the
    rules are module constants — which is exactly why it can run even when the
    policy failed to load (A1)."""
    for rx, rid, reason in _HARD_DENY_RULES:
        if rx.search(search_text):
            return EnforceDecision(
                permission="deny", reason=reason, rule_id=rid, hard_deny=True
            )
    # Single-command credential exfil: read a cred store AND send it out in one
    # command (cred file is the egress payload). FP-safe → hard-block before the
    # secret leaves the machine.
    if detect_cred_exfil(search_text):
        return EnforceDecision(
            permission="deny",
            reason=(
                "Чтение секрет-стора и отправка его наружу в одной команде "
                "(угон ключей). Заблокировано из коробки — секрет не должен "
                "покинуть машину."
            ),
            rule_id="hard.cred_exfil",
            hard_deny=True,
        )
    return None


def _decide_bash(command: str, policy: Policy) -> EnforceDecision:
    pol = policy.commands

    # P1: de-obfuscate ONCE. Deny-path matchers (dangerous / destructive /
    # network / always_deny / denylist) search the normalized text so
    # base64/$IFS/var-indirection bypasses are closed. The allowlist check
    # deliberately stays on the RAW command — normalization must never loosen
    # an allow rule. normalize_command is fail-open (returns raw on any error).
    norm = normalize_command(command)
    search_text = command + "\n" + norm.text

    # Hard-deny tier FIRST: never-legitimate actions block regardless of mode.
    # Shared with the policy-unavailable path via _bash_hard_deny (A1) so the
    # two can never diverge.
    hard = _bash_hard_deny(search_text)
    if hard is not None:
        return hard

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
        if not compiled.search(search_text):
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

    # P1.5 / Destructive-by-dangerous-target (ТЗ-IMPACT): rm/db/overwrite of a
    # SENSITIVE target (NOT an allowlisted safe path). Shares
    # ``detect_destructive`` with the audit-signal path so PREV (this block) and
    # DETECT (the impact.* signal) never diverge. delete/overwrite → block;
    # `db` → warn only (SQL target-awareness is imperfect; emit a finding, never
    # a hard block, to keep false positives off the enforce path). Either way the
    # rule_id starts with "dangerous." so the existing finding emitter records it
    # (and observe-mode still emits without blocking → DETECT).
    destructive_cat = detect_destructive(command) or detect_destructive(norm.text)
    if destructive_cat is not None:
        rid = f"dangerous.destructive/{destructive_cat}"
        if destructive_cat == "db":
            if rid not in warning_signals:
                warning_signals.append(rid)
        else:
            return EnforceDecision(
                permission="deny",
                reason=(
                    f"Деструктивное действие по чувствительной цели ({destructive_cat}); "
                    "T1485 Data Destruction. Используй безопасную цель из allowlist "
                    "или выполни вручную."
                ),
                rule_id=rid,
                warning_signals=warning_signals,
            )

    # P1 / Suspicious network calls: если команда вытаскивает URL через
    # curl/wget/http/nc — проверяем хост по тому же каталогу, что и WebFetch.
    # Делаем ПОСЛЕ dangerous_patterns (у них своя структурированная reason),
    # но ПЕРЕД always_deny/denylist (хотим показать понятный «почему» вместо
    # голого regex).
    urls = norm.urls or extract_urls_from_command(command)
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
        if pat.search(search_text):
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
        if pat.search(search_text):
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


def _hard_deny_only(payload: EnforceHookInput) -> EnforceDecision | None:
    """Policy-independent hard-deny tier for the policy-unavailable path.

    Returns a hard-deny decision when a never-legitimate action is detected
    (reverse shell / single-command cred-exfil / anti-tamper / attacker-key
    persistence), else ``None``. Mirrors the hard-deny branches of
    :func:`decide` but needs no :class:`Policy`, so corrupting/removing the
    policy file can no longer silently disable these blocks (A1)."""
    if payload.hook_event_name != "PreToolUse":
        return None
    tool = payload.tool_name
    ti = payload.tool_input
    if tool == "Bash":
        cmd = ti.get("command", "")
        if not isinstance(cmd, str):
            return None
        norm = normalize_command(cmd)
        return _bash_hard_deny(cmd + "\n" + norm.text)
    if tool in _WRITE_TOOLS:
        decision = _decide_write(ti)
        return decision if decision.hard_deny else None
    return None


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
    # Hard deny is never-legitimate → block even in observe mode.
    if decision.hard_deny:
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
    if pi_cfg.enabled and payload.tool_name not in _WRITE_TOOLS:
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
    if tool == "Read":
        # BACKLOG §6 PI-READ: opt-in PreToolUse block of Read on PI-containing
        # files. Disk-read happens only when the flag is on AND the engine is
        # enabled — keeps the hot path zero-cost for the default config.
        return _decide_read(ti, policy)
    if tool in _WRITE_TOOLS:
        # B.6: target-based hard-deny for never-legitimate write targets
        # (~/.ssh/authorized_keys). PI step already skipped for these tools.
        return _decide_write(ti)
    return EnforceDecision(permission="allow", reason="tool not in enforce scope")


def _decide_read(tool_input: dict, policy: Policy) -> EnforceDecision:
    """Read tool — opt-in PreToolUse PI scan of the on-disk file content.

    Allow-by-default. Only when both ``prompt_injection.enabled=True`` AND
    ``prompt_injection.read_pi_block=True`` we read the file from disk
    (up to 50 KB, text-only extensions) and run the default PI catalog.
    On match we return deny with a structured rule_id; the caller wraps
    the result in :func:`_apply_enforcement_mode` so observe mode still
    flips this to allow + audit.
    """
    pi_cfg = policy.prompt_injection
    if not pi_cfg.enabled or not pi_cfg.read_pi_block:
        return EnforceDecision(permission="allow", reason="read_pi_block disabled")
    file_path = tool_input.get("file_path")
    if not isinstance(file_path, str) or not file_path:
        return EnforceDecision(permission="allow", reason="no file_path")

    text = read_pi_scan_mod.read_file_truncated(file_path)
    if not text:
        return EnforceDecision(permission="allow", reason="file unreadable or non-text")

    try:
        result = read_pi_scan_mod.scan_read_text(text, pi_cfg)
    except Exception:
        # Engine crash on Read content → fail-open. We deliberately do NOT
        # honor block_fail_mode="closed" here: a closed-fail on every Read
        # would brick the agent the moment a regex misbehaves on benign text.
        return EnforceDecision(permission="allow", reason="pi-scan engine error")

    if result is None:
        return EnforceDecision(permission="allow", reason="no PI markers in file")
    if result.rule_id == "prompt_injection.llama_guard.model_missing":
        return EnforceDecision(permission="allow", reason="lg model missing — ignored on Read")

    rule_id = read_pi_scan_mod.build_rule_id(result)
    return EnforceDecision(
        permission="deny",
        reason=(
            f"файл '{file_path}' содержит признаки prompt injection "
            f"({result.category}); чтение заблокировано"
        ),
        rule_id=rule_id,
    )


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
        # A1: the never-legitimate hard-deny tier needs no policy, so run it even
        # when the policy is unavailable. Otherwise corrupting/removing the
        # policy file would silently disable anti-tamper / reverse-shell /
        # cred-exfil blocks — a clean fail-open bypass of the whole hard tier.
        hard = _hard_deny_only(payload)
        if hard is not None:
            write_audit(
                audit_logger,
                AuditEntry(
                    timestamp=now,
                    tool_name=payload.tool_name,
                    decision="deny",
                    rule_id=hard.rule_id,
                    reason=hard.reason,
                    fail_open=False,
                    tool_input_fingerprint=fp,
                ),
            )
            return 0, render_hook_response(hard)
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
