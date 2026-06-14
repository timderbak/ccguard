"""PostToolUse hook stdin parser + dispatcher (TUA-01).

Hot-path budget: <20ms wall-clock per invocation. To stay under budget we:

1. Parse stdin with stdlib ``json`` (no pydantic on the hook hot-path).
2. Compute the 16-hex fingerprint and **immediately drop the raw tool_input
   local** (``del tool_input``) — privacy intent made explicit (T-01-07).
3. INSERT one row into the local SQLite buffer (BEGIN IMMEDIATE; <5ms typical).
4. Hand off to :func:`maybe_spawn_flusher` which forks/spawns a detached
   subprocess. The hook itself never makes a network call.

Failure model: the entire body is wrapped in ``try/except Exception: return 0``.
A malformed stdin, an unwritable buffer, or any other failure surfaces as a
no-op fail-open — Claude Code's tool use is NEVER blocked by an audit failure
(T-01-05).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from ccguard.agent.audit_hook.actor import detect_actor_user
from ccguard.agent.audit_hook.buffer import ToolBufferDB
from ccguard.agent.audit_hook.fingerprint import compute_fingerprint
from ccguard.agent.audit_hook.flusher import maybe_spawn_flusher
from ccguard.agent.config import default_config_dir
from ccguard.agent.signals import extract_signals
from ccguard.agent.signals.overrides_loader import load_overrides

# Lazy imports inside the Read-PI helper keep cold-path cost off the hot
# path (most invocations are NOT Read). Imported at module scope nonetheless
# because the helpers themselves are pure functions and tests monkeypatch them.
from ccguard.agent import read_pi_scan as _read_pi_scan_mod


def _result_status_from_response(
    tool_response: dict[str, Any],
) -> str:
    """Derive ``result_status`` from PostToolUse ``tool_response`` payload.

    Order is significant: an explicit error trumps an interrupt flag.
    """
    if tool_response.get("error") or tool_response.get("success") is False:
        return "error"
    if tool_response.get("interrupted"):
        return "blocked"
    return "success"


def main_cli(stdin_text: str | None = None) -> int:
    """Read PostToolUse stdin → fingerprint → buffer.insert → maybe_spawn_flusher.

    Always returns 0. Any internal failure is swallowed (fail-open).
    """
    try:
        if stdin_text is None:
            import sys

            stdin_text = sys.stdin.read()

        # 1. Parse — tolerate malformed JSON without raising.
        try:
            data = json.loads(stdin_text) if stdin_text.strip() else {}
        except json.JSONDecodeError:
            return 0
        if not isinstance(data, dict):
            return 0

        tool_name = data.get("tool_name") or "(unknown)"
        if not isinstance(tool_name, str):
            tool_name = "(unknown)"

        # ТЗ-01: session_id is a top-level field on the hook payload (NOT inside
        # tool_input), so it is untouched by the `del tool_input` privacy-drop
        # below. Coerce non-str to None so old/odd payloads ingest cleanly.
        session_id = data.get("session_id")
        if not isinstance(session_id, str):
            session_id = None

        tool_input = data.get("tool_input") or {}
        if not isinstance(tool_input, dict):
            tool_input = {}

        # tool_response: tolerate dict or bare string (Read tool sometimes
        # returns the file content directly). Keep raw_response separate
        # from the dict-shape used by _result_status_from_response.
        raw_response = data.get("tool_response")
        if isinstance(raw_response, dict):
            tool_response = raw_response
        else:
            tool_response = {}

        # BACKLOG §6 (Phase 6 / PI-READ): scan Read tool_response content
        # against the PI catalog. We do this BEFORE dropping tool_input so we
        # can grab file_path from it. Failure is silent (fail-open) — audit
        # buffer write below must not be affected.
        if tool_name == "Read":
            _maybe_emit_read_pi_finding(tool_input, raw_response)
        elif tool_name == "WebFetch" or tool_name.startswith("mcp__"):
            # indirect-injection scan of the web page / MCP tool RESULT body
            _maybe_emit_tool_result_pi_finding(tool_name, tool_input, raw_response)

        # 2. Fingerprint + extract signals, THEN drop raw tool_input (privacy
        #    invariant). Both consume the raw input in-process; only the 16-hex
        #    fingerprint and the signal IDs survive this scope.
        fp = compute_fingerprint(tool_name, tool_input)
        # E4: load server-pushed catalog overrides from the synced policy
        # cache. Missing/malformed file degrades to baked CATALOG only.
        overrides = load_overrides(default_config_dir() / "policy.yaml")
        signals = extract_signals(tool_name, tool_input, overrides=overrides)
        del tool_input  # explicit — only `fp` + `signals` survive.

        # 3. Build event fields.
        ts = datetime.now(UTC).isoformat()
        decision = "allow"  # PostToolUse fires only after PreToolUse permitted.
        result_status = _result_status_from_response(tool_response)
        actor_user = detect_actor_user()  # Per-User Attribution

        # 4. INSERT into buffer; capture row_count for flush-threshold check.
        buffer_path = default_config_dir() / "audit_buffer.db"
        with ToolBufferDB(buffer_path) as buf:
            buf.insert(
                ts=ts,
                tool_name=tool_name,
                fingerprint=fp,
                decision=decision,
                result_status=result_status,
                signals=signals,
                actor_user=actor_user,
                session_id=session_id,
            )
            row_count = buf.row_count()

        # 5. Maybe spawn detached flusher (outside CM — connection closed before fork).
        maybe_spawn_flusher(row_count_hint=row_count)
        return 0
    except Exception:
        # Fail-open: never propagate any error back to Claude Code.
        return 0


def _load_pi_cfg_or_default() -> Any:
    """Load PromptInjectionConfig from the local policy.yaml cache.

    Failure (file missing, parse error) → default PromptInjectionConfig
    (enabled=True, severity=warn) so the Read PI scan still runs out of
    the box — admins who explicitly disable PI in policy will see scans
    skipped, but a missing/broken policy MUST NOT silently disable the
    audit detector.
    """
    from ccguard.schemas.policy import PromptInjectionConfig

    try:
        import yaml

        from ccguard.schemas import Policy

        policy_path = default_config_dir() / "policy.yaml"
        if not policy_path.exists():
            return PromptInjectionConfig()
        data = yaml.safe_load(policy_path.read_text()) or {}
        pol = Policy.model_validate(data)
        return pol.prompt_injection
    except Exception:
        return PromptInjectionConfig()


def _maybe_emit_read_pi_finding(
    tool_input: dict[str, Any],
    raw_response: Any,
) -> None:
    """Best-effort scan of Read tool_response for prompt-injection markers.

    Emits a ``prompt_injection.read_file.<category>`` finding when a
    match is found. Silent fail on any error — Claude must never see an
    exception from the audit hook.
    """
    try:
        cfg = _load_pi_cfg_or_default()
        if not cfg.enabled:
            return
        text = _read_pi_scan_mod.extract_read_response_text(raw_response)
        if not text:
            return
        file_path = tool_input.get("file_path")
        if not isinstance(file_path, str):
            file_path = ""
        result = _read_pi_scan_mod.scan_read_text(text, cfg)
        if result is None:
            # P5: the strict catalog missed. If a cheap suspicion heuristic
            # still flags the content, spool it for the server-side LLM
            # backstop (drained on the next sync cycle). Best-effort.
            _maybe_spool_read_escalation(file_path, text)
            return
        # model_missing marker (D-3 from PI engine): never a real detection.
        if result.rule_id == "prompt_injection.llama_guard.model_missing":
            return
        # Find matched substring snippet around the regex hit for the
        # finding's matched_pattern. Capped at 200 chars (mask_secrets
        # enforces the same ceiling).
        snippet = _extract_match_snippet(text, result.matched_pattern)
        # Format the matched_pattern as "<file_path>::<snippet>" so the
        # server can split it back out. file_path may legitimately be
        # empty; the format degrades gracefully.
        composed = f"{file_path}::{snippet}" if file_path else snippet

        from ccguard.agent.findings_hook.buffer import emit_finding

        rule_id = _read_pi_scan_mod.build_rule_id(result)
        emit_finding(
            rule_id=rule_id,
            severity="warn",
            title=f"Признаки prompt injection в файле ({result.category})",
            source="regex",
            matched_pattern=composed,
            tool_name="Read",
        )
    except Exception:
        # Best-effort — never break the audit pipeline.
        return


def _maybe_emit_tool_result_pi_finding(
    tool_name: str,
    tool_input: dict[str, Any],
    raw_response: Any,
) -> None:
    """Scan a WebFetch / MCP tool_response BODY for prompt-injection markers.

    This is the indirect-injection vector ccguard's moat is about: a poisoned
    web page or a malicious MCP tool result fed back into the model as authority.
    Previously only Read content was deep-scanned. Emits
    ``prompt_injection.{web,mcp}_result.<category>`` (a moat TRIGGER the server
    correlates to any later endpoint escalation), and spools regex-misses for the
    server-side LLM backstop. Best-effort / silent (audit hook must never raise).
    """
    try:
        cfg = _load_pi_cfg_or_default()
        if not cfg.enabled:
            return
        text = _read_pi_scan_mod.extract_read_response_text(raw_response)
        if not text:
            return
        if tool_name.startswith("mcp__"):
            channel = "mcp"
            parts = tool_name.split("__")
            identifier = parts[1] if len(parts) > 1 else tool_name  # MCP server name
        else:
            channel = "web"
            url = tool_input.get("url")
            identifier = url if isinstance(url, str) else ""
        result = _read_pi_scan_mod.scan_read_text(text, cfg)
        if result is None:
            # strict catalog missed → queue for the server LLM backstop
            _maybe_spool_read_escalation(identifier or channel, text)
            return
        if result.rule_id == "prompt_injection.llama_guard.model_missing":
            return
        snippet = _extract_match_snippet(text, result.matched_pattern)
        composed = f"{identifier}::{snippet}" if identifier else snippet

        from ccguard.agent.findings_hook.buffer import emit_finding

        base = result.rule_id
        cat = base[len("prompt_injection.") :] if base.startswith("prompt_injection.") else result.category
        rule_id = f"prompt_injection.{channel}_result.{cat}"
        where = "MCP-результате" if channel == "mcp" else "WebFetch-результате"
        emit_finding(
            rule_id=rule_id,
            severity="warn",
            title=f"Признаки prompt injection в {where} ({result.category})",
            source="regex",
            matched_pattern=composed,
            tool_name=tool_name,
        )
    except Exception:
        return


def _maybe_spool_read_escalation(file_path: str, text: str) -> None:
    """Queue regex-missed-but-suspicious read content for the LLM backstop.

    Runs only when the strict PI catalog produced no finding. Lazy imports keep
    the cost off the (common) non-suspicious path. Best-effort and fail-open —
    the audit hook must never raise.
    """
    try:
        from ccguard.agent import read_pi_escalation

        if not read_pi_escalation.should_escalate(text):
            return
        from ccguard.agent import read_scan_spool

        read_scan_spool.spool(file_path, text)
    except Exception:
        return


def _extract_match_snippet(text: str, pattern_str: str, *, window: int = 80) -> str:
    """Return a small substring of ``text`` around the first regex hit.

    Falls back to the first 160 chars of ``text`` if the pattern fails to
    re-compile (admin custom regex is hashed, not the raw source). Truncated
    to ~160 chars so :func:`mask_secrets` (200-char cap) leaves it intact.
    """
    import re as _re

    try:
        m = _re.search(pattern_str, text, _re.IGNORECASE | _re.DOTALL)
    except _re.error:
        m = None
    if m is None:
        return text[: 2 * window]
    start = max(0, m.start() - window // 4)
    end = min(len(text), m.end() + window)
    return text[start:end]
