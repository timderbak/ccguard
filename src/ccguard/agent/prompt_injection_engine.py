"""Prompt-injection scan engine (Phase 5 / 05-02).

Pure-function entry point ``scan(text, cfg) -> ScanResult | None`` with the
following gate order:

    1. cfg.enabled / empty text early-exit
    2. NFKC + casefold normalize (D-4)
    3. Allowlist early-exit (exact substring OR ``re:``-prefix regex)
    4. Default catalog regex scan (curated 15-pattern set)
    5. Admin custom regex scan (cfg.regex_patterns)
    6. Optional LlamaGuard deep-scan (only when steps 4-5 produced nothing)

Design contract (per 05-RESEARCH §"Pattern 1: Pure-Function Engine"):

- Engine is **pure** except for an optional HTTP call to a self-hosted
  Ollama endpoint inside ``_llama_guard_scan``.
- Engine does NOT swallow unexpected exceptions from its own internals —
  the caller (``enforce.decide()`` from plan 05-03) wraps the call and
  applies the policy-level ``block_fail_mode`` (open/closed). The only
  silencing happens inside ``_llama_guard_scan`` itself, where every
  network/parse failure becomes ``None`` (fail-open per D-2 / D-3).
- Model-missing on Ollama emits a marker ``ScanResult`` with rule_id
  ``prompt_injection.llama_guard.model_missing`` (D-3 locked decision):
  it signals "deep-scan not available" without being itself a finding
  that blocks tool use — severity is determined by the caller.

Latency budget (perf test enforces 30ms on 4KB × 30 admin patterns):
- Compiled patterns are cached via ``functools.lru_cache`` keyed on the
  patterns tuple, so steady-state cost is N regex searches.
- LlamaGuard adds up to ``cfg.timeout_ms`` of wall-clock per scan and is
  intentionally OUT of the regex budget (gated by ``llama_guard.enabled``).
"""

from __future__ import annotations

import hashlib
import logging
import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from typing import Literal

import httpx

from ccguard.agent.prompt_injection_patterns import get_default_patterns
from ccguard.agent.prompt_injection_safety import (
    is_structurally_unsafe,
    probe_redos_safe,
)
from ccguard.schemas.policy import LlamaGuardConfig, PromptInjectionConfig

log = logging.getLogger(__name__)

Source = Literal["regex", "llama_guard", "allowlist"]

# Bound on ``matched_pattern`` length emitted in findings. Pattern sources
# can be arbitrary admin-supplied regex; truncating prevents finding-payload
# blow-up. LlamaGuard category fragments use the tighter 50-char budget.
_MAX_PATTERN_LEN = 200
_MAX_LG_CAT_LEN = 50
_MAX_LG_INPUT_CHARS = 4096

_ADMIN_FLAGS = re.IGNORECASE | re.DOTALL


@dataclass(frozen=True, slots=True)
class ScanResult:
    """Single finding produced by ``scan()``. Frozen for cache/safety."""

    category: str
    matched_pattern: str
    source: Source
    rule_id: str


def _normalize(s: str) -> str:
    """NFKC + casefold per locked D-4. Idempotent.

    Note: NFKC does NOT collapse Cyrillic homoglyphs (e.g., U+0456 'і' vs
    Latin 'i' U+0069) — those are distinct codepoints. The Cyrillic smoke
    pattern in the default catalog covers the dedicated RU branch.
    """
    return unicodedata.normalize("NFKC", s).casefold()


@lru_cache(maxsize=4)
def _compiled_admin(patterns_tuple: tuple[str, ...]) -> tuple[re.Pattern[str], ...]:
    """Compile admin custom patterns; silently skip invalid or ReDoS-unsafe regex.

    Validation happens on the server at publish-time (plan 05-05), but admin
    patterns can also reach the agent via hand-edited YAML or pre-Phase-5
    policies. CR-01 defense-in-depth: structurally reject nested-quantifier
    shapes and run a 50ms adversarial probe on each compiled pattern. Slow
    patterns are dropped with a warning log; the PreToolUse hook stays
    inside its 100ms budget regardless of policy source.
    """
    out: list[re.Pattern[str]] = []
    for raw in patterns_tuple:
        if is_structurally_unsafe(raw):
            log.warning(
                "prompt_injection: dropping structurally-unsafe admin pattern "
                "(nested quantifier): hash=%s",
                hashlib.sha256(raw.encode()).hexdigest()[:12],
            )
            continue
        try:
            compiled = re.compile(raw, _ADMIN_FLAGS)
        except re.error:
            continue
        if not probe_redos_safe(compiled):
            log.warning(
                "prompt_injection: dropping admin pattern that exceeded "
                "ReDoS probe budget: hash=%s",
                hashlib.sha256(raw.encode()).hexdigest()[:12],
            )
            continue
        out.append(compiled)
    return tuple(out)


@lru_cache(maxsize=4)
def _compiled_allowlist(
    patterns_tuple: tuple[str, ...],
) -> tuple[re.Pattern[str] | str, ...]:
    """Allowlist entries: ``re:<regex>`` compiles; everything else is
    casefolded as a substring check against normalized input."""
    out: list[re.Pattern[str] | str] = []
    for raw in patterns_tuple:
        if raw.startswith("re:"):
            try:
                out.append(re.compile(raw[3:], _ADMIN_FLAGS))
            except re.error:
                # Same skip-policy as admin patterns.
                continue
        else:
            out.append(raw.casefold())
    return tuple(out)


def scan(text: str, cfg: PromptInjectionConfig) -> ScanResult | None:
    """Run the prompt-injection scan; return first match or ``None``.

    See module docstring for the full gate order. Caller is responsible for
    fail-mode handling around unexpected exceptions from this function.
    """
    if not cfg.enabled or not text:
        return None

    norm = _normalize(text)

    # 1) Allowlist early-exit — admin says "this text is fine, stop checking".
    for entry in _compiled_allowlist(tuple(cfg.allowlist_patterns)):
        if isinstance(entry, str):
            if entry and entry in norm:
                return None
        else:
            if entry.search(norm):
                return None

    # 2) Default catalog scan.
    for category, pattern in get_default_patterns():
        if pattern.search(norm):
            return ScanResult(
                category=category,
                matched_pattern=pattern.pattern[:_MAX_PATTERN_LEN],
                source="regex",
                rule_id=f"prompt_injection.{category}",
            )

    # 3) Admin custom regex scan.
    # CR-03 privacy: do NOT ship raw regex source upstream — admin patterns
    # can encode secret shapes (e.g. `password=([A-Za-z0-9]{16,})`),
    # internal hostnames, employee names, or licensed content. Emit a
    # generic positional placeholder + a stable hash so admins can
    # correlate locally without leaking the source. The default catalog
    # keeps the raw source (it is public).
    for idx, pattern in enumerate(_compiled_admin(tuple(cfg.regex_patterns)), start=1):
        if pattern.search(norm):
            pattern_hash = hashlib.sha256(pattern.pattern.encode()).hexdigest()[:12]
            return ScanResult(
                category="admin_custom",
                matched_pattern=f"[admin pattern {idx}] sha256:{pattern_hash}",
                source="regex",
                rule_id="prompt_injection.admin_custom",
            )

    # 4) Optional LlamaGuard deep-scan — runs uniformly across severities
    #    (D-2: severity=info/warn/block all reach this step).
    if cfg.llama_guard.enabled:
        result = _llama_guard_scan(text, cfg.llama_guard)
        if result is not None:
            return result

    return None


# --- LlamaGuard (Ollama) deep-scan -----------------------------------------

# LlamaGuard 3 chat template. The user_text is delimited by explicit BEGIN/END
# CONVERSATION markers so a crafted input cannot escape into the rubric. S14
# ("Code Interpreter Abuse") is the closest first-party MLCommons category
# for tool-use abuse, which is the threat we care about most.
_LG_PROMPT_TEMPLATE = """Task: Check if there is unsafe content in 'User' messages in conversations according our safety policy with the below categories.

<BEGIN UNSAFE CONTENT CATEGORIES>
S1: Violent Crimes.
S2: Non-Violent Crimes.
S6: Specialized Advice.
S8: Intellectual Property.
S10: Hate.
S13: Elections.
S14: Code Interpreter Abuse.
<END UNSAFE CONTENT CATEGORIES>

<BEGIN CONVERSATION>
User: {user_text}
<END CONVERSATION>

Provide your safety assessment for ONLY THE LAST User message in the above conversation:
 - First line must read 'safe' or 'unsafe'.
 - If unsafe, a second line must include a comma-separated list of violated categories."""


def _llama_guard_scan(
    text: str, cfg: LlamaGuardConfig
) -> ScanResult | None:
    """Deep-scan ``text`` via a self-hosted Ollama LlamaGuard model.

    Returns:
        - ``None`` on safe verdict OR any network/parse failure (fail-open
          per D-2).
        - Marker ``ScanResult`` with rule_id
          ``prompt_injection.llama_guard.model_missing`` when the model is
          not loaded on Ollama (404 OR 200 with ``{"error": "...not found"}``)
          per D-3.
        - Regular ``ScanResult`` with source ``llama_guard`` on unsafe
          verdict.
    """
    truncated = text[:_MAX_LG_INPUT_CHARS]
    payload = {
        "model": cfg.model,
        "prompt": _LG_PROMPT_TEMPLATE.format(user_text=truncated),
        "stream": False,
        "options": {"temperature": 0.0, "num_predict": 16},
    }

    try:
        with httpx.Client(timeout=cfg.timeout_ms / 1000.0) as client:
            resp = client.post(f"{cfg.endpoint}/api/generate", json=payload)
    except (httpx.HTTPError, httpx.TimeoutException):
        return None

    # Model-missing branch (D-3): 404 from Ollama.
    if resp.status_code == 404:
        return ScanResult(
            category="llama_guard.model_missing",
            matched_pattern=f"model {cfg.model} not loaded on Ollama",
            source="llama_guard",
            rule_id="prompt_injection.llama_guard.model_missing",
        )

    if resp.status_code != 200:
        return None

    try:
        body = resp.json()
    except (ValueError, TypeError):
        return None
    if not isinstance(body, dict):
        return None

    # Ollama sometimes returns 200 with an error payload when the model
    # is missing. Map that to the same marker (D-3).
    error_msg = body.get("error")
    if isinstance(error_msg, str):
        lowered = error_msg.lower()
        if "not found" in lowered or ("model" in lowered and "not" in lowered):
            return ScanResult(
                category="llama_guard.model_missing",
                matched_pattern=f"model {cfg.model} not loaded on Ollama",
                source="llama_guard",
                rule_id="prompt_injection.llama_guard.model_missing",
            )

    raw_response = body.get("response", "")
    if not isinstance(raw_response, str):
        return None
    response_text = raw_response.strip().lower()
    if not response_text.startswith("unsafe"):
        return None

    # Extract categories from line after newline (if present).
    parts = response_text.split("\n", 1)
    categories = parts[1].strip() if len(parts) == 2 else ""
    cats_truncated = categories[:_MAX_LG_CAT_LEN]

    return ScanResult(
        category="prompt-injection-template",
        matched_pattern=f"llama-guard:{cats_truncated}",
        source="llama_guard",
        rule_id="prompt_injection.llama_guard",
    )


__all__ = ["ScanResult", "Source", "scan"]
