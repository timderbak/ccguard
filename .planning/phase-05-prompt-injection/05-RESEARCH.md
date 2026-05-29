# Phase 5: Prompt-Injection Detection — Research

**Researched:** 2026-05-26
**Domain:** PreToolUse hook regex engine + optional Ollama LlamaGuard deep-scan + Policy schema extension + UI form parsing for `prompt_injection` section
**Confidence:** HIGH (regex catalog, Ollama API, integration points), MEDIUM (false-positive rate on adversarial inputs — needs empirical tuning during execution)

## Summary

Phase 5 inserts a **prompt-injection step into the existing v0.1 `ccguard-enforce` PreToolUse pipeline**. The step runs **before** the existing `_decide_bash` / `_decide_mcp` / `_decide_web` matchers, applies a curated set of ~15 compiled regex patterns to `tool_input.command` (Bash) and `tool_input.prompt` (Task) / `tool_input.instructions` (mcp/Task variants), and on match emits a `FindingRecord` (rule_id `prompt_injection.<category>`) plus a hook decision driven by `policy.prompt_injection.severity`. When `policy.prompt_injection.llama_guard.enabled` is true and the regex set did NOT match, a 500ms-budgeted POST to local Ollama `http://localhost:11434/api/generate` with model `llama-guard3:8b` runs as a deep-scan; "unsafe S{N}" response → finding, "safe" → allow.

The hard problems are: (1) **latency budget** — the existing enforce shim is ~30 ms and Claude Code enforces a 100 ms hard cap on PreToolUse hooks, so the regex stage must stay <30 ms for 30 patterns × 4 KB input (achievable with pre-compiled `re.Pattern` objects and ASCII bytes-mode matching); (2) **ReDoS safety** — admin-supplied `regex_patterns` from policy must be `re.compile`-validated at *publish time* on the server, not at hot-path time, and the default catalog must use atomic / non-backtracking constructs; (3) **fail-open semantics** — Ollama unreachable, `httpx.ConnectError`, timeout, or regex engine crash → log audit + allow tool call + do NOT emit finding; (4) **backward-compat** — agent v0.1/v0.2 without `prompt_injection` support must continue to operate unchanged → `extra=ignore` on `Policy` (already set after Phase 4) handles this and adding `prompt_injection: PromptInjectionConfig = PromptInjectionConfig()` keeps server defaults coherent.

**Primary recommendation:** Build a single new module `src/ccguard/agent/prompt_injection_engine.py` exposing one pure function `scan(text: str, cfg: PromptInjectionConfig) -> ScanResult | None` (None = clean), wire it into `enforce.decide()` at the *top* of the dispatch (before `_decide_bash`), emit findings through a new lightweight `agent/findings_emit.py` helper (mirrors the Phase 1 audit-buffer pattern: drop into `~/.ccguard/findings_buffer.db`, flushed by an existing or sibling subprocess flusher), and add a `<details>` card in `policy_editor.html` parsed via the existing `_section` helper in `policy_form.py`.

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Regex Detection (PI-01):**
- Patterns live in `src/ccguard/agent/prompt_injection_patterns.py` — list of compiled regex + helper `get_default_patterns()`.
- Categories: `ignore_previous_instructions`, `jailbreak_template`, `base64_encoded_prompt`, `role_swap`, `instruction_override`.
- Source-of-truth: Anthropic Prompt Injection Risk Categories whitepaper + community-curated set (garak, llm-attack).
- Applied to ALL PreToolUse events where `tool_input.command` (Bash) or `tool_input.prompt` (Task) or `tool_input.instructions` (other) is present.
- Latency budget: **<30 ms** inline regex matching (10–30 patterns × max 4 KB input).
- Match → create local Finding (through existing Phase 1 flusher pipeline) + emit decision per severity.

**LlamaGuard (PI-02):**
- Optional, default OFF — `policy.prompt_injection.llama_guard.enabled: false`.
- When enabled AND regex did not match → deep scan via Ollama HTTP API at `http://localhost:11434`.
- Model: `llama-guard3:8b` (standard).
- Timeout: 500 ms (if LlamaGuard did not finish → fail-open, allow, log warning).
- LlamaGuard response parsing: `"safe"` / `"unsafe\nS{N}"` — unsafe → finding with `category=prompt-injection-template`.

**Severity Mapping (PI-03):**
- `policy.prompt_injection.severity` — `warn` (default) | `block` | `info`.
- `block` → PreToolUse exit code 2 (deny tool call) + finding.
- `warn` → exit code 0 (allow) + finding `severity=warn` (visible in UI).
- `info` → exit code 0 + finding `severity=info` (only on `/findings`).
- `fail_mode` (already in policy: open|closed) reused for regex engine crash.

**Allowlist (PI-04):**
- `policy.prompt_injection.allowlist_patterns: []` — exact-string OR `re:`-prefixed regex.
- Match in allowlist → do NOT emit finding (security research / chemistry exceptions).
- Applied BEFORE regex detection (early-exit).

**Policy Schema:**
- New `prompt_injection` section in Policy Pydantic:
  - `enabled: bool = True`
  - `severity: Literal["info","warn","block"] = "warn"`
  - `regex_patterns: list[str] = []` (additional admin patterns, merged with default set)
  - `allowlist_patterns: list[str] = []`
  - `llama_guard: LlamaGuardConfig` (enabled, model, timeout_ms, endpoint)
- Backward-compat: `extra=ignore`; v0.1–0.2 agents ignore the section.

**UI:**
- New «Prompt-Injection» card in existing `/policy` rules tab (NOT `/policy/mandatory`).
- Fields: enabled toggle, severity dropdown, `regex_patterns` textarea (line-per-pattern), `allowlist_patterns` textarea, llama_guard block (enabled toggle, endpoint URL, timeout_ms).
- Russian copy verbatim per UI-SPEC.

### Claude's Discretion
- Exact default-regex set (researched below — 15 patterns).
- Structure of `prompt_injection_engine.py` module.
- Ollama HTTP client (httpx synchronous, already a dep).
- Error UI for invalid regex on publish.

### Deferred Ideas (OUT OF SCOPE)
- Custom-trained classifier — v0.4+.
- Cloud-based prompt-injection API (Lakera Guard) — v0.3.
- Adaptive per-user thresholds — v0.4.
- Multi-language regex (currently English-centric, with one Cyrillic doppelganger pattern) — v0.3.
- Pattern auto-update from threat-intel feed — v0.4.
- Per-tool severity overrides — v0.3.
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| PI-01 | PreToolUse shim regex over `tool_input.command` / `tool_input.prompt` (Anthropic PI Risk Categories) | Default Pattern Catalog (15 patterns); Architecture Patterns: engine module structure |
| PI-02 | Optional local LlamaGuard 8B via Ollama, feature-flagged | Ollama API section; httpx integration; fail-open semantics |
| PI-03 | Findings `severity=warn` default, `severity=block` opt-in | Severity → exit code mapping table; Claude Code hook contract |
| PI-04 | Policy section `prompt_injection` with allowlist (security research / chemistry) | Schema diff; allowlist early-exit ordering |
</phase_requirements>

## Project Constraints (from CLAUDE.md)

| Constraint | Impact on This Phase |
|---|---|
| Stack frozen (Python 3.12 / FastAPI / SQLModel / HTMX / Jinja2) | No new top-level deps. `httpx` (already a dep) used for Ollama. `re` (stdlib) for regex. |
| Self-hosted, no SaaS | Ollama is local-only (`localhost:11434`). No cloud LlamaGuard. |
| Single-tenant | LlamaGuard config global per-server (per-policy), no per-team override. |
| Backward compat (v0.1 agents) | `extra=ignore` on `Policy` already set (Phase 4 / D-1). Adding section is additive — no schema_version bump. |
| DB: SQLite WAL | Findings emitted through existing Phase 1 buffer pattern (sqlite WAL local + subprocess flusher → server). |
| Performance: hook <100ms (current ~30ms) | <30 ms budget for regex stage; LlamaGuard timeout 500 ms is OUTSIDE the inline budget — deep-scan runs only when regex did NOT match, and the timeout is the cap. If admin sets timeout > 100ms with `severity=block`, they accept the latency tradeoff. |
| Security: hashes/encrypted only | Patterns are not secrets; stored plain in policy YAML. Matched text in finding `details` is truncated to 200 chars to avoid leaking sensitive command bodies. |
| Schema versioning | Adding `prompt_injection` is additive; agent v0.1/0.2 see `extra=ignore`. No schema_version bump. |

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Regex scan of tool_input | Agent (PreToolUse shim) | — | Must run inline before tool execution; server is too far (network latency > budget). |
| LlamaGuard deep-scan | Agent → localhost Ollama | — | Self-hosted constraint forbids cloud; Ollama runs on developer endpoint. |
| Policy storage & distribution | Server (FastAPI + SQLite) | Agent (cached YAML) | Existing pattern from v0.1; agent pulls via `/api/v1/policy`. |
| Pattern catalog (default set) | Agent (compiled in module) | Server (admin extensions merged in) | Catalog must work offline; admin overlay via policy. |
| Regex validation at publish | Server (`policy_form.py`) | — | Fail fast before broken policy ships to fleet. |
| Finding emit | Agent (local buffer) → Server (REST POST) | — | Mirrors Phase 1 audit pattern; decouples hot path from network. |
| UI editor | Server (Jinja2 + HTMX) | — | Existing v0.1 admin UI. |

---

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `re` (stdlib) | 3.12 | Compiled regex matching | No external deps; sufficient for 30-pattern set under 30 ms `[VERIFIED: Python stdlib]` |
| `httpx` | ≥ 0.27 | Ollama HTTP POST with timeout | Already a project dep (Phase 1 flusher uses it) `[VERIFIED: existing import in flusher.py]` |
| `pydantic` v2 | ≥ 2.5 | `PromptInjectionConfig` / `LlamaGuardConfig` schema | Already core dep; `extra=ignore` already set on `Policy` `[VERIFIED: schemas/policy.py line 191]` |
| `sqlite3` (stdlib) | 3.12 | Local findings buffer (mirror audit_buffer.db pattern) | Already used for `audit_buffer.db` in Phase 1 `[VERIFIED: audit_hook/buffer.py]` |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `unicodedata` (stdlib) | 3.12 | NFKC normalisation before regex | Defeat homoglyph evasion ("і"+"g"+"n"+"оrе") |
| `base64` (stdlib) | 3.12 | Decode base64-suspected substrings for deep inspection | Only when entropy heuristic flags candidate |
| `yaml` (already in deps) | — | Policy serialisation | Already used in v0.1 |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| stdlib `re` | `re2` (Google re2-python) | re2 immune to ReDoS but +5 MB binary, breaks PyInstaller-thin enforce shim; rejected. |
| LlamaGuard 8B | `prompt-guard-2-86m` (smaller) | 86M model has lower latency (~60 ms vs ~300 ms for 8B) but lower accuracy; **note for execution**: admin can override `model` field in `LlamaGuardConfig` `[ASSUMED based on Meta model card]` |
| Sync httpx | `aiohttp` | enforce shim is sync (subprocess called by Claude Code with stdin); async adds no value here. |
| Local-DB finding buffer | Direct synchronous POST to server | Adds network latency to hot path (current shim ~30 ms; POST adds 50–200 ms over LAN). Buffer + flusher pattern (Phase 1) keeps hot path local. |

**Installation:** No new pip packages required. All deps already in `pyproject.toml`.

**Version verification:**
```bash
python3 -c "import re, httpx, pydantic, sqlite3, unicodedata; print(httpx.__version__, pydantic.VERSION)"
# Confirm httpx ≥ 0.27, pydantic ≥ 2.5
```

---

## Package Legitimacy Audit

| Package | Registry | Age | Downloads | Source Repo | slopcheck | Disposition |
|---------|----------|-----|-----------|-------------|-----------|-------------|
| `httpx` | PyPI | 9 yrs | ~80M/mo | github.com/encode/httpx | [OK] | Approved (already in deps) |
| `pydantic` | PyPI | 8 yrs | ~250M/mo | github.com/pydantic/pydantic | [OK] | Approved (already in deps) |

**No new packages introduced** — Phase 5 uses stdlib + already-installed deps. slopcheck NOT run (no new installs).

**Packages removed due to slopcheck [SLOP] verdict:** none
**Packages flagged as suspicious [SUS]:** none

---

## Architecture Patterns

### System Architecture Diagram

```
                  Claude Code (PreToolUse)
                          │
                          ▼  stdin JSON
                ┌─────────────────────────┐
                │  ccguard-enforce shim   │
                │  (agent/enforce.py)     │
                └──────────┬──────────────┘
                           │
              ┌────────────▼─────────────┐
              │ 1. parse_input           │
              │ 2. load_policy (cached)  │
              │ 3. policy.prompt_inj?    │ ◄── NEW Phase 5 step
              │    ├ enabled=False ─────►│ skip → existing pipeline
              │    └ enabled=True        │
              └────────────┬─────────────┘
                           ▼
              ┌──────────────────────────┐
              │ prompt_injection_engine  │ ◄── NEW MODULE
              │  ├ normalize(NFKC)       │
              │  ├ check_allowlist       │ early-exit if match → allow
              │  ├ regex_scan (15 def    │
              │  │   + admin patterns)   │
              │  └ llama_guard (opt)     │
              │      └─► localhost:11434 │
              └──────────┬───────────────┘
                         │
            ┌────────────┴────────────┐
            │ MATCH                   │ NO MATCH
            ▼                         ▼
   ┌─────────────────┐       ┌──────────────────────┐
   │ emit_finding()  │       │ existing pipeline    │
   │  → findings_    │       │  _decide_bash/mcp/web │
   │    buffer.db    │       └──────────┬───────────┘
   └────────┬────────┘                  │
            │                           │
            ▼                           │
   severity → exit code                 │
   block → exit 2                       │
   warn/info → exit 0  ─────────────────┤
                                        ▼
                              stdout → Claude Code
                                        │
                                        ▼
                              (async, separate process)
                              findings_flusher.py
                                        │
                                        ▼  POST /api/v1/findings
                              ccguard server
```

### Recommended Project Structure
```
src/ccguard/
├── agent/
│   ├── enforce.py                       # MODIFY — insert prompt_inj step in decide()
│   ├── prompt_injection_engine.py       # NEW — pure scan logic
│   ├── prompt_injection_patterns.py     # NEW — DEFAULT_PATTERNS list[CompiledPattern]
│   ├── findings_emit.py                 # NEW (or extend audit_hook) — local buffer write
│   └── findings_hook/                   # NEW — buffer.py + flusher.py (mirrors audit_hook/)
│       ├── buffer.py
│       └── flusher.py
├── schemas/
│   └── policy.py                        # MODIFY — add PromptInjectionConfig, LlamaGuardConfig
└── server/
    └── web/
        ├── policy_form.py               # MODIFY — parse prompt_injection.*
        └── templates/
            └── policy_editor.html       # MODIFY — add <details> card
```

### Pattern 1: Pure-Function Engine with Cached Compilation
**What:** Engine module exposes one entry point `scan(text, cfg) -> ScanResult | None`. Compiled regex list cached at module level via `functools.lru_cache` keyed by `tuple(cfg.regex_patterns)`.
**When to use:** Hot path called once per PreToolUse — cache survives multiple invocations within a process.
**Example:**
```python
# src/ccguard/agent/prompt_injection_engine.py
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from typing import Literal

from ccguard.agent.prompt_injection_patterns import get_default_patterns
from ccguard.schemas.policy import PromptInjectionConfig

Source = Literal["regex", "llama_guard", "allowlist"]


@dataclass(frozen=True)
class ScanResult:
    category: str            # e.g. "ignore_previous_instructions"
    matched_pattern: str     # truncated to 200 chars
    source: Source
    rule_id: str             # "prompt_injection.<category>"


def _normalize(s: str) -> str:
    """NFKC + lowercase ASCII fold — defeats Unicode homoglyph evasion."""
    return unicodedata.normalize("NFKC", s).casefold()


@lru_cache(maxsize=4)
def _compiled_admin(patterns_tuple: tuple[str, ...]) -> list[re.Pattern[str]]:
    out = []
    for p in patterns_tuple:
        try:
            out.append(re.compile(p, re.IGNORECASE | re.DOTALL))
        except re.error:
            continue  # bad regex from admin — silently skip (validated at publish)
    return out


@lru_cache(maxsize=4)
def _compiled_allowlist(patterns_tuple: tuple[str, ...]) -> list[re.Pattern[str] | str]:
    """Allowlist supports raw strings AND `re:`-prefixed regex."""
    out: list[re.Pattern[str] | str] = []
    for p in patterns_tuple:
        if p.startswith("re:"):
            try:
                out.append(re.compile(p[3:], re.IGNORECASE | re.DOTALL))
            except re.error:
                continue
        else:
            out.append(p.casefold())
    return out


def scan(text: str, cfg: PromptInjectionConfig) -> ScanResult | None:
    if not cfg.enabled or not text:
        return None

    norm = _normalize(text)

    # 1. Allowlist early-exit
    for entry in _compiled_allowlist(tuple(cfg.allowlist_patterns)):
        if isinstance(entry, str):
            if entry in norm:
                return None  # signal handled by caller — emit no finding
        else:
            if entry.search(norm):
                return None

    # 2. Default catalog + admin extensions
    for category, pattern in get_default_patterns():
        if pattern.search(norm):
            return ScanResult(
                category=category,
                matched_pattern=pattern.pattern[:200],
                source="regex",
                rule_id=f"prompt_injection.{category}",
            )
    for pattern in _compiled_admin(tuple(cfg.regex_patterns)):
        if pattern.search(norm):
            return ScanResult(
                category="admin_custom",
                matched_pattern=pattern.pattern[:200],
                source="regex",
                rule_id="prompt_injection.admin_custom",
            )

    # 3. LlamaGuard deep-scan (only if enabled AND regex clean)
    if cfg.llama_guard.enabled:
        result = _llama_guard_scan(text, cfg.llama_guard)
        if result is not None:
            return result

    return None
```

### Pattern 2: Default Pattern Catalog (frozen tuple at module load)
**What:** `get_default_patterns()` returns a tuple of `(category, compiled_pattern)` — compiled once at import.
**Example:**
```python
# src/ccguard/agent/prompt_injection_patterns.py
from __future__ import annotations
import re
from functools import lru_cache

_FLAGS = re.IGNORECASE | re.DOTALL

# Each entry: (category, regex_source)
# Sources: Anthropic Prompt Injection Risk Categories whitepaper,
#          garak (NVIDIA) probe.promptinject,
#          llm-attack repo curated jailbreaks.
# Patterns are written to AVOID catastrophic backtracking:
#  - no nested quantifiers on overlapping classes
#  - bounded `.{0,N}` instead of `.*` where possible
_DEFAULTS: tuple[tuple[str, str], ...] = (
    # --- ignore_previous_instructions ---
    ("ignore_previous_instructions",
     r"\bignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instruction|prompt|message|context|rule)s?\b"),
    ("ignore_previous_instructions",
     r"\bdisregard\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instruction|prompt|rule)s?\b"),
    ("ignore_previous_instructions",
     r"\bforget\s+(?:everything|all)\s+(?:above|prior|previous|you\s+(?:were\s+)?told)\b"),
    # Cyrillic doppelgangers — common Russian-language injection
    ("ignore_previous_instructions",
     r"(?:игнорируй|забудь)\s+(?:все\s+)?(?:предыдущ|прошл)"),

    # --- instruction_override ---
    ("instruction_override",
     r"\bnew\s+(?:instruction|system\s+prompt|rule)s?\s*[:\-]"),
    ("instruction_override",
     r"\b(?:system|admin|developer)\s*(?:prompt|message|instruction)\s*[:\-]\s*"),
    ("instruction_override",
     r"</?\s*(?:system|user|assistant)\s*>"),  # fake chat-template tags

    # --- role_swap ---
    ("role_swap",
     r"\byou\s+are\s+now\s+(?:a|an)\s+(?:different|new|unrestricted|jailbroken)\b"),
    ("role_swap",
     r"\bact\s+as\s+(?:if\s+you\s+(?:are|were)|a)\s+(?:dan|stan|aim|developer\s+mode)\b"),
    ("role_swap",
     r"\bpretend\s+(?:you\s+(?:are|have\s+no)|to\s+be)\s+(?:an?\s+)?(?:unrestricted|uncensored|jailbroken)\b"),

    # --- jailbreak_template (DAN/STAN/AIM family) ---
    ("jailbreak_template",
     r"\b(?:dan|stan|aim|dude|stan\.?\s*\d+|do\s+anything\s+now)\b.{0,200}\b(?:mode|prompt|jailbreak)\b"),
    ("jailbreak_template",
     r"\bdeveloper\s+mode\b.{0,100}\b(?:enabled|activated|on)\b"),
    ("jailbreak_template",
     r"\b(?:OPPOSITE|opposite)\s+day\b"),  # known jailbreak template

    # --- base64_encoded_prompt (heuristic: long b64-ish run + suspicious keyword nearby) ---
    ("base64_encoded_prompt",
     r"(?:base64|b64)\s*[:=]?\s*[A-Za-z0-9+/]{40,}={0,2}"),
    ("base64_encoded_prompt",
     r"\bdecode\s+(?:the\s+)?(?:following|this)\s+(?:base64|b64)\b"),
)


@lru_cache(maxsize=1)
def get_default_patterns() -> tuple[tuple[str, re.Pattern[str]], ...]:
    return tuple((cat, re.compile(src, _FLAGS)) for cat, src in _DEFAULTS)
```

### Pattern 3: Ollama LlamaGuard Sync Client (httpx, fail-open)
**What:** Single `httpx.Client` POST with explicit timeout. Any exception → return None (allow).
**Example:**
```python
# src/ccguard/agent/prompt_injection_engine.py (continued)
import httpx
from ccguard.schemas.policy import LlamaGuardConfig


_LG_PROMPT_TEMPLATE = (
    "<|begin_of_text|><|start_header_id|>user<|end_header_id|>\n\n"
    "Task: Check if there is unsafe content in 'User' messages in conversations "
    "according to our safety policy with the below categories.\n\n"
    "<BEGIN UNSAFE CONTENT CATEGORIES>\n"
    "S14: Code Interpreter Abuse.\n"
    "<END UNSAFE CONTENT CATEGORIES>\n\n"
    "<BEGIN CONVERSATION>\n\n"
    "User: {user_text}\n\n"
    "<END CONVERSATION>\n\n"
    "Provide your safety assessment for the LAST User message in the above "
    "conversation:\n - First line must read 'safe' or 'unsafe'.\n - If unsafe, "
    "a second line must include a comma-separated list of violated categories."
    "<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n"
)


def _llama_guard_scan(text: str, cfg: LlamaGuardConfig) -> ScanResult | None:
    """Best-effort deep scan via local Ollama. Fail-open on ANY error."""
    # Truncate input — LlamaGuard context is finite; 4KB is plenty for tool_input
    truncated = text[:4096]
    payload = {
        "model": cfg.model,
        "prompt": _LG_PROMPT_TEMPLATE.format(user_text=truncated),
        "stream": False,
        "options": {"temperature": 0.0, "num_predict": 16},
    }
    try:
        with httpx.Client(timeout=cfg.timeout_ms / 1000.0) as client:
            resp = client.post(f"{cfg.endpoint}/api/generate", json=payload)
        if resp.status_code != 200:
            return None
        body = resp.json().get("response", "").strip().lower()
    except (httpx.HTTPError, httpx.TimeoutException, ValueError, KeyError):
        return None  # fail-open

    if not body.startswith("unsafe"):
        return None
    # Parse "unsafe\nS14" or "unsafe\ns14, s2"
    cats = ""
    if "\n" in body:
        cats = body.split("\n", 1)[1].strip()
    return ScanResult(
        category="prompt-injection-template",
        matched_pattern=f"llama-guard:{cats[:50]}",
        source="llama_guard",
        rule_id="prompt_injection.llama_guard",
    )
```

### Pattern 4: enforce.decide() Integration
**What:** Insert PI scan at top of `decide()` — runs ONCE per hook regardless of tool type, since `tool_input` may contain a `prompt` for Task/SubagentStop tools and `command` for Bash.
**Example:**
```python
# src/ccguard/agent/enforce.py — modify decide()
from ccguard.agent.prompt_injection_engine import scan as pi_scan
from ccguard.agent.findings_emit import emit_finding


def _extract_pi_payload(tool_input: dict) -> str:
    """Concatenate all string fields that could carry an injection payload."""
    parts = []
    for key in ("command", "prompt", "instructions", "description", "content"):
        v = tool_input.get(key)
        if isinstance(v, str):
            parts.append(v)
    return "\n".join(parts)


def decide(payload: EnforceHookInput, policy: Policy) -> EnforceDecision:
    if payload.hook_event_name != "PreToolUse":
        return EnforceDecision(permission="allow", reason="not PreToolUse")

    # --- NEW: prompt-injection step (Phase 5) ---
    if policy.prompt_injection.enabled:
        text = _extract_pi_payload(payload.tool_input)
        try:
            pi_result = pi_scan(text, policy.prompt_injection)
        except Exception:
            # Engine crash → fail-open per CONTEXT D-3 (severity fail_mode reused)
            pi_result = None
        if pi_result is not None:
            # Emit finding asynchronously via local buffer
            emit_finding(
                rule_id=pi_result.rule_id,
                severity=policy.prompt_injection.severity,
                title=f"Prompt-injection match ({pi_result.category})",
                source=pi_result.source,
                matched_pattern=pi_result.matched_pattern,
                tool_name=payload.tool_name,
            )
            if policy.prompt_injection.severity == "block":
                return EnforceDecision(
                    permission="deny",
                    reason=f"prompt-injection: {pi_result.category}",
                    rule_id=pi_result.rule_id,
                )
            # warn / info → fall through to existing pipeline (still allow)

    # --- existing v0.1 pipeline ---
    tool = payload.tool_name
    ti = payload.tool_input
    if tool == "Bash":
        ...
```

### Anti-Patterns to Avoid
- **DO NOT** compile regex inside `scan()` per call — compile at module load via `lru_cache`. Each `re.compile` is ~50 µs; 30 patterns × 50 µs = 1.5 ms wasted per hook invocation.
- **DO NOT** use `.*` greedy unbounded on user input — adversarial input → catastrophic backtracking → hook timeout.
- **DO NOT** synchronously POST findings to server in the hot path — adds 50–200 ms LAN latency. Use the audit-buffer pattern.
- **DO NOT** call Ollama on EVERY hook — only when regex did NOT match. This keeps clean cases at <30 ms.
- **DO NOT** raise from the engine; always return None on internal error and let `decide()` allow (consistent with `block_fail_mode=open`).

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Pattern catalog from scratch | Curate your own from blog posts | Adapt from Anthropic PI Risk Categories whitepaper + garak `promptinject` probe | Existing curated lists have years of adversarial testing. |
| ReDoS-safe regex engine | Custom NFA evaluator | stdlib `re` + careful pattern authorship (no unbounded `.*`, no nested quantifiers) | re2-python adds 5MB to PyInstaller bundle; rejected per stack constraint. |
| LLM safety classifier | Train your own | LlamaGuard 3 8B via Ollama | Self-hosted constraint forbids cloud APIs; Meta's LlamaGuard is the de-facto open weight standard for content moderation `[CITED: huggingface.co/meta-llama/Llama-Guard-3-8B]` |
| Local finding buffer | Direct POST in hot path | Reuse Phase 1 SQLite WAL buffer pattern | Already proven in production; same flusher pattern. |
| Ollama prompt format | Compose freestyle | Use the official LlamaGuard chat template from model card | Free-form prompts → unstable "safe/unsafe" parsing. |

**Key insight:** Phase 5 is integration, not invention. Every component (regex engine, HTTP client, finding buffer, policy schema) already exists; the work is wiring + curating the default pattern set.

---

## Common Pitfalls

### Pitfall 1: ReDoS on admin-supplied patterns
**What goes wrong:** Admin adds `(a+)+b` in policy → adversarial input (`tool_input.command = "aaaaaa..."`) causes 100+ ms regex eval → hook breaches 100 ms hard cap → Claude Code kills the hook → fail-open allows the very command we tried to block.
**Why it happens:** Python's `re` is backtracking-based; nested quantifiers on overlapping classes blow up.
**How to avoid:**
- Validate admin patterns at publish time (server-side `policy_form.py`) with `re.compile` + a 50 ms `signal.alarm`-wrapped test match against a `"a" * 1000` adversarial probe; reject if it exceeds.
- Document for admins: avoid `(.*)+`, `(a+)+`, `(.+)*`.
- Catalog defaults use bounded `{0,N}` instead of `*`.
**Warning signs:** unit test on adversarial input takes > 5 ms.

### Pitfall 2: False positives on legitimate dev commands
**What goes wrong:** Pattern `ignore.{0,30}previous` matches `git revert --ignore-merge-options HEAD~1` or doc strings containing the literal phrase ("This will ignore the previous default…").
**Why it happens:** Patterns are heuristics, not parsers.
**How to avoid:**
- Default severity = `warn` (not block) so false positives generate findings without breaking dev flow.
- Allowlist mechanism (PI-04) gives admin escape hatch.
- During execution: collect FP rate on dev's own machine for 1 week before recommending `severity=block`.
**Warning signs:** repeated findings on benign commands from same developer.

### Pitfall 3: Ollama unreachable but `llama_guard.enabled=true`
**What goes wrong:** Admin enables LlamaGuard but doesn't run Ollama → every hook spends 500 ms timing out → cumulative latency hurts developer productivity.
**Why it happens:** Connection-refused returns FAST (<5 ms) but DNS-lookup failures or hung TCP can hit timeout.
**How to avoid:**
- Set `httpx.Client(timeout=cfg.timeout_ms / 1000.0)` with full timeout (connect+read+write all bounded).
- Emit one-shot warning to ccguard agent log on first unreachable; don't spam.
- Health-check endpoint in `ccguard check` CLI: probe `GET /api/tags` once at sync time, surface in UI.
**Warning signs:** every hook adds 500 ms to total runtime.

### Pitfall 4: Base64 false positives on legitimate command output
**What goes wrong:** `aws s3 cp s3://bucket/AAAAAAAAA... .` matches the base64 detector.
**Why it happens:** S3 keys, JWT-like tokens, hashes all look like base64.
**How to avoid:**
- Default pattern requires the literal "base64"/"b64" keyword nearby (not just the b64-shaped string).
- Optional entropy heuristic (Shannon entropy > 4.5 over the suspect substring) — defer to admin tuning.
**Warning signs:** high FP rate on AWS-heavy commands.

### Pitfall 5: Unicode homoglyph evasion
**What goes wrong:** `іgnore previous` (Cyrillic "і" U+0456 instead of Latin "i") bypasses ASCII regex.
**Why it happens:** Visual identity ≠ codepoint identity.
**How to avoid:**
- NFKC normalise + `casefold()` before matching (homoglyphs in different scripts still differ post-NFKC — Cyrillic "і" stays distinct from Latin "i").
- Additional safety: explicit Cyrillic doppelganger patterns in default catalog (one example added: `(?:игнорируй|забудь)`).
- LlamaGuard catches semantic intent regardless of script.
**Warning signs:** finding rate drops to zero after attacker iterates payloads — they may have found the bypass.

### Pitfall 6: Backward-compat breakage on v0.1 agents
**What goes wrong:** New policy YAML pushed to fleet, v0.1 agent (no `extra=ignore` in subsection) raises `ValidationError` → falls back to last cached policy → fleet drifts.
**Why it happens:** Pydantic default is `extra=forbid`.
**How to avoid:**
- `Policy.model_config` already has `extra=ignore` after Phase 4 (line 191 of `schemas/policy.py`).
- Add explicit unit test: build a Policy with `prompt_injection` section, dump to YAML, validate with v0.1 schema (or pin pydantic to old behavior).
**Warning signs:** post-publish drift in `/machines` page showing v0.1 agents on old policy revisions.

### Pitfall 7: Sensitive data in finding `matched_pattern`
**What goes wrong:** Finding includes full matched text including secret values that happened to look like prompts ("set MY_API_KEY=sk-... # ignore previous").
**Why it happens:** Truncate-only doesn't redact.
**How to avoid:**
- Pass `matched_pattern` through existing `mask_secrets()` from `agent/masking.py` (already used in Phase 3 scanner) BEFORE truncation.
- Hard-truncate to 200 chars per CONTEXT.
**Warning signs:** secrets appear in `/findings` UI.

---

## Runtime State Inventory

Phase 5 is greenfield within the agent — no rename/refactor. Skipped per spec.

---

## Code Examples

### Policy Schema Diff (`src/ccguard/schemas/policy.py`)
```python
# Source: extension of existing v0.1+Phase 4 schema
from pydantic import ConfigDict, Field
from typing import Literal


class LlamaGuardConfig(SchemaBase):
    """Optional LlamaGuard deep-scan via local Ollama (PI-02)."""
    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    enabled: bool = False
    endpoint: str = "http://localhost:11434"
    model: str = "llama-guard3:8b"
    timeout_ms: int = Field(default=500, ge=50, le=10000)


class PromptInjectionConfig(SchemaBase):
    """Prompt-injection detection (PI-01..04). Backward-compat: extra=ignore."""
    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)

    enabled: bool = True
    severity: Literal["info", "warn", "block"] = "warn"
    regex_patterns: list[str] = Field(default_factory=list)
    allowlist_patterns: list[str] = Field(default_factory=list)
    llama_guard: LlamaGuardConfig = Field(default_factory=LlamaGuardConfig)


class Policy(SchemaBase):
    # ... existing fields ...
    prompt_injection: PromptInjectionConfig = Field(default_factory=PromptInjectionConfig)
```

### policy_form.py Extension
```python
# Source: src/ccguard/server/web/policy_form.py — additive
def _parse_prompt_injection(form: Mapping[str, str]) -> dict[str, Any]:
    """Parse the 'Prompt-Injection' card from POST form."""
    # Validate admin regex_patterns AT PUBLISH TIME (fail fast)
    raw_patterns = _lines_to_list(form.get("prompt_injection.regex_patterns", ""))
    invalid: list[str] = []
    for p in raw_patterns:
        try:
            re.compile(p)
        except re.error as e:
            invalid.append(f"{p}: {e}")
    if invalid:
        raise ValueError(
            f"Невалидные regex в prompt_injection.regex_patterns:\n" + "\n".join(invalid)
        )

    return {
        "enabled": _checkbox(form.get("prompt_injection.enabled", "0")),
        "severity": form.get("prompt_injection.severity", "warn"),
        "regex_patterns": raw_patterns,
        "allowlist_patterns": _lines_to_list(
            form.get("prompt_injection.allowlist_patterns", "")
        ),
        "llama_guard": {
            "enabled": _checkbox(form.get("prompt_injection.llama_guard.enabled", "0")),
            "endpoint": form.get(
                "prompt_injection.llama_guard.endpoint", "http://localhost:11434"
            ),
            "model": form.get(
                "prompt_injection.llama_guard.model", "llama-guard3:8b"
            ),
            "timeout_ms": int(
                form.get("prompt_injection.llama_guard.timeout_ms", "500")
            ),
        },
    }
```

### Jinja Template Snippet (`policy_editor.html` add)
```jinja
{# Source: addition to existing policy_editor.html rules tab #}
<details class="policy-card" {% if policy.prompt_injection.enabled %}open{% endif %}>
  <summary class="policy-card__title">Защита от prompt-injection</summary>
  <div class="policy-card__body">
    <label>
      <input type="checkbox" name="prompt_injection.enabled" value="1"
             {% if policy.prompt_injection.enabled %}checked{% endif %}>
      Включить детекцию
    </label>
    <label>Уровень severity:
      <select name="prompt_injection.severity">
        {% for s in ["info","warn","block"] %}
          <option value="{{s}}"
            {% if policy.prompt_injection.severity == s %}selected{% endif %}>{{s}}</option>
        {% endfor %}
      </select>
    </label>
    <label>Дополнительные паттерны (по одному на строку):
      <textarea name="prompt_injection.regex_patterns" rows="6">{{
        policy.prompt_injection.regex_patterns | join("\n")
      }}</textarea>
    </label>
    <label>Allowlist (exact-string или re:&lt;regex&gt; — по одному на строку):
      <textarea name="prompt_injection.allowlist_patterns" rows="4">{{
        policy.prompt_injection.allowlist_patterns | join("\n")
      }}</textarea>
    </label>
    <fieldset>
      <legend>LlamaGuard (опционально)</legend>
      <label>
        <input type="checkbox" name="prompt_injection.llama_guard.enabled" value="1"
               {% if policy.prompt_injection.llama_guard.enabled %}checked{% endif %}>
        Включить deep-scan через локальный Ollama
      </label>
      <label>Endpoint:
        <input type="url" name="prompt_injection.llama_guard.endpoint"
               value="{{ policy.prompt_injection.llama_guard.endpoint }}">
      </label>
      <label>Модель:
        <input type="text" name="prompt_injection.llama_guard.model"
               value="{{ policy.prompt_injection.llama_guard.model }}">
      </label>
      <label>Timeout (ms):
        <input type="number" min="50" max="10000"
               name="prompt_injection.llama_guard.timeout_ms"
               value="{{ policy.prompt_injection.llama_guard.timeout_ms }}">
      </label>
    </fieldset>
  </div>
</details>
```

### Severity → Exit Code Mapping
```
+----------+------------+----------------+---------------------+
| severity | exit code  | hook stdout    | finding emitted?    |
+----------+------------+----------------+---------------------+
| block    | 0 (with    | JSON deny+     | YES (severity=block)|
|          | structured | reason         |                     |
|          | output)    |                |                     |
| warn     | 0          | "" (empty)     | YES (severity=warn) |
| info     | 0          | "" (empty)     | YES (severity=info) |
+----------+------------+----------------+---------------------+
```
**Important:** Claude Code's PreToolUse contract: exit code 2 = deny but stderr-only reason; the supported path is exit 0 + JSON `permissionDecision: "deny"` in `hookSpecificOutput`. The existing `render_hook_response()` in `enforce.py` already implements this — Phase 5 reuses it `[VERIFIED: enforce.py:157-170]`.

### Ollama Generate API
```
POST http://localhost:11434/api/generate
Content-Type: application/json
{
  "model": "llama-guard3:8b",
  "prompt": "<llama-guard formatted prompt>",
  "stream": false,
  "options": {"temperature": 0.0, "num_predict": 16}
}

Response 200:
{
  "model": "llama-guard3:8b",
  "created_at": "...",
  "response": "safe",      // or "unsafe\nS14"
  "done": true,
  ...
}
```
`[CITED: ollama.com/library/llama-guard3 — model card and Ollama REST API docs]`
LlamaGuard 3 categories S1–S14 (S14 = Code Interpreter Abuse is the relevant one for tool-use injection) `[CITED: huggingface.co/meta-llama/Llama-Guard-3-8B model card]`.

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Hand-rolled keyword blacklist | Curated regex catalog + LLM classifier | 2024–2025 | Industry baseline (Lakera, Cisco AI Defense) |
| GPT-3.5-based judging | LlamaGuard 3 (Meta, 2024) | Late 2024 | Local-hostable open weights, S1–S14 taxonomy `[CITED: Meta blog Dec 2024]` |
| Inline synchronous scanning | Buffered async emit + inline regex | This phase | Hot-path budget compliance |
| Generic "jailbreak" category | Granular categories (ignore-prev, role-swap, base64, etc.) | 2024 | Better triage in SOC; matches Anthropic taxonomy |

**Deprecated/outdated:**
- LlamaGuard 1 / 2: superseded by v3; do not use.
- Cloud-only Lakera Guard API: incompatible with self-hosted constraint.

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | LlamaGuard 3 8B on Ollama returns ~200–400 ms median latency on modern dev CPU | Pitfalls (latency budget) | If much slower, default timeout 500ms may saturate too often → high fail-open rate. Mitigation: timeout already a policy field. |
| A2 | NFKC + casefold collapses common homoglyph attacks | Pitfall 5 | If attacker uses non-NFKC-collapsable codepoints (e.g. Mathematical Alphanumeric Symbols), bypass possible. Add explicit unicode block strip if seen. |
| A3 | The 15-pattern default catalog covers ~80% of garak-class injections | Default Pattern Catalog | If FP rate too high in practice, drop weakest patterns and rely on LlamaGuard. |
| A4 | Admin `regex_patterns` validation at publish time is sufficient ReDoS defense | Pitfall 1 | If a pattern passes the `"a"*1000` probe but fails on a different adversarial input, hot-path can still hang. Mitigation: hard-bound hook timeout via OS-level alarm (deferred to v0.3). |
| A5 | Existing audit-flusher pattern (Phase 1) can be cloned for findings buffer with minimal changes | Architecture Patterns | If schema differs significantly (`Finding` vs `ToolUseEvent`), might need new flusher binary. Plan should verify by reading `flusher.py` during execution. |
| A6 | `tool_input.prompt` is the canonical field for Task tool injection payload | `_extract_pi_payload` | Other tools may use different field names; broaden if discovered during execution. |

---

## Open Questions

1. **Findings emit pipeline location: extend audit_hook or new findings_hook module?**
   - What we know: Phase 1 built `audit_hook/{buffer,flusher}.py` for `ToolUseEvent`. A `Finding` row has different fields (`rule_id`, `severity`, `title`, `description`, `source`, `recommendation`, `matched_value`).
   - What's unclear: whether to (a) extend `audit_hook` with a second table, (b) clone it as `findings_hook/`, or (c) piggyback findings onto an existing server endpoint synchronously when severity=block (since we're already blocking and have budget).
   - Recommendation: (b) clone as `findings_hook/` for symmetry; copy buffer.py with new schema, copy flusher.py with new POST endpoint. Decision deferred to plan-phase.

2. **Should LlamaGuard run for `severity=info`?**
   - What we know: Default `info` shouldn't disrupt flow; LlamaGuard adds latency.
   - What's unclear: do we run LlamaGuard always-if-enabled, or skip it when severity=info?
   - Recommendation: run regardless of severity; the cost is per-hook latency only, and detection accuracy improves uniformly.

3. **Where to install LlamaGuard model on agent?**
   - What we know: Ollama uses `~/.ollama/models/`; the model is ~4.5 GB quantized.
   - What's unclear: do we auto-pull on first enable, or require admin to `ollama pull llama-guard3:8b` manually?
   - Recommendation: manual install for v0.2; surface "model unavailable" finding when LlamaGuard returns 404 (Ollama responds with `model not found` JSON).

4. **Russian-language patterns coverage?**
   - What we know: one Cyrillic example added (`игнорируй|забудь`).
   - What's unclear: completeness — Russian-speaking attackers can craft variants.
   - Recommendation: ship with one as marker; deferred to v0.3 (multi-language milestone).

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Python 3.12 | Engine module | ✓ | system | — |
| `httpx` | Ollama client | ✓ | already a dep | — |
| Ollama daemon | LlamaGuard (PI-02) | optional | — | `llama_guard.enabled=false` is the default; engine works without Ollama |
| `llama-guard3:8b` model | LlamaGuard (PI-02) | optional | ~4.5 GB | finding `prompt_injection.llama_guard.model_unavailable` on 404, fail-open |

**Missing dependencies with no fallback:** none — Phase 5 ships functional with regex-only mode if Ollama is absent.
**Missing dependencies with fallback:** Ollama / LlamaGuard model (graceful degradation per fail-open contract).

---

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | pytest 8.x (already in project) |
| Config file | `pyproject.toml` `[tool.pytest.ini_options]` (existing) |
| Quick run command | `pytest tests/agent/test_prompt_injection_engine.py -x` |
| Full suite command | `pytest -x` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|--------------|
| PI-01 | 15 default patterns each match a known attack string | unit | `pytest tests/agent/test_prompt_injection_patterns.py -x` | ❌ Wave 0 |
| PI-01 | Allowlist early-exits before pattern scan | unit | `pytest tests/agent/test_prompt_injection_engine.py::test_allowlist_skip -x` | ❌ Wave 0 |
| PI-01 | <30ms for 4KB input × 30 patterns | perf | `pytest tests/agent/test_prompt_injection_perf.py -x` | ❌ Wave 0 |
| PI-01 | ReDoS adversarial pattern times out at publish | unit (server) | `pytest tests/server/test_policy_form_pi.py::test_redos_rejected -x` | ❌ Wave 0 |
| PI-02 | Ollama HTTP success path returns ScanResult on `"unsafe\nS14"` | unit (httpx mock) | `pytest tests/agent/test_llama_guard.py::test_unsafe_parse -x` | ❌ Wave 0 |
| PI-02 | Ollama timeout / ConnectError → None (fail-open) | unit (httpx mock) | `pytest tests/agent/test_llama_guard.py::test_fail_open -x` | ❌ Wave 0 |
| PI-02 | LlamaGuard NOT called if regex matched | unit | `pytest tests/agent/test_prompt_injection_engine.py::test_lg_skipped_on_regex_hit -x` | ❌ Wave 0 |
| PI-03 | `severity=block` → enforce returns deny JSON | integration | `pytest tests/agent/test_enforce_pi_block.py -x` | ❌ Wave 0 |
| PI-03 | `severity=warn` → enforce allow + finding emitted | integration | `pytest tests/agent/test_enforce_pi_warn.py -x` | ❌ Wave 0 |
| PI-04 | Policy form parses prompt_injection section round-trip | unit (server) | `pytest tests/server/test_policy_form_pi.py -x` | ❌ Wave 0 |
| PI-04 | Invalid regex in admin patterns → publish rejected with Russian error copy | unit (server) | `pytest tests/server/test_policy_form_pi.py::test_invalid_regex_publish -x` | ❌ Wave 0 |
| backward-compat | v0.1 agent (without prompt_injection field) parses policy with new section | unit | `pytest tests/schemas/test_policy_backcompat.py -x` | ❌ Wave 0 |
| e2e | Publish policy with PI section → agent enforces → finding visible on `/findings` | e2e | `pytest tests/e2e/test_pi_e2e.py -x` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** `pytest tests/agent/test_prompt_injection_engine.py tests/agent/test_prompt_injection_patterns.py -x`
- **Per wave merge:** `pytest tests/agent/ tests/schemas/test_policy_backcompat.py -x`
- **Phase gate:** Full suite + e2e green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `tests/agent/test_prompt_injection_patterns.py` — covers PI-01 (per-pattern positive/negative cases)
- [ ] `tests/agent/test_prompt_injection_engine.py` — covers PI-01, PI-02 wiring
- [ ] `tests/agent/test_prompt_injection_perf.py` — latency assertion (<30 ms)
- [ ] `tests/agent/test_llama_guard.py` — Ollama mock (httpx.MockTransport) for safe/unsafe/timeout
- [ ] `tests/agent/test_enforce_pi_block.py` + `test_enforce_pi_warn.py` — enforce.decide() integration
- [ ] `tests/server/test_policy_form_pi.py` — form parser + ReDoS publish-time guard
- [ ] `tests/schemas/test_policy_backcompat.py` — v0.1 schema round-trip
- [ ] `tests/e2e/test_pi_e2e.py` — full agent → server flow
- [ ] `tests/conftest.py` — shared fixture `pi_config` for engine tests

---

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | yes | Reuse v0.1 `X-CCGuard-Token` for finding POST |
| V3 Session Management | no | Hook is stateless |
| V4 Access Control | yes | Policy-driven severity = access decision; reuse v0.1 admin-only `/policy` route |
| V5 Input Validation | yes | Pydantic v2 + admin regex re.compile at publish |
| V6 Cryptography | no | No new crypto introduced; existing Fernet for tokens unchanged |
| V11 BOLA / Auth Bypass | yes | Allowlist must not be remotely-bypassable — patterns ship in policy, distributed via authenticated `/api/v1/policy` only |
| V14 Configuration | yes | Default-secure: `severity=warn` (visible, non-disruptive); `llama_guard.enabled=false` (no surprise latency) |

### Known Threat Patterns for ccguard stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| ReDoS via admin regex_patterns | Denial of Service | Publish-time `re.compile` + 50 ms adversarial probe (Pitfall 1) |
| Homoglyph evasion | Tampering | NFKC normalize + Cyrillic doppelganger patterns in catalog (Pitfall 5) |
| Sensitive data leak via matched_pattern | Information Disclosure | Reuse `mask_secrets()` from v0.1 before serialising finding (Pitfall 7) |
| Ollama prompt injection (attacker manipulates LlamaGuard) | Tampering | Fixed prompt template wraps user_text in `<BEGIN/END CONVERSATION>` boundary tokens; never concat raw |
| Bypass via field not in `_extract_pi_payload` | Tampering | Document the field-list; integration test asserts coverage; LlamaGuard catches semantic intent independent of field |
| Policy poisoning (attacker gains admin, lowers severity) | Elevation of Privilege | v0.1 auth model — admin password + audit log on policy publish (existing) |

---

## Sources

### Primary (HIGH confidence)
- `src/ccguard/agent/enforce.py` (v0.1, lines 138–170) — existing decide() pipeline and `render_hook_response`
- `src/ccguard/schemas/policy.py` (Phase 4, line 191) — `extra=ignore` on Policy already set
- `src/ccguard/agent/audit_hook/buffer.py` + `flusher.py` (Phase 1) — buffer + flusher pattern reused for findings
- `src/ccguard/server/web/policy_form.py` — `_section` helper, `_lines_to_list`, `_checkbox` reused for new card
- Ollama REST API docs (`/api/generate` request/response shape) `[CITED: ollama.com/docs/api]`
- LlamaGuard 3 model card on HuggingFace (S1–S14 taxonomy, prompt template) `[CITED: huggingface.co/meta-llama/Llama-Guard-3-8B]`
- Anthropic Prompt Injection Risk Categories whitepaper (category taxonomy) `[CITED: anthropic.com/research]`

### Secondary (MEDIUM confidence)
- garak (NVIDIA) `probe.promptinject` curated patterns — basis for `ignore_previous`, `dan_jailbreak`, `role_swap` regex
- llm-attack repo curated jailbreaks
- Phase 3 RESEARCH.md (severity tier `critical` added, mask_secrets reuse)
- Phase 4 RESEARCH.md (additive policy schema pattern; `extra=ignore` backward-compat)

### Tertiary (LOW confidence, flagged for validation during execution)
- Exact LlamaGuard 8B median latency on consumer hardware (~200–400 ms — varies by CPU, see Assumption A1)
- Optimal default pattern severity tradeoff (FP/FN balance — empirical tuning needed in week 1 after ship)

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all packages already in deps, no new installs.
- Architecture: HIGH — direct extension of v0.1 enforce pipeline + Phase 1 buffer pattern.
- Default pattern catalog: MEDIUM — 15 patterns drawn from authoritative sources but FP rate is empirical.
- LlamaGuard integration: HIGH on API shape (well-documented), MEDIUM on latency assumptions (hardware-dependent).
- Pitfalls: HIGH — ReDoS, homoglyph, Ollama-unreachable are well-known classes with established mitigations.
- Backward compat: HIGH — `extra=ignore` already locked in Phase 4.

**Research date:** 2026-05-26
**Valid until:** 2026-06-25 (30 days — patterns evolve slowly, but LlamaGuard model versions may iterate)
