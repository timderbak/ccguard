# Phase 5: Prompt-Injection Detection - Context

**Gathered:** 2026-05-26
**Status:** Ready for planning

<domain>
## Phase Boundary

PreToolUse hook (расширение существующего ccguard-enforce shim из v0.1) проверяет `tool_input.command` / `tool_input.prompt` против regex-набора Anthropic Prompt Injection Risk Categories. Optional deep-scan через локальный Ollama LlamaGuard 8B. Policy-driven severity (warn|block) + allowlist. UI для редактирования секции `prompt_injection` в /policy. Покрывает PI-01..04. **Не включает**: cloud-based LlamaGuard, custom-trained models (out-of-scope).

</domain>

<decisions>
## Implementation Decisions

### Regex Detection (PI-01)
- Набор паттернов хранится в `src/ccguard/agent/prompt_injection_patterns.py` — список compiled regex, helper get_default_patterns()
- Категории: `ignore_previous_instructions`, `jailbreak_template`, `base64_encoded_prompt`, `role_swap`, `instruction_override`
- Source-of-truth: Anthropic Prompt Injection Risk Categories whitepaper + community-curated set (e.g., garak, llm-attack)
- Применение: ко всем PreToolUse событиям где `tool_input.command` (Bash) или `tool_input.prompt` (Task) или `tool_input.instructions` (другие)
- Latency budget: <30ms inline regex matching (10-30 patterns × max 4KB input)
- Match → создать локальный Finding (через существующий flusher pipeline из Phase 1) + emit decision per severity

### LlamaGuard (PI-02)
- Optional, default OFF — `policy.prompt_injection.llama_guard.enabled: false`
- Когда enabled + regex не сматчил → deep scan via Ollama HTTP API на `http://localhost:11434`
- Model: `llama-guard3:8b` (стандарт)
- Timeout: 500ms (если LlamaGuard не успел — fail-open, allow tool call, log warning)
- Latency: при выключенном — <30ms; при включенном — добавляется LlamaGuard time но fail-open значит latency budget enforce'ится через timeout
- LlamaGuard response parsing: "safe" / "unsafe S{N}" — unsafe → finding с category=`prompt-injection-template`

### Severity Mapping (PI-03)
- `policy.prompt_injection.severity` — `warn` (default) | `block` | `info`
- `block` → PreToolUse exit code 2 (deny tool call) + finding
- `warn` → exit code 0 (allow) + finding с severity=warn (виден в UI)
- `info` → exit code 0 + finding с severity=info (только в /findings)
- `fail_mode` уже есть в policy (open|closed) — переиспользуем для случая если regex engine bcrash'нется

### Allowlist (PI-04)
- `policy.prompt_injection.allowlist_patterns: []` — exact-string или regex `re:`-prefix patterns
- Если match allowlist → НЕ создаём finding (security research / chemistry exceptions)
- Применяется ДО regex detection (early-exit)

### Policy Schema (PUSH 4 extension)
- Новая секция `prompt_injection` в Policy Pydantic:
  - `enabled: bool = True`
  - `severity: Literal["info","warn","block"] = "warn"`
  - `regex_patterns: list[str] = []` (additional admin patterns, объединяются с default set)
  - `allowlist_patterns: list[str] = []`
  - `llama_guard: LlamaGuardConfig` (enabled, model, timeout_ms, endpoint)
- Backward-compat: extra=ignore; v0.1-0.2 агенты игнорируют секцию

### UI (/policy)
- Новая секция в существующем /policy editor: «Prompt-Injection» card
- Поля: enabled toggle, severity dropdown (info/warn/block), regex_patterns textarea (line-per-pattern), allowlist_patterns textarea, llama_guard block (enabled toggle, endpoint URL, timeout_ms)
- Регистрация в обоих tabs: основной /policy (rules) — не в /policy/mandatory
- Russian copy verbatim per UI-SPEC

### Claude's Discretion
- Точный набор default-regex (исследуется в research phase)
- Структура `prompt_injection_engine.py` модуль
- Ollama HTTP client (httpx synchronous, уже есть в зависимостях)
- Точная error UI для invalid regex при publish

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- ccguard-enforce shim (PreToolUse) из v0.1 — добавляем prompt_injection step в pipeline; не ломаем
- Finding emit pipeline из Phase 1 (audit buffer + flusher) — переиспользуем для эмита PI findings
- Policy YAML schema из v0.1 + Phase 4 mandatory — добавляем секцию prompt_injection
- UI policy editor — добавляем card «Prompt-Injection» рядом с существующими 7 секциями
- httpx (есть в deps) — для Ollama API call

### Established Patterns
- PreToolUse exit codes: 0 = allow, 2 = deny (стандарт Claude Code hooks)
- Latency: <100ms hard budget enforced by Claude Code (текущий enforce shim ≈30ms)
- Finding emit с rule_id=`prompt_injection.<category>` (snake_case dot-namespaced — pattern from Phase 2)
- Pydantic v2 extra=ignore для backward-compat
- create_all (no Alembic); никаких новых таблиц — Finding уже есть

### Integration Points
- src/ccguard/agent/enforce_main.py — добавить prompt_injection_engine call перед существующими policy checks
- src/ccguard/agent/prompt_injection_engine.py — новый модуль с regex matching + Ollama deep-scan
- src/ccguard/schemas/policy.py — расширение Policy с `prompt_injection: PromptInjectionConfig`
- src/ccguard/server/web/templates/policy_editor.html — добавить новый <details> блок
- src/ccguard/server/web/policy_form.py — парсинг новой секции

</code_context>

<specifics>
## Specific Ideas

- Default regex set (research phase утвердит): ~15 паттернов покрывающих ignore-prev, role-swap, jailbreak templates, base64 ifield-encoded
- Allowlist priority: проверяется ДО pattern matching, early-exit с allow
- LlamaGuard endpoint: http://localhost:11434/api/generate с JSON `{"model": "llama-guard3:8b", "prompt": "..."}`
- LlamaGuard fail-open: если timeout/connection-refused — log warning + allow + НЕ создавать finding (admin сам разберётся в логах)
- Backward-compat: если в policy нет секции prompt_injection — engine отключен (treated as enabled=false)
- finding `details` field: category, matched_pattern (truncated to 200 chars), source (regex|llama_guard)

</specifics>

<deferred>
## Deferred Ideas

- Custom-trained classifier (replacement for LlamaGuard) — v0.4+
- Cloud-based prompt-injection API (Lakera Guard integration) — v0.3
- Adaptive thresholds based on per-user behavior — v0.4
- Multi-language regex patterns (currently English-centric) — v0.3
- Pattern auto-update from threat intel feed — v0.4
- Per-tool severity overrides — v0.3

</deferred>
