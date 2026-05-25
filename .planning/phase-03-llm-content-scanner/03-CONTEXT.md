# Phase 3: LLM Content Scanner - Context

**Gathered:** 2026-05-25
**Status:** Ready for planning

<domain>
## Phase Boundary

Сканировать содержимое `~/.claude/agents/*.md` и `~/.claude/skills/*/SKILL.md` через Anthropic API на jailbreak / prompt-injection / data-exfil / privilege-escalation с кэшем по file_hash, дневным бюджетом, и UI настройками. Покрывает LLM-01..04. **Не включает**: scanning MCP-кода (out-of-scope), local LLM (Phase 5 prompt-injection runtime), per-tenant API keys (v0.3).

</domain>

<decisions>
## Implementation Decisions

### Content Transmission & Privacy
- Агент шлёт полное markdown-содержимое файлов только если **scanner включён админом** в Settings AND `ANTHROPIC_API_KEY` задан в server env
- Маскирование секретов перед отправкой: на агенте (та же regex-логика что для MCP args в Phase v0.1) — JWT, sk-*, AKIA, ghp_*, etc.
- Новый endpoint `POST /api/v1/scan-content` (batch до N файлов) — отдельно от inventory
- Payload size: soft cap 100KB/файл, hard cap 1MB; > truncate с `truncated=True` флагом + warning

### Anthropic API Usage
- Модель: `claude-haiku-4-5-20251001` — быстрая/дешёвая для классификации; не нужен thinking mode
- Prompt format: system prompt + user message с content; structured output через `tool_use` (один tool `report_risk` с JSON-schema risk_score+category+rationale)
- Кэш: sha256(file_content_bytes) — байт-точное совпадение; разные пробелы → разный hash → re-scan
- TTL: 30 дней; manual "Re-scan" кнопка per-row в findings + global "Пересканировать всё" в Settings

### Budget & Rate Limiting
- Таблица `LLMCallLog(id, ts UTC, file_hash, model, input_tokens, output_tokens, cost_estimate_cents)` — для аудита и счётчика
- Budget exhaustion → сервер возвращает 429 агенту; cache hits всё ещё работают
- Default daily_call_budget: 100 calls/day (admin-tunable в Settings)
- Concurrency: sequential — один scan request на сервере одновременно (server-side mutex via asyncio.Lock)

### UI
- Результаты scan'ов отображаются на существующей `/findings` странице (расширить severity mapping: risk_score < 30 → info, 30-70 → warn, > 70 → critical)
- Settings UI: новая секция «LLM-сканер» под существующими блоками — тоггл enabled, поле daily_call_budget, счётчик использовано/бюджет сегодня, последние 10 ScanResult
- Re-scan: per-row кнопка в findings таблице + global "Пересканировать всё" в Settings
- Risk_score отображение: число + badge с цветом (зелёный <30, жёлтый 30-70, красный >70) + категория text

### Storage
- Новая таблица `ScanResult(id, file_hash UNIQUE, file_path, scope (agent|skill), risk_score int, category enum, rationale text, scanned_at, model, ttl_expires_at)` — UPSERT при re-scan того же hash
- ScanResult выше определённого risk_score → автоматически создать Finding (rule_id=`llm.scan.<category>`, severity per score-mapping)
- Идемпотентность: server проверяет cache по file_hash → если hit и not expired → возвращает кэш без call к Anthropic

### Claude's Discretion
- Точная JSON-схема `report_risk` tool
- Cost estimation формула (haiku pricing $0.25/$1.25 per M tokens)
- Точная архитектура async-mutex (asyncio.Lock или threading.Lock)
- Pydantic схемы для request/response

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- v0.1 secret-masking regex в `inventory.py` — переиспользуем для маскирования content'а перед отправкой
- ETag-кэширование паттерн из `/api/v1/policy` — не нужен для scan, но похожий cache-by-hash идея
- Finding SQLModel + emit pattern (как в Phase 2 anomaly_service) — повторяется
- Settings page и SettingsRecord таблица из v0.1 (там должны быть admin-toggles)
- httpx (уже зависимость) — для Anthropic API calls

### Established Patterns
- FastAPI + SQLModel + SQLite WAL; create_all для новых таблиц
- X-CCGuard-Token для agent endpoints (scan-content)
- Cookie auth для admin endpoints (Settings, re-scan кнопки)
- Russian UI strings; English opaque tokens (rule_id, category names)
- Tests: pytest + httpx ASGI client + mock external (Anthropic API mocked)

### Integration Points
- Agent CLI: новая под-команда или extension к `ccguard inventory` для сбора + отправки content при enabled
- Server: новый router `/api/v1/scan-content`; новый router `/admin/llm-settings` или extend Settings
- DB: 2 новые таблицы (ScanResult, LLMCallLog); расширение Settings таблицы (enabled, daily_call_budget) или конфиг
- pyproject.toml: `anthropic>=0.40` (official SDK) — новая dep
- ENV: `ANTHROPIC_API_KEY` обязателен для server при enabled scanner
- /findings UI: расширить filter по rule_id LIKE 'llm.scan.*'

</code_context>

<specifics>
## Specific Ideas

- Anthropic SDK — официальная `anthropic` Python библиотека (не raw httpx — она тонкая, не overkill)
- Tool definition `report_risk`: input_schema `{type: object, properties: {risk_score: {type: integer, minimum: 0, maximum: 100}, category: {type: string, enum: [...]}, rationale: {type: string, maxLength: 500}}}`
- Categories enum: jailbreak | prompt-injection-template | data-exfil | privilege-escalation | benign (последняя — для score < 20)
- Cost estimate: Haiku input $0.25/M tokens, output $1.25/M tokens — sum в LLMCallLog для UI отображения
- Re-scan кнопка: POST `/admin/scan/{file_hash}/re-scan` → invalidates cache + immediate API call
- В Settings показывать: «Использовано: 23/100 calls сегодня • $0.12»
- При server lifespan startup: проверить наличие ANTHROPIC_API_KEY; если scanner enabled но key пустой → warning в логах + flag scanner как disabled

</specifics>

<deferred>
## Deferred Ideas

- Per-tenant API keys (multi-tenant) — v0.3
- Local LLM fallback (Ollama LlamaGuard для prompt-injection) — Phase 5 (runtime), не для content scan
- Async batch API Anthropic — overkill для <100 машин в сутки
- Webhook для high-severity findings → SIEM (Phase 6)
- Manual upload/review UI (просмотр content + human override score) — v0.3
- Цепочка scanner-models (Haiku → Sonnet retry для borderline scores) — позже если будут false positives
- Embedding-based similarity (cluster похожих jailbreak'ов) — v0.4+

</deferred>
