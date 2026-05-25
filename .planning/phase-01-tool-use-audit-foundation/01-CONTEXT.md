# Phase 1: Tool-Use Audit (Foundation) - Context

**Gathered:** 2026-05-25
**Status:** Ready for planning

<domain>
## Phase Boundary

Собрать фактические tool-use события через PostToolUse hook на агенте и показать их в web UI: timeline-граф + фильтруемая таблица событий. Включает:
- PostToolUse hook → локальный SQLite-буфер на агенте
- Batch-отправка событий на новый `POST /api/v1/audit` (расширение существующей AuditRecord-инфры через новую таблицу `ToolUseEvent`)
- UI-страница `/audit` со страничной таблицей и timeline-графом за 24h (детали в `01-UI-SPEC.md`)

Покрывает требования TUA-01, TUA-02, TUA-03. **Не включает**: anomaly detection (Phase 2), LLM scanning (Phase 3).

</domain>

<decisions>
## Implementation Decisions

### Fingerprinting & Privacy
- Алгоритм fingerprint: `sha256(tool_name + ":" + normalized_token).hexdigest()[:16]` — 16 hex chars, детерминированно
- Bash command нормализация: shlex/shell-парсинг → берётся **первая команда** до пайпов/`&&`/`;`; флаги отброшены (`git status -uall && echo ok` → fp по `git status`)
- Edit/Write/Read: fingerprint от `tool_name + ":" + basename(file_path)` — без полного пути (privacy)
- Прочие tools (Task, Glob и т.п.): fingerprint от `tool_name` only, либо от наиболее семантически-значимого поля без leak'а контента
- **Никакого raw `tool_input`** в БД (ни сервер, ни агент-буфер) — строго fingerprint + `tool_name` + `decision` + `result_status` + `ts` + `machine_id`

### Agent-Side Buffering & Batching
- Локальный буфер: SQLite `~/.ccguard/audit_buffer.db` (WAL, переживает рестарт hook-процесса)
- Flush trigger: **50 событий ИЛИ 30 секунд** (что раньше); manual flush при graceful exit агента (`atexit`)
- Backpressure: cap 10k событий; при переполнении — drop-oldest + warning в локальный лог
- PostToolUse hook latency: **< 20ms inline** (только INSERT в локальный SQLite); flush на сервер — фоновый процесс/thread, не блокирует hook
- Flush failure handling: retry с экспоненциальным backoff (3 попытки), при окончательной неудаче события остаются в буфере (subject to overflow rule)

### Server Schema & Timeline Aggregation
- **Новая таблица `ToolUseEvent`** (semantic split с существующей AuditRecord):
  - Поля: `id` PK, `machine_id`, `tool_name`, `fingerprint`, `decision` (allow/deny/error), `result_status` (success/error/blocked), `ts` (UTC datetime), `received_at`
  - SQLModel + Alembic migration
- AuditRecord остаётся для policy-decision-aware событий (как в v0.1) — не трогаем
- Schema versioning: `schema_version` в API request → minor bump (`0.1` → `0.2`); сервер graceful: агенты v0.1 продолжают работать, `/api/v1/audit` — новый endpoint, агент v0.1 его просто не вызывает
- Timeline aggregation: **on-the-fly** через SQL `strftime('%Y-%m-%d %H', ts)` GROUP BY ; кэширование не нужно для <100 машин при SQLite WAL
- Индексы: composite `(machine_id, ts DESC)`, `(tool_name, ts DESC)`, `(decision, ts DESC)` — покрывают все фильтры из UI-SPEC

### Claude's Discretion
- Точные имена колонок и Alembic revision id
- Имя async-flush механизма (thread vs process vs httpx + ThreadPoolExecutor) — выбрать минимально-инвазивно для существующего кода агента
- Структура помощных модулей (fingerprinter.py, buffer.py, flusher.py) — на усмотрение plan-phase

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `enforce-shim` (PreToolUse hook) — уже умеет читать JSON hook-payload, маскировать секреты, ходить в сервер. PostToolUse hook можно построить по тому же шаблону.
- `AuditRecord` SQLModel — паттерн новой таблицы повторяется один в один
- `templates/findings_feed.html` — layout фильтр-бара и таблицы (UI-SPEC явно требует копию)
- `templates/overview.html` HTMX-polling pattern — для timeline-карты
- `templates/base.html` — нав-сайдбар (нужна вставка `<a href="/audit">Аудит</a>`)
- Маскирование секретов из `inventory.py` — переиспользуется в fingerprinter, если придётся обрабатывать args
- ETag-кэширование из `/api/v1/policy` — паттерн для будущего, но в этой фазе `/api/v1/audit` без кэша (write-heavy)

### Established Patterns
- FastAPI + SQLModel + SQLite WAL; миграции — Alembic (один autogenerate per schema change)
- Pydantic v2 для request/response моделей (отдельные от SQLModel)
- HTMX-fragments под `/_partials/*` URL prefix, server-rendered Jinja
- Auth split: cookie-сессия для админ-UI; `X-CCGuard-Token` header для агент-API (sha256-хеш в БД)
- Все strings в UI — на русском; коды/идентификаторы (rule_id, tool_name) — английские опаковые токены
- Тесты: pytest, unit + integration (httpx ASGI client), 1 e2e smoke

### Integration Points
- `pyproject.toml` / agent CLI: новая команда (или подкоманда) для PostToolUse hook entrypoint
- `~/.claude/settings.json` hooks секция: добавить PostToolUse → `ccguard-audit` (или эквивалент); агент-инсталлер должен это уметь
- Server: новый router `/api/v1/audit` под существующий auth middleware
- UI: новый route `/audit` в admin-роутере + 2 partial endpoints (`/_partials/audit/timeline`, `/_partials/audit/events`)
- Nav: одна правка в `templates/base.html`
- DB: один Alembic migration; обновить `schema_version` константу

</code_context>

<specifics>
## Specific Ideas

- UI/UX контракт уже зафиксирован полностью в `01-UI-SPEC.md` — plan-phase должен следовать ему буквально (фильтры, имена query params, HTMX endpoints, состояния, цвета/токены reused).
- 24h timeline: hourly buckets, CSS bar-chart, min-height 2px для непустых часов
- Default LIMIT таблицы = 200 events; pagination — простой `offset/limit` через query params (если plan-phase решит — добавить кнопку «дальше»)
- Click-through на `machine_id` → `/machines/{machine_id}` (уже существует)
- Timeline poll: HTMX `every 30s`, передаёт активные фильтры через `hx-include`

</specifics>

<deferred>
## Deferred Ideas

- ML-классификация tool-use паттернов — Phase 2 (3σ baseline) и v0.3+ (ML)
- Хранение полного tool_input с retention TTL — out of scope (privacy-by-design)
- Real-time push (WebSocket/SSE) timeline — out of scope, 30s polling достаточно
- Export audit-событий в CSV/JSON — мб в Phase 6 (SIEM)
- Per-tool-name detailed drill-down страницы — после того как соберём данные
- Cross-machine aggregations (e.g. "this fingerprint seen on 5 машинах") — Phase 2 anomaly territory

</deferred>
