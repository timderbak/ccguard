# Phase 2: Anomaly Detection - Context

**Gathered:** 2026-05-25
**Status:** Ready for planning

<domain>
## Phase Boundary

Per-machine rolling baseline (14-day window) для 4-х метрик tool-use поведения + 3σ-алерты. Включает:
- Background scheduler (hourly tick) пересчитывающий baseline для каждой машины
- Новая таблица `MachineBaseline` (read-cached aggregate)
- Генерация finding'ов severity=warn с rule_id=`anomaly.*` при отклонении >3σ
- Overview-карта "Anomalies" (top-5 recent)
- Drill-down /anomalies — таблица × sparkline + timeseries с baseline-полосой

Покрывает ANO-01, ANO-02, ANO-03. **Не включает**: ML-detection (v0.3+), alerting через email/Slack (Phase 6 SIEM).

</domain>

<decisions>
## Implementation Decisions

### Baseline Computation
- Пересчёт baseline: APScheduler in-process, hourly tick на сервере (для <100 машин нагрузка минимальна)
- Алгоритм: sample mean + sample stdev (`statistics.stdev`) по последним 14 daily/weekly point'ам
- Cold-start: warm-up флаг `baseline_ready=False` пока < 7 точек данных; не генерим finding'и в этот период
- Хранение: новая таблица `MachineBaseline(machine_id, metric, median, sigma, sample_count, baseline_ready, updated_at)` — uniqueness on (machine_id, metric)

### Metrics & Alerting
- 4 метрики:
  - `bash_calls_per_day` — count(ToolUseEvent where tool_name='Bash') GROUP BY day
  - `new_mcp_per_week` — inventory diff: уникальные MCP servers впервые seen за последние 7 дней
  - `new_agents_per_week` — inventory diff: agent dir_hash changes за 7 дней
  - `skill_dir_hash_changes_per_week` — count изменений skill_dir_hash за 7 дней
- Источник new_mcp/new_agents: diff между последовательными InventoryReport snapshot'ами одного machine_id
- Дедупликация: один finding в день per (machine_id, metric); поиск по `rule_id` + `machine_id` + same day
- rule_id format: snake_case dot-namespaced — `anomaly.bash_calls_per_day`, `anomaly.new_mcp_per_week`, `anomaly.new_agents_per_week`, `anomaly.skill_dir_hash_changes_per_week`
- severity: всегда `warn` (per ANO-02)

### UI Drill-down
- Overview: новая card "Anomalies" под существующими summary-tiles; top-5 recent anomalies (machine_id link + metric + current vs baseline)
- /anomalies: таблица "machine × 4 метрики" с CSS sparkline-колонкой (mini bar chart 14 точек); клик по строке/cell → drill-down
- Timeseries-график: 14-day daily values + baseline-полоса (median ± 3σ светло-серым) + outlier points красным
- Chart: CSS-only (как в Phase 1 audit timeline) — никакого JS, единый стиль

### Claude's Discretion
- Точные имена колонок MachineBaseline и Alembic-style миграции через create_all
- APScheduler integration — embedded в FastAPI lifespan (`startup`/`shutdown`)
- Структура service-modulей (anomaly_service, baseline_service)
- Bot-protection scheduler-tick при множественных workers — single-process для self-hosted достаточно

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- `ToolUseEvent` table из Phase 1 — источник bash_calls_per_day
- `Finding` SQLModel — паттерн новой записи (severity=warn, rule_id, machine_id, details JSON)
- `InventoryReport` SQLModel + maskirovka — diff source для new_mcp/new_agents
- Overview page (`templates/overview.html`) — паттерн нового card-блока
- HTMX polling pattern из audit timeline — переиспользуем для /anomalies refresh
- CSS bar-chart из `_audit_timeline.html` — копия для sparkline и timeseries

### Established Patterns
- FastAPI + SQLModel + SQLite WAL; `create_all` для новых таблиц
- AuthZ split: cookie для админ-UI, X-CCGuard-Token для agent-API (последний не нужен — anomaly это server-side computation)
- HTMX-fragments под `/_partials/*`; Jinja2 templates под `templates/`
- Russian UI strings, English opaque tokens (rule_id, metric_name)
- Tests: pytest unit + integration; e2e light

### Integration Points
- FastAPI `lifespan` context — register APScheduler start/shutdown
- New router `/anomalies` + admin auth dep
- New partial `/_partials/anomalies/overview` for HTMX poll on Overview
- `templates/base.html` — добавить nav link "Аномалии" между Аудит и Политика
- DB: новая таблица MachineBaseline via `init_db` + `create_all`; `Finding` re-use без миграции

</code_context>

<specifics>
## Specific Ideas

- 14-day rolling window — это календарных дней; точки aggregate to day boundaries (UTC)
- Daily/weekly differentiation: 2 метрики daily (bash_calls), 3 метрики weekly (new_mcp, new_agents, skill_dir_hash_changes)
- Baseline-полоса визуально: тонкая горизонтальная полоса с opacity 30%, цвет slate-300
- Outlier point: красная точка диаметром 4-6px поверх линии
- Sparkline в таблице /anomalies: 14 vertical bars, height proportional, 80px wide × 24px tall
- Anomaly card на Overview обновляется HTMX poll каждые 60s (не critical, можно реже чем audit timeline 30s)
- Pseudo-streaming: при baseline переcalc не оверrite a stale finding в тот же день (idempotent insertion)

</specifics>

<deferred>
## Deferred Ideas

- ML-based anomaly detection (autoencoder, isolation forest) — v0.3+
- Email/Slack/Pager alerting — Phase 6 SIEM-канал
- Multi-metric correlation (e.g. "bash spike + new MCP appeared" = highest severity) — v0.3
- Per-team baseline (multi-tenant) — v0.3
- Adaptive threshold (не 3σ а ML-learned) — v0.3+
- Pre-aggregated daily summary table (если SQL aggregation на ToolUseEvent станет медленным) — оптимизация когда понадобится
- Mute/snooze finding'ов — v0.3 (нужен RBAC)

</deferred>
