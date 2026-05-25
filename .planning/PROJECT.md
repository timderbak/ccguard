# ccguard

## What This Is

**EDR-слой для AI-агентов на developer-эндпоинтах.** Self-hosted central server + endpoint agent, которые инвентаризируют, контролируют и enforcement'ят конфигурацию Claude Code (MCP-серверы, skills, hooks, agents, commands, permissions) в организации. Целевая аудитория — AppSec/SecOps команды в финтехе, healthtech и гос-секторе, для которых классический EDR (CrowdStrike, SentinelOne) и cloud-AI-WAF (Cisco AI Defense, Lakera) не покрывают слепое пятно: shell-execution через AI dev-tooling.

## Core Value

**Полная visibility + behavioral enforcement на каждом developer-эндпоинте, где живёт AI-агент с правом на Bash/Write/Edit.** Если ИБ не видит и не блочит — атака через supply chain плагин с `tools: Bash` обходит весь EDR.

## Requirements

### Validated

<!-- v0.1.0-alpha — shipped, проверено на собственной dev-машине. 185 unit+integration тестов. -->

- ✓ **INV-01**: Agent CLI инвентаризирует MCP-серверы из `~/.claude.json`, `~/.claude/.mcp.json`, settings.json — v0.1
- ✓ **INV-02**: Agent инвентаризирует skills (с `dir_hash`), plugins, hooks (с `file_hash` скрипта), agents (с `tools` из frontmatter), commands, env_keys, permissions — v0.1
- ✓ **INV-03**: Маскирование секретов (JWT, sk-*, AKIA, ghp_*, и т.п.) в args MCP до отправки — v0.1
- ✓ **POL-01**: Policy engine с 7 секциями (mcp/network/commands/skills/hooks/agents/env), severity warn|block|info, allowlist/denylist/deny_all_unknown, `trusted_*_hashes` — v0.1
- ✓ **ENF-01**: `ccguard-enforce` shim как PreToolUse hook, allow/deny по Claude Code hook-протоколу, `block_fail_mode: open|closed` — v0.1
- ✓ **SRV-01**: FastAPI + SQLite сервер: `/api/v1/{health,inventory,policy,machines,findings}`, ETag-кэширование policy — v0.1
- ✓ **UI-01**: Web UI на русском с Jinja2+HTMX+Tailwind: 6 страниц (Обзор/Машины/Находки/Политика/История/Настройки), cookie-auth админа отдельно от X-CCGuard-Token агентов, CSRF на POST — v0.1
- ✓ **UI-02**: Policy editor form-only, draft→publish с диффом и историей версий, rollback — v0.1
- ✓ **UI-03**: Token CRUD (sha256 хеши), смена admin password, env→DB bootstrap — v0.1
- ✓ **OPS-01**: Docker compose deploy одной командой — v0.1

### Active

<!-- v0.2 "Behavioral EDR + Compliance" — текущий milestone. 7 фич, разбитых на фазы. -->

**Tool-use audit (Foundation):**
- [ ] **TUA-01**: PostToolUse hook собирает фактические `(tool_name, tool_input_fingerprint, decision, result_status)` без сохранения полного tool_input
- [ ] **TUA-02**: Агрегация на агенте + batch-отправка на `/api/v1/audit` (extension of existing AuditRecord)
- [ ] **TUA-03**: UI-страница `/audit` с фильтрами по machine/tool_name/decision и timeline

**Anomaly detection:**
- [ ] **ANO-01**: Per-machine baseline (rolling 14-дневное окно) для метрик: bash_calls/day, new MCP/week, agents/week, skill dir_hash changes
- [ ] **ANO-02**: Алерт severity=warn при отклонении >3σ от median; ML/детектор позже
- [ ] **ANO-03**: UI: блок «Anomalies» на Overview + страница drill-down

**LLM content scanner:**
- [ ] **LLM-01**: Content-scanner для `~/.claude/agents/*.md` и `~/.claude/skills/*/SKILL.md` через Anthropic API (ANTHROPIC_API_KEY env)
- [ ] **LLM-02**: Risk score 0-100 + категории (jailbreak / prompt-injection-template / data-exfil / privilege-escalation)
- [ ] **LLM-03**: Кэш по file_hash в БД (`ScanResult` table) — не пересканировать; TTL 30 дней; manual `re-scan` button
- [ ] **LLM-04**: Settings UI: вкл/выкл сканер, бюджет (max calls/day), вывод последних N результатов

**Push-install (centrally-managed config):**
- [ ] **PUSH-01**: Policy расширяется секциями `required_mcp_servers`, `required_skills`, `required_agents` — сервер раздаёт их через `/api/v1/policy`
- [ ] **PUSH-02**: Агент применяет required-артефакты к `~/.claude/` (drop-in или симлинк) при sync, с rollback на ошибках
- [ ] **PUSH-03**: Centrally-managed CLAUDE.md секции (например, OWASP Top 10 правила) — merge с пользовательским CLAUDE.md через marker-блоки
- [ ] **PUSH-04**: UI: editor для required-артефактов в /policy, отдельная вкладка «Mandatory»

**Prompt-injection детект на tool_input:**
- [ ] **PI-01**: На PreToolUse shim: regex-набор (Anthropic Prompt Injection Risk Categories) по `tool_input.command` / `prompts`
- [ ] **PI-02**: Опционально LlamaGuard 8B (local Ollama) с конфиг-флагом для глубокого скана
- [ ] **PI-03**: Финдинги severity=warn по умолчанию, опция severity=block в policy
- [ ] **PI-04**: Policy section `prompt_injection` с allowlist_patterns (chemistry/security research exceptions)

**SIEM export:**
- [ ] **SIEM-01**: Splunk HEC streaming findings + audit events (configurable URL + token в Settings UI, шифрованно в БД)
- [ ] **SIEM-02**: Syslog (UDP/TCP, RFC 5424) альтернатива
- [ ] **SIEM-03**: Generic webhook (HTTP POST with HMAC signature) для произвольных SOAR
- [ ] **SIEM-04**: Retry с exponential backoff, dead-letter queue в БД, Settings UI с health-индикатором

**Compliance mapping:**
- [ ] **COMP-01**: Маппинг наших policy-правил на NIST AI RMF 1.0 (Govern/Map/Measure/Manage) controls
- [ ] **COMP-02**: SOC2 CC6/CC7 evidence-generation из audit log
- [ ] **COMP-03**: EU AI Act Article 9-15 чеклист coverage
- [ ] **COMP-04**: UI-страница `/compliance`: matrix-табличка «контроль × статус», auto-generated PDF отчёт

### Out of Scope

<!-- Не в этом milestone. -->

- **Multi-tenant (Organizations/Teams)** — отдельный milestone v0.3; multi-tenant требует RBAC, SSO, team-isolated policy — большой блок работы
- **SSO (OIDC, SAML)** — следует за multi-tenant
- **Model validation / red-teaming** — out of scope как класс задач (это Robust Intelligence territory; мы — endpoint, не модель)
- **Mobile app для админов** — web-first; mobile только если будут реальные требования
- **AI Access (per-employee approved AI apps list)** — фича Cisco AI Defense; пока за рамками — мы держим focus на самих эндпоинтах
- **Cross-tool (Cursor, Aider, Codex)** — v0.4 milestone; v0.2 остаётся Claude Code-only
- **ML-based anomaly detection** — для v0.2 простая статистика (3σ); ML позже
- **Active response (quarantine, MDM API)** — v0.4+; в v0.2 только detection + alerting

## Context

**Кодовая база:**
- Python 3.12, FastAPI, SQLModel/SQLite, pydantic v2
- Web UI: HTMX + Jinja2 + Tailwind (server-rendered, без npm в Dockerfile)
- Agent CLI: typer, httpx
- 185 unit+integration тестов, 1 e2e smoke test, всё в green
- Repo: github.com/timderbak/ccguard (master branch)

**Текущий рантайм:**
- Сервер в docker compose, агент через `pip install -e .`
- Bootstrap policy из `examples/policy.example.yaml` (revision 4, permissive)
- Один admin (admin/admin), bcrypt-хеш в env

**Конкуренты:**
- **Cisco AI Defense** (GA 2025): cloud-focused, 4 модуля (Visibility, Access, Runtime Protection, Model Validation). Мы — endpoint-focus, белое пятно у них.
- **Lakera Guard**: только prompt-injection runtime API, не EDR
- **Robust Intelligence**: model red-teaming, не endpoint

**Документация v0.1:**
- `docs/SPEC.md`, `docs/BRAINSTORM.md`, `docs/PLAN.md`, `docs/HOOKS_PROTOCOL.md`
- `docs/superpowers/specs/2026-05-24-ccguard-web-ui-design.md` — спека веб-UI v0.1
- `docs/superpowers/plans/2026-05-24-ccguard-web-ui.md` — implementation plan
- `docs/presentations/ccguard-overview.md` — MARP-презентация для стейкхолдеров
- Public: https://timderbak.github.io/ccguard/

## Constraints

- **Tech stack**: Python 3.12, FastAPI, SQLModel, HTMX + Jinja2 — не меняем стек для v0.2
- **Self-hosted**: ВСЁ должно работать on-prem без внешних SaaS; единственное внешнее зависимость — Anthropic API для LLM-сканера, опциональная
- **Single-tenant**: один org на инстанс; multi-tenant перенесён в v0.3
- **Backward compat**: agent v0.1 должен продолжить работать против server v0.2 (graceful degradation новых endpoints)
- **DB**: SQLite WAL-режим, не Postgres — пока < 100 машин; миграция на Postgres в v0.3 если потребуется
- **Performance**: PreToolUse hook latency < 100ms (текущий enforce-shim ≈30ms); prompt-injection scan не должен этого ломать
- **Security**: всё что хранится — хеши или шифрованно (Fernet через `SECRET_KEY` env); никаких plain-text токенов в БД
- **Schema versioning**: `schema_version` в InventoryReport и Policy — повышаем при breaking changes, агент шлёт свою версию, сервер graceful

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Phase ordering: Foundation → Compliance | Поведенческие данные (tool-use audit) — основа для anomaly detection и compliance evidence. Сначала собираем данные, потом обвешиваем. | — Pending |
| LLM-сканер использует ANTHROPIC_API_KEY в env | Стандартно для self-hosted; никаких UI-секретов в БД. Per-tenant ключи — в v0.3 multi-tenant. | — Pending |
| Tool-use audit через PostToolUse (не PreToolUse) | PreToolUse уже занят enforce-shim; PostToolUse фиксирует факт + result_status (success/error). Меньше latency-влияния. | — Pending |
| Push-install — на стороне агента, не админ-команда | Сервер декларативно говорит «нужно»; агент сам разруливает (drop-in vs симлинк), не нужно SSH/MDM. | — Pending |
| LlamaGuard через Ollama (опционально) | Local fallback для prompt-injection если admin не хочет Anthropic API. Качество хуже, но self-contained. | — Pending |
| Compliance — отдельная страница, не часть Settings | Auto-generated PDF — отчётный артефакт для аудиторов, должен быть discoverable. | — Pending |
| SIEM-каналы — все три (Splunk HEC + syslog + webhook) | Финтех почти всегда Splunk; гос-сектор любит syslog; SOAR (Tines, Cortex) — webhook. Покрыть все три сразу. | — Pending |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd:transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd:complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-05-25 after initialization for v0.2 milestone*
