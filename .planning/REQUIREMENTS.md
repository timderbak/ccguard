# Requirements: ccguard v0.2 "Behavioral EDR + Compliance"

**Defined:** 2026-05-25
**Core Value:** Полная visibility + behavioral enforcement на каждом developer-эндпоинте, где живёт AI-агент с правом на Bash/Write/Edit
**Prior milestone:** v0.1.0-alpha (185 тестов, web UI на русском, MVP в production-like deploy)

## v1 Requirements

Требования v0.2 milestone. Каждое мапится на phase в ROADMAP.md.

### Tool-Use Audit

- [ ] **TUA-01**: PostToolUse hook собирает фактические `(tool_name, tool_input_fingerprint, decision, result_status, ts)` без сохранения полного tool_input (privacy)
- [ ] **TUA-02**: Агент агрегирует и шлёт batch на `/api/v1/audit` (расширение существующей `AuditRecord`-таблицы, новые поля)
- [ ] **TUA-03**: Web UI: страница `/audit` с фильтрами machine/tool_name/decision/timeframe + timeline-граф

### Anomaly Detection

- [ ] **ANO-01**: Per-machine baseline (rolling 14-дневное окно) для метрик: `bash_calls/day`, `new_mcp/week`, `new_agents/week`, `skill dir_hash changes`
- [ ] **ANO-02**: Алерт severity=warn при отклонении >3σ от median; финдинги в существующую `findings` таблицу с `rule_id=anomaly.*`
- [ ] **ANO-03**: Web UI: блок «Anomalies» на Overview + страница drill-down с timeseries-графиком

### LLM Content Scanner

- [ ] **LLM-01**: Content-scanner для `~/.claude/agents/*.md` и `~/.claude/skills/*/SKILL.md` через Anthropic API (`ANTHROPIC_API_KEY` env var)
- [ ] **LLM-02**: Risk score 0-100 + категории: `jailbreak | prompt-injection-template | data-exfil | privilege-escalation | benign`
- [ ] **LLM-03**: Кэш по `file_hash` в новой таблице `ScanResult` — не пересканировать; TTL 30 дней; manual "re-scan" кнопка в UI
- [ ] **LLM-04**: Settings UI: вкл/выкл сканер, бюджет (max calls/day), вывод последних N результатов; счётчик потраченных calls

### Push-Install (Centrally-Managed Config)

- [ ] **PUSH-01**: Policy расширяется секциями `required_mcp_servers`, `required_skills`, `required_agents` — сервер раздаёт через `/api/v1/policy`
- [ ] **PUSH-02**: Агент применяет required-артефакты к `~/.claude/` (drop-in или symlink) при sync; rollback на ошибках записи
- [ ] **PUSH-03**: Centrally-managed CLAUDE.md секции через marker-блоки `<!-- ccguard:managed start ID -->` … `<!-- ccguard:managed end ID -->`; merge с пользовательским CLAUDE.md
- [ ] **PUSH-04**: Web UI: editor для required-артефактов в `/policy`, отдельная вкладка «Mandatory»

### Prompt-Injection Detection

- [ ] **PI-01**: PreToolUse shim: regex-набор по `tool_input.command` / `tool_input.prompt` (паттерны: «ignore previous instructions», jailbreak templates, base64-encoded prompts)
- [ ] **PI-02**: Опционально LlamaGuard 8B (local Ollama) — feature-flag в policy
- [ ] **PI-03**: Финдинги severity=warn по умолчанию, опция severity=block в policy
- [ ] **PI-04**: Policy section `prompt_injection`: `enabled`, `severity`, `regex_patterns`, `allowlist_patterns` (для security research), `llama_guard.enabled`

### SIEM Export

- [ ] **SIEM-01**: Splunk HEC streaming findings + audit events (URL + token в Settings UI, токен шифрованно в БД через Fernet)
- [ ] **SIEM-02**: Syslog (UDP/TCP, RFC 5424) альтернативный канал
- [ ] **SIEM-03**: Generic webhook (HTTP POST + HMAC SHA256 signature header)
- [ ] **SIEM-04**: Retry с exponential backoff, dead-letter queue в БД, Settings UI с health-индикатором каждого канала

### Compliance Mapping

- [ ] **COMP-01**: Маппинг наших policy-правил на NIST AI RMF 1.0 controls (Govern 1.1 / Map 2.x / Measure 3.x / Manage 4.x)
- [ ] **COMP-02**: SOC2 CC6 (logical access) + CC7 (system operations) — auto-generated evidence из audit log
- [ ] **COMP-03**: EU AI Act Article 9 (risk mgmt) + 12 (record-keeping) + 14 (human oversight) — чеклист coverage
- [ ] **COMP-04**: Web UI: страница `/compliance` — matrix «контроль × статус (covered/partial/missing)», auto-generated PDF report через reportlab

## v2 Requirements

Deferred — следующий milestone v0.3.

### Multi-Tenant

- **MT-01**: Organizations + Teams в schema
- **MT-02**: RBAC roles (admin / responder / reader)
- **MT-03**: Team-isolated policy + per-team findings views

### SSO

- **SSO-01**: OIDC (Google, Okta)
- **SSO-02**: SAML 2.0 для enterprise

### Active Response (v0.4+)

- **RESP-01**: Quarantine (вывести машину из network через MDM API)
- **RESP-02**: Auto-rollback `~/.claude/` к доверенному snapshot
- **RESP-03**: Just-in-time access — временно разрешить tool по тикету в Jira/ServiceNow

### Cross-Tool Support (v0.4+)

- **XT-01**: Cursor agent inventory
- **XT-02**: Aider, Codex CLI
- **XT-03**: Shared policy YAML между AI-кодерами

## Out of Scope

Явные исключения для v0.2 — задокументированы чтобы не размывать scope.

| Feature | Reason |
|---|---|
| Multi-tenant | Большой блок работы (RBAC, isolation); отдельный milestone v0.3 |
| SSO (OIDC/SAML) | Требует multi-tenant как фундамент |
| Model validation / red-teaming | Не наш класс задач (Robust Intelligence territory). Мы — endpoint, не модель |
| Mobile app | Web-first; mobile только при реальных требованиях |
| AI Access (per-employee approved list) | Cisco AI Defense фича; держим focus на самих эндпоинтах |
| Cross-tool (Cursor, Aider, Codex) | v0.4 milestone; v0.2 — Claude Code only |
| ML-based anomaly | Простая статистика (3σ) в v0.2; ML позже когда соберём данные |
| Active response | v0.4+; в v0.2 только detection + alerting |
| Postgres migration | SQLite WAL пока хватает (<100 машин); миграция при scale-out |

## Traceability

Каждое требование → ровно одна фаза. Заполняется gsd-roadmapper.

| Requirement | Phase | Status |
|---|---|---|
| TUA-01 | Phase 1 | Pending |
| TUA-02 | Phase 1 | Pending |
| TUA-03 | Phase 1 | Pending |
| ANO-01 | Phase 2 | Pending |
| ANO-02 | Phase 2 | Pending |
| ANO-03 | Phase 2 | Pending |
| LLM-01 | Phase 3 | Pending |
| LLM-02 | Phase 3 | Pending |
| LLM-03 | Phase 3 | Pending |
| LLM-04 | Phase 3 | Pending |
| PUSH-01 | Phase 4 | Pending |
| PUSH-02 | Phase 4 | Pending |
| PUSH-03 | Phase 4 | Pending |
| PUSH-04 | Phase 4 | Pending |
| PI-01 | Phase 5 | Pending |
| PI-02 | Phase 5 | Pending |
| PI-03 | Phase 5 | Pending |
| PI-04 | Phase 5 | Pending |
| SIEM-01 | Phase 6 | Pending |
| SIEM-02 | Phase 6 | Pending |
| SIEM-03 | Phase 6 | Pending |
| SIEM-04 | Phase 6 | Pending |
| COMP-01 | Phase 7 | Pending |
| COMP-02 | Phase 7 | Pending |
| COMP-03 | Phase 7 | Pending |
| COMP-04 | Phase 7 | Pending |

**Coverage:**
- v0.2 requirements: 26 total
- Mapped to phases: 26
- Unmapped: 0 ✓

---
*Requirements defined: 2026-05-25*
*Last updated: 2026-05-25 after initial definition for v0.2*
