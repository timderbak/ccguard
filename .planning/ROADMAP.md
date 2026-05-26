# Roadmap: ccguard v0.2 "Behavioral EDR + Compliance"

**Created:** 2026-05-25
**Mode:** mvp (vertical slices: DB → service → API → UI → tests)
**Granularity:** standard
**Phases:** 7
**Coverage:** 26/26 v0.2 requirements mapped

## Phases

- [ ] **Phase 1: Tool-Use Audit (Foundation)** — Собрать фактические tool-use события через PostToolUse hook и показать timeline в web UI
- [ ] **Phase 2: Anomaly Detection** — Per-machine baseline + 3σ-алерты на отклонения в tool-use поведении
- [ ] **Phase 3: LLM Content Scanner** — Сканировать agents/skills через Anthropic API на jailbreak/prompt-injection с кэшем по hash
- [ ] **Phase 4: Push-Install (Centrally-Managed Config)** — Сервер декларирует required MCP/skills/agents/CLAUDE.md, агент применяет
- [ ] **Phase 5: Prompt-Injection Detection** — Regex + optional LlamaGuard на PreToolUse с policy-конфигурируемой severity
- [ ] **Phase 6: SIEM Export** — Splunk HEC + syslog + webhook каналы с retry/DLQ и health-индикаторами
- [ ] **Phase 7: Compliance Mapping** — NIST AI RMF / SOC2 / EU AI Act matrix + auto-generated PDF evidence

## Phase Details

### Phase 1: Tool-Use Audit (Foundation)
**Goal:** Собрать фактические tool-use события через PostToolUse hook и показать timeline в web UI
**Mode:** mvp
**Depends on:** Nothing (foundation, расширяет существующую AuditRecord)
**Requirements:** TUA-01, TUA-02, TUA-03
**Success Criteria:**
1. Агент логирует tool-use в локальный буфер при каждом PostToolUse событии (tool_name, fingerprint, decision, result_status, ts) без сохранения полного tool_input
2. POST /api/v1/audit принимает batch и пишет в расширенную AuditRecord таблицу
3. Web UI /audit показывает события с фильтрами machine/tool_name/decision/timeframe
4. Timeline-граф на /audit отображает события за последние 24h с группировкой по hour
5. Все 185+ existing тестов зелёные + 20+ новых (unit + integration + e2e для /audit)
**Plans:** TBD
**UI hint**: yes

### Phase 2: Anomaly Detection
**Goal:** Per-machine baseline + 3σ-алерты на отклонения в tool-use поведении
**Mode:** mvp
**Depends on:** Phase 1 (audit-данные — источник для baseline)
**Requirements:** ANO-01, ANO-02, ANO-03
**Success Criteria:**
1. Сервер вычисляет rolling 14-дневный baseline (median + σ) для метрик bash_calls/day, new_mcp/week, new_agents/week, skill_dir_hash_changes per-machine
2. При отклонении текущего значения >3σ создаётся finding с severity=warn и rule_id=anomaly.*
3. Web UI Overview содержит блок «Anomalies» с топ-N недавних аномалий
4. Drill-down страница /anomalies показывает timeseries-график метрики с baseline-полосой и выбросами
5. Тесты покрывают: baseline-расчёт с пустыми данными, edge-case <3σ, генерацию finding, UI-rendering
**Plans:** TBD
**UI hint**: yes

### Phase 3: LLM Content Scanner
**Goal:** Сканировать agents/skills через Anthropic API на jailbreak/prompt-injection с кэшем по hash
**Mode:** mvp
**Depends on:** Phase 1 (audit показывает кто/когда менял agents/skills — драйвер re-scan)
**Requirements:** LLM-01, LLM-02, LLM-03, LLM-04
**Success Criteria:**
1. Агент при инвентаризации шлёт содержимое `~/.claude/agents/*.md` и `~/.claude/skills/*/SKILL.md` если scanner включён и ANTHROPIC_API_KEY задан
2. Сервер вызывает Anthropic API и сохраняет risk_score (0-100) + категорию (jailbreak/prompt-injection-template/data-exfil/privilege-escalation/benign) в ScanResult таблицу
3. Повторный скан того же file_hash берётся из кэша (TTL 30 дней); manual «Re-scan» кнопка в UI инвалидирует кэш
4. Settings UI: тоггл вкл/выкл, поле daily_call_budget, счётчик потраченных calls сегодня, список последних N ScanResult
5. Тесты: mock Anthropic API, кэш hit/miss, budget exhaustion (отказ от вызова), UI-rendering ScanResult в /findings
**Plans:** TBD
**UI hint**: yes

### Phase 4: Push-Install (Centrally-Managed Config)
**Goal:** Сервер декларирует required MCP/skills/agents/CLAUDE.md, агент применяет с rollback
**Mode:** mvp
**Depends on:** Phase 1 (audit фиксирует apply events для troubleshooting)
**Requirements:** PUSH-01, PUSH-02, PUSH-03, PUSH-04
**Success Criteria:**
1. /api/v1/policy раздаёт новые секции `required_mcp_servers`, `required_skills`, `required_agents`, `managed_claude_md_blocks`
2. Агент при sync создаёт/обновляет файлы в `~/.claude/` (drop-in для skills/agents, merge для CLAUDE.md через `<!-- ccguard:managed start ID -->` маркеры); ошибки записи откатываются
3. Web UI /policy получает отдельную вкладку «Mandatory» с editor'ом для required-артефактов и managed CLAUDE.md блоков
4. После apply агент шлёт audit-событие `policy.apply.success` или `policy.apply.rollback` с деталями
5. Тесты: drop-in новой skill, conflict с user-edited CLAUDE.md вне маркеров (сохраняется), rollback при permission error, UI CRUD для mandatory секций
**Plans:** TBD
**UI hint**: yes

### Phase 5: Prompt-Injection Detection
**Goal:** Regex + optional LlamaGuard на PreToolUse с policy-конфигурируемой severity
**Mode:** mvp
**Depends on:** Phase 4 (policy расширилась — добавляем новую секцию `prompt_injection`)
**Requirements:** PI-01, PI-02, PI-03, PI-04
**Success Criteria:**
1. ccguard-enforce shim проверяет `tool_input.command`/`tool_input.prompt` против regex-набора (Anthropic Prompt Injection Risk Categories) и создаёт finding если matched
2. При `prompt_injection.llama_guard.enabled=true` shim делает локальный call к Ollama LlamaGuard 8B как deep-scan; failure fail-open
3. Severity finding'а берётся из `policy.prompt_injection.severity` (warn по умолчанию, опция block)
4. Policy section `prompt_injection` редактируется в /policy UI: enabled, severity, regex_patterns, allowlist_patterns, llama_guard toggle
5. PreToolUse latency остаётся <100ms при выключенном LlamaGuard; тесты покрывают match/no-match/allowlist/llama_guard mock
**Plans:** 6 plans
Plans:
- [ ] 05-01-PLAN.md — PromptInjectionConfig + LlamaGuardConfig Pydantic schema + default regex catalog (15+ patterns)
- [ ] 05-02-PLAN.md — prompt_injection_engine: regex + allowlist + Ollama LlamaGuard client + fail-open
- [ ] 05-03-PLAN.md — enforce.decide() integration: PI step, severity→exit-code mapping, finding emit
- [ ] 05-04-PLAN.md — findings_hook/ buffer + flusher (clone audit_hook) + server batch endpoint
- [ ] 05-05-PLAN.md — UI «Prompt-Injection» card on /policy + form parser + ReDoS publish-time guard
- [ ] 05-06-PLAN.md — Integration + e2e + backward-compat tests (≥30 new tests, full pipeline)
**UI hint**: yes

## Deferred to Backlog (v0.3+)

Following phases were planned for v0.2 but moved to backlog on 2026-05-27 per user decision to ship v0.2 with Phases 1-5 (Behavioral EDR core) and defer compliance/SIEM tooling to a follow-up milestone.

### Phase 6: SIEM Export — DEFERRED
Splunk HEC + syslog + webhook каналы с retry/DLQ и health-индикаторами. Requirements: SIEM-01..04.

### Phase 7: Compliance Mapping — DEFERRED
NIST AI RMF / SOC2 / EU AI Act matrix + auto-generated PDF evidence. Requirements: COMP-01..04.

Both phases retain their original requirements in REQUIREMENTS.md and will be planned in the next milestone.

## Progress

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Tool-Use Audit | 0/0 | Not started | - |
| 2. Anomaly Detection | 0/0 | Not started | - |
| 3. LLM Content Scanner | 0/0 | Not started | - |
| 4. Push-Install | 0/0 | Not started | - |
| 5. Prompt-Injection Detection | 0/6 | Planned | - |
| 6. SIEM Export | 0/0 | Not started | - |
| 7. Compliance Mapping | 0/0 | Not started | - |

## Coverage Validation

26/26 v0.2 requirements mapped ✓
- Phase 1: TUA-01, TUA-02, TUA-03 (3)
- Phase 2: ANO-01, ANO-02, ANO-03 (3)
- Phase 3: LLM-01, LLM-02, LLM-03, LLM-04 (4)
- Phase 4: PUSH-01, PUSH-02, PUSH-03, PUSH-04 (4)
- Phase 5: PI-01, PI-02, PI-03, PI-04 (4)
- Phase 6: SIEM-01, SIEM-02, SIEM-03, SIEM-04 (4)
- Phase 7: COMP-01, COMP-02, COMP-03, COMP-04 (4)

No orphans, no duplicates.

---
*Roadmap created: 2026-05-25*
