# Phase 4: Push-Install (Centrally-Managed Config) - Context

**Gathered:** 2026-05-26
**Status:** Ready for planning

<domain>
## Phase Boundary

Сервер декларирует обязательные MCP/skills/agents/CLAUDE.md секции через расширенную policy; агент при sync применяет их к `~/.claude/` с atomic write + rollback on error. Покрывает PUSH-01..04. **Не включает**: per-user differential push (multi-tenant v0.3), policy drift detection beyond apply event (Phase 2 anomaly уже частично покрывает).

</domain>

<decisions>
## Implementation Decisions

### Policy Schema Extension
- Policy YAML расширяется 4 новыми секциями: `required_mcp_servers`, `required_skills`, `required_agents`, `managed_claude_md_blocks`
- Schema version bump: minor (например `0.2 → 0.3`); agent v0.2 graceful — игнорирует неизвестные секции
- ETag-кэширование policy (из v0.1) автоматически обновится через hash содержимого

### Agent Apply Mechanics
- Skills/agents/MCP: **drop-in** — write content to `~/.claude/agents/{name}.md`, `~/.claude/skills/{name}/SKILL.md`, `~/.claude.json` MCP merge
- CLAUDE.md: **merge via markers** — `<!-- ccguard:managed start {id} -->` / `<!-- ccguard:managed end {id} -->`; user content вне маркеров сохраняется; managed блоки rewriteable
- Atomic write: temp-file + `os.replace()` (POSIX atomic rename) — никогда half-written файлы
- Snapshot перед apply: copy targeted files to `~/.ccguard/snapshots/{ts}/` (rolling 5 last snapshots)
- Rollback: on ANY exception во время apply → restore из самого свежего snapshot + emit `policy.apply.rollback` audit event с reason
- Apply порядок: snapshot → write all → verify (file exists + content match) → если verify failed → rollback
- Permission errors не блокируют другие файлы — partial rollback с отдельным reason per file

### UI: Mandatory Tab
- /policy получает новую вкладку «Обязательные» (Mandatory) рядом с существующей формой policy
- Editor для каждой секции:
  - **required MCP servers**: list с inline form (name, command, args, env)
  - **required skills**: list с (name, content textarea, frontmatter тип)
  - **required agents**: list с (name, content textarea)
  - **managed_claude_md_blocks**: list с (id, content textarea, description)
- Draft → Publish → History flow как уже есть в v0.1; revision bump на publish

### Audit Events
- Новые audit event types: `policy.apply.success` (details: applied_count, snapshot_id), `policy.apply.rollback` (details: failed_file, reason, snapshot_id)
- Event flow: agent → POST /api/v1/audit (extending existing ToolUseEvent table OR separate? — separate новая таблица `PolicyApplyEvent` для семантической чистоты)
- UI: на /history добавить filter «События политики» / на отдельной странице — для v0.2 включить в /audit как новый source тип

### Claude's Discretion
- Точная YAML-структура managed_claude_md_blocks (list of {id, content} dicts)
- Имена rollback-snapshot директорий
- Стратегия conflict resolution при manual edit того же managed-block ID — overwrite vs warn
- UI editor type — plain textarea для v0.2 (Monaco overkill)

</decisions>

<code_context>
## Existing Code Insights

### Reusable Assets
- v0.1 Policy YAML + revision/publish/history flow — расширяем секциями, ничего не ломаем
- `policy_engine.py` — точно знает где applies, новые секции просто добавляются в parser
- ETag-кэш `/api/v1/policy` — автоматически работает после bump revision
- Agent inventory.py — знает где `~/.claude/agents`, `~/.claude/skills`, `~/.claude.json`
- Settings draft/publish UI pattern — копия для Mandatory tab

### Established Patterns
- Pydantic v2 валидация policy на сервере (отклонять malformed) + клиент-side проверка перед draft save
- create_all для новой таблицы PolicyApplyEvent
- httpx GET /api/v1/policy на агенте — расширяем response parsing
- Snapshot pattern: `~/.ccguard/snapshots/{iso_ts}/` — переиспользуем директорию `~/.ccguard/` уже созданную для audit buffer Phase 1
- Маскирование секретов в MCP `env` ПЕРЕД отправкой на сервер уже работает (v0.1), при push обратно — никаких секретов в push (admin кладёт plain в editor → policy storage всё равно encrypted Fernet)

### Integration Points
- `src/ccguard/server/db/models.py`: новый `PolicyApplyEvent` table
- `src/ccguard/schemas/policy.py`: расширение Pydantic с 4 новыми секциями
- `src/ccguard/server/web/routes.py`: новая страница `/policy/mandatory` (или tab внутри /policy)
- `src/ccguard/agent/`: новый модуль `push_install.py` — apply + rollback logic
- `src/ccguard/agent/cli.py`: hook в sync command — после получения policy → push_install.apply()
- `~/.claude.json`: MCP merge стратегия — replace ccguard-managed entries (помеченные marker'ом в JSON через `_managed_by: ccguard` поле), оставить user entries
- POST /api/v1/audit endpoint расширяется (new event_source='policy_apply') — backward-compat

</code_context>

<specifics>
## Specific Ideas

- Snapshot retention: 5 последних в `~/.ccguard/snapshots/`, older auto-deleted
- managed block ID format: kebab-case alphanumeric (`security-rules`, `owasp-top10`)
- Marker comments в CLAUDE.md: ровно `<!-- ccguard:managed start {id} -->\n{content}\n<!-- ccguard:managed end {id} -->`
- Push UI: «Применить ко всем машинам» — нет, push pull-based (агент при sync) — не нарушаем модель
- Verify after write: SHA256 содержимого vs expected; mismatch → rollback
- ~/.claude.json merge: ccguard-managed entries имеют prefix `ccguard-` в keys + `_managed_by: ccguard` marker — agent при apply удаляет старые ccguard-managed и добавляет новые из policy
- При cold-start agent без `~/.claude/` (свежая машина): создаёт директории + apply

</specifics>

<deferred>
## Deferred Ideas

- Per-team/per-role differential push — v0.3 multi-tenant
- Push notification (server → agent realtime, не pull) — v0.4 (нужен websocket / SSE)
- Conflict resolution UI (admin видит divergence per machine) — v0.3
- Time-based scheduled push (apply at midnight UTC) — v0.4
- Multi-version managed blocks (admin может pin specific version) — v0.3
- Encrypted managed content (требует key distribution) — out of scope

</deferred>
