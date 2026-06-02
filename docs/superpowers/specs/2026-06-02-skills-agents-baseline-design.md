# Skills + Agents TOFU baseline + source tracking — design

**Status:** approved (brainstorm 2026-06-02, no formal user review — "просто делай")
**Sibling:** `2026-06-01-hooks-tofu-baseline-design.md` (same TOFU pattern, different entity)

## Цель

Распространить supply-chain drift detection с хуков на два других класса
исполняемых артефактов Claude Code:

- **Skills** (`~/.claude/skills/<n>/` + `<plugin_install_path>/skills/<n>/`)
- **Agents** (`~/.claude/agents/<n>.md` + `<plugin_install_path>/agents/<n>.md`)

И, попутно, обогатить inventory информацией о происхождении (marketplace /
plugin), чтобы (а) дать пользователю контекст "откуда это вообще взялось"
и (б) сделать возможным fleet-wide агрегацию "у какой версии скилла какая
доля машин".

## Не-цели

- Commands (`~/.claude/commands/`) — текст без исполнения, в этой итерации skip.
- Plugin-уровневый baseline (enable/disable drift) — отдельная фича.
- LLM-сканер skills/agents — уже существует на `/admin/skills`, не трогаем.

## Архитектурный обзор

Зеркалим решение из `2026-06-01-hooks-tofu-baseline-design.md`:

- Две новые SQLModel-таблицы: `SkillBaseline`, `AgentBaseline`.
- Сервис `skill_baseline_service` + `agent_baseline_service` с
  `compute_fingerprint` / `update_and_detect` / `accept_baseline` /
  `accept_all_pending` / `reject_and_mark`.
- POST `/api/v1/inventory` вызывает оба `update_and_detect` рядом с
  `hook_baseline_service` и `mcp_baseline_service`.
- Web-routes `/machines/{id}/skill-baseline/...` + `/agent-baseline/...`
  по той же сигнатуре что и hook-baseline routes.
- UI на `machine_detail`: bootstrap-banner + drift-cards + status-badges
  для skills и agents (повторно используем `_hook_word` плюс новые
  `_skill_word` / `_agent_word` Jinja-filters).
- Новая страница `/admin/skills-inventory` (fleet table, см. §UI).

**Решение: две таблицы, не одна generic `ArtifactBaseline`.** Skills и
agents имеют разную identity (skill = dir_hash папки, agent = file_hash
одного .md), разные кардинальности `tools`/`model`/`description`, и
разные severity-правила. Дискриминатор-колонкой это размазалось бы.

## Identity

| Сущность | Identity-tuple (slot) | Identity-hash в fingerprint |
|---|---|---|
| Skill | `(machine_id, name, origin, parent_plugin)` | `dir_hash` |
| Agent | `(machine_id, name, origin, parent_plugin)` | `file_hash` |

`origin` — `local` / `plugin`. Marketplace `origin` оставляем как
литерал в schema но не эмитим (агент-сканер его не использует).

`parent_plugin` — имя плагина (`name` часть из `name@marketplace`); для
local-артефактов — `None`. Полезно как часть идентичности: если один и
тот же skill-name живёт в двух разных плагинах, это разные slot'ы.

`fingerprint = sha256("{name}|{origin}|{parent_plugin or ''}|{dir_hash}")`
— композитный, по аналогии с хуками.

## Source tracking — поля на baseline-строке

Дополнительные колонки (помимо identity):

- `parent_plugin: str | None` — имя плагина-родителя (для inventory-time).
- `source_marketplace: str | None` — marketplace-key из `enabledPlugins`
  (например `anthropics/claude-plugins-official`). Для local — `None`.

Эти два поля **денормализованы** — повторяются в каждой строке. Это
сознательно: fleet-stats запросы становятся `SELECT source_marketplace,
COUNT(DISTINCT machine_id) GROUP BY source_marketplace` без джойнов, и
UI не нужно резолвить через `PluginEntry`.

Поля заполняются агентом во время сканирования: skills/agents из
`<plugin_install_path>` ассоциируются с `PluginEntry` через ту же
`installed_plugins.json`, где installPath → marketplace-key.

## Расширение agent-сканера

`src/ccguard/agent/scan/agents.py` сейчас обходит только
`~/.claude/agents/`. Расширяем по образцу `skills.py`:

1. Локальные → `origin="local"`, `parent_plugin=None`.
2. Per-plugin: `<plugin_install_path>/agents/*.md` →
   `origin="plugin"`, `parent_plugin=<plugin_name>`.

`AgentEntry` приобретает два новых optional-поля:
- `origin: Literal["local", "plugin"] = "local"` (backward-compat: default
  для v0.2 агентов, новые поля Optional чтобы старые InventoryReport'ы
  валидировались).
- `parent_plugin: str | None = None`.

Аналогично `SkillEntry` уже имеет `origin`, добавляем `parent_plugin`.

## Detection matrix

Severity-калибровка под угрозу:

| Сценарий | Skill | Agent |
|---|---|---|
| Новая запись (после bootstrap) | `warn` (`skill.new`) | `warn` (`agent.new`) |
| Bootstrap (нет ни одного active) | silent | silent |
| Удалена (silent missing) | silent, status="missing" | silent, status="missing" |
| Content drift, скрипты есть (`has_referenced_scripts=True`) | **`block`** (`skill.rug_pull.content`) | n/a |
| Content drift, только SKILL.md | `warn` (`skill.drift.text`) | n/a |
| Content drift, `tools` содержит `Bash` / `Write` / `Edit` | n/a | **`block`** (`agent.rug_pull.dangerous`) |
| Content drift, `tools` без опасных | n/a | `warn` (`agent.drift.text`) |

Логика "опасных tools" — список `{"Bash","Write","Edit","NotebookEdit"}`,
выносим константой в сервис.

## Bootstrap

Тот же подход что и в hooks: если для machine_id нет ни одной
`status="active"` строки в нужной таблице — все новые записи ингестятся
тихо как `pending`, без findings. Первое active появляется → последующие
новые слот'ы дают `warn`-findings.

## Web routes

По образцу `hook_baseline_*` (Task 15 от 2026-06-01):

```
POST /machines/{id}/skill-baseline/{bl_id}/accept
POST /machines/{id}/skill-baseline/accept-all-pending
POST /machines/{id}/skill-baseline/{bl_id}/reject
POST /machines/{id}/agent-baseline/{bl_id}/accept
POST /machines/{id}/agent-baseline/accept-all-pending
POST /machines/{id}/agent-baseline/{bl_id}/reject
```

Все шесть — `RedirectResponse(303)` на `/machines/{id}`, CSRF-защищены,
`LookupError` → 404. Можно вынести общий хелпер в
`server/web/routes.py` чтобы не повторять 6 идентичных хендлеров;
условие "стоит ли" решит executor когда увидит код.

## UI

### machine_detail (расширение)

Перед существующим блоком «Хуки Claude Code» рендерим (в порядке
важности):

1. `_skill_baseline_banner.html` (bootstrap для skills) + `_skill_drift_cards.html`
2. `_agent_baseline_banner.html` (bootstrap для agents) + `_agent_drift_cards.html`

Status-badges на каждой записи в блоках skills/agents (analog Task 18 на
хуках): `baseline` / `pending` / `drift accepted` чипы.

Для drift-cards источник в payload — на каждой карточке маленький
"источник" badge: `{parent_plugin}@{source_marketplace}` или
`local`. Это даёт пользователю мгновенный ответ "это откуда?".

### Fleet inventory — новая страница `/admin/skills-inventory`

Двухколоночный layout:

**Колонка 1: skills aggregate**
- Table: skill_name → marketplace → версии (distinct `dir_hash`) → machines_count_per_version
- Сортировка по убыванию `machines_using`
- Подсветка строк где `count(distinct dir_hash) > 1` (divergence!) — это
  явный signal supply chain / локального тампера.

**Колонка 2: agents aggregate** — то же самое для `AgentBaseline`.

Header показывает totals (всего baselines, divergent count, machines).

Запросы — два SELECT GROUP BY (skill_name, marketplace, dir_hash). При
~10 машинах и десятках skill'ов это <100ms на SQLite, не нужен кэш.

### Drill-down "risk skills"

Кликабельная строка в fleet-table раскрывает: список (machine_label,
dir_hash, status, first_seen). Реализуем как HTMX `hx-get` partial,
чтобы не перегружать страницу.

## Backward compat

- Новые optional-поля в `SkillEntry` / `AgentEntry` — default'ы None /
  "local" чтобы v0.1/v0.2 агенты, не знающие про эти поля, продолжали
  валидироваться.
- Старые InventoryReport snapshot'ы парсятся без потерь.
- Если у строки `parent_plugin=None` и `source_marketplace=None`, fleet-
  table отображает её как "local / unknown source".

## Тесты

По образцу hooks (`tests/unit/test_hook_*.py` + `tests/integration/`):

- `tests/unit/test_skill_baseline_service.py` (compute_fingerprint, update_and_detect: bootstrap, new, drift_content, drift_text, removal, ownership).
- `tests/unit/test_skill_baseline_accept_flow.py` (accept, accept_all, reject).
- `tests/unit/test_agent_baseline_service.py` + accept flow аналогично.
- `tests/unit/test_agent_scan_plugin_dirs.py` — новый сканер обходит plugin/agents/.
- `tests/integration/test_inventory_emits_skill_findings.py` (wire).
- `tests/integration/test_inventory_emits_agent_findings.py` (wire).
- `tests/integration/test_machine_detail_skill_baseline_ui.py` (banner/cards/badges + 6 routes).
- `tests/integration/test_machine_detail_agent_baseline_ui.py` (то же для agents).
- `tests/integration/test_admin_skills_inventory.py` — fleet aggregate + divergence highlight + drill-down partial.

Regen snapshot `machine_detail_with_risk.html` при необходимости (вероятно
ничего — partials условные, при пустых данных рендерят пусто).

## Деплой

После всех зелёных тестов — rsync на VPS (как делали с хуками 2026-06-02),
docker compose rebuild, smoke-check `/health` + `/admin/skills-inventory`.

## Roll-out риски

- Денормализация `parent_plugin`/`source_marketplace`: если в будущем
  marketplace переименуется, исторические baseline-строки сохранят
  старое имя. ОК для v0.2 (TOFU baseline и так привязан к моменту
  принятия), нет нужды в миграции.
- Plugin-bundled agent-сканер может в первый запуск выкатить большой
  bootstrap (десятки агентов из claude-mem / context-mode / superpowers).
  Bootstrap-silent режим это покрывает — баннер сгруппирует.
- Fleet `/admin/skills-inventory` при пустом флите (1-2 машины) выглядит
  бледно. ОК — это вложение в будущее, рендерится корректно даже при 0
  строк.
