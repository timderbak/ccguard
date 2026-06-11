# Spec — P3: Auto-enrichment loop (self-hosted, operator-reviewed)

**Дата:** 2026-06-11
**Под-проект:** P3 программы «ccguard → настоящий EDR для AI-агентов»
**Статус:** design (одобрено наперёд; реализуем тем же TDD-циклом)
**Связано:** аудит 2026-06-11 + 7-агентная карта скелета обогащения (memory `project_edr_roadmap_2026_06`)

## 1. Проблема и находка

Потолок покрытия ccguard — закрытый каталог из ~49 регексов-сигналов. Цель P3 —
**непрерывный цикл обогащения**, чтобы каталог рос сам, а оператор только ревьюил:

```
threat-intel ИСТОЧНИКИ → LLM-ДРАФТЕР (regex + варианты-обходы + тесты)
   → ОЧЕРЕДЬ РЕВЬЮ (что / откуда / почему + diff) → approve → SHIP через
   catalog.override.<id> (policy ETag, без редеплоя)
```

Карта скелета (7 агентов) показала: **цикл собран на ~70% и вшит в scheduler.**
Половина `draft → review → ship` работает вживую и корректно. Половина
`sources → draft` **мертва ровно в одном суставе**: единственный драфтер —
`AnthropicSignalDrafter`, создаётся только при наличии `ANTHROPIC_API_KEY`
(main.py:82-99), а discovery-tick null-чекает `app.state.signal_drafter`
(main.py:211-212). На on-prem-боксе без ключа — целевой деплой — `sources→draft`
никогда не запускается. Локального драфтера нет; единственный Ollama-клиент в
проекте — агентский LlamaGuard PI-скан (prompt_injection_engine `_llama_guard_scan`).

## 2. Что УЖЕ работает (не трогаем, переиспользуем)

- **5 source-мониторов** (mitre-attack, atlas, lakera-blog, cve, atomic-red-team):
  stdlib-only, инъектируемый fetch, дедуп по `SourceFetchLog.item_url`, per-monitor
  `since`-курсор, 23h self-throttle. Инстанцированы в lifespan, вшиты в `discovery_service.tick`.
- **discovery_service.tick** — оркестратор: per-monitor since, дедуп, draft-per-item,
  изоляция ошибок, BudgetExhausted early-abort.
- **`draft_signal_from_text`** — budget-gate → `drafter.draft()` → `_parse_response` → `ProposedSignal`.
- **ProposedSignal review-queue + approve/reject** — `proposed_signal_service`:
  `list_pending`/`list_reviewed`, `approve` (validate+compile+UPSERT `catalog.override.<id>`),
  CSRF/session-gated.
- **Signal override SHIP** — `approve` → `SettingsRecord['catalog.override.<id>']` →
  `/api/v1/policy` (catalog.override.*, +ov-ETag) → агент `overrides_loader` →
  `extractor._build_active_catalog` на каждом событии. **Это reuse-цель для всех ship-путей.**
- **Scheduler** — enrichment-tick живёт в том же hourly job, что и 6 детект-тиков; gated `CCGUARD_DISABLE_SCHEDULER` + drafter null-check.

## 3. Решения (зафиксированы с владельцем)

- **LLM:** self-hosted Ollama **on by default** + Anthropic как опциональный фолбэк.
  Дефолтная модель **`qwen2.5:7b-instruct`** (instruct, надёжный JSON), override `CCGUARD_LLM_MODEL`.
- **Объём раунда: P3.1–P3.7** (рабочий цикл + доверенное ревью). **P3.8 (ship PI-паттернов)
  и P3.9 (chain-драфтинг) — отложены** (отдельный раунд; не трогаем контракт корреляции).
- Провалившиеся self-тесты драфта → **флажить-красным-в-очереди**, НЕ авто-реджект
  (оператор ревьюит всё; но draft, не матчащий собственные positives, можно ронять до очереди).
- Per-approve ETag (батч-публикация — позже). Бюджет = call-count cap. Источники —
  публичные хосты + задел под per-monitor base-URL override (air-gap — позже).
- Рациональ оператора = **field-level diff** (P3.4), без отдельной LLM-генерации «почему».
- **Корреляционные движки НЕ трогаем.**

## 4. Фазы (каждая — отдельный PR-кусок, TDD, зелёный регресс)

### P3.1 — Локальный драфтер (разблокировка) ⟵ несущая
`server/services/signal_drafter.py`: добавить `OllamaSignalDrafter(SignalDrafterProtocol)`
с `draft(threat_text)->str`. Портировать проверенный агентский Ollama-клиент
(`prompt_injection_engine._llama_guard_scan`: module-level reused `httpx.Client`,
POST `{endpoint}/api/generate`, `stream:false`, `temperature:0`, обработка
model-missing 404/200-error, fail-safe). Переиспользовать существующие
`_SYSTEM_PROMPT` + few-shot + `_parse_response` (fence-recovery). Чистое добавление,
scheduler/ship не трогаем. Unit-тест с фейковым Ollama-HTTP-слоем (как `test_signal_drafter`).

### P3.2 — Флип дефолта + конфиг
`ServerConfig`: `llm_provider` ('ollama'|'anthropic', default 'ollama'),
`ollama_endpoint` (default `http://localhost:11434`), `ollama_model`
(`qwen2.5:7b-instruct`), env `CCGUARD_LLM_*`. Фабрика `build_signal_drafter(cfg)`:
Ollama по умолчанию; Anthropic только при ключе И выборе. **Вынести создание
`app.state.signal_drafter` ИЗ-под if-anthropic-key (main.py:82-99)** → ставится
безусловно. Ollama-preflight (reuse model-missing detection); если недоступен и нет
ключа → None + баннер оператору (scheduler уже fail-safe). **Это и делает уже-вшитый
hourly tick живым на on-prem.**

### P3.3 — Доступная честная витрина ревью
Пункт сайдбара на `/admin/proposed-signals` в `base.html`; pending-счётчик на overview
делаем `<a>` в очередь. (Без новой логики — просто гейт-человек перестаёт быть скрытым.)

### P3.4 — Diff + коллизии в карточке ревью
Для каждого pending грузить baked `CATALOG`-запись и существующий
`catalog.override.<id>`; field-level before/after (reuse diff-хелпер из routes.py);
рендер «новый сигнал» vs «ЗАМЕНЯЕТ X (pattern A→B)» + бейдж OVERWRITES.
Закрывает silent-replace (UPSERT в proposed_signal_service.py:131-135) и даёт «почему+diff».

### P3.5 — Варианты-обходы + тесты в драфте, бэктест в ревью
`_SYSTEM_PROMPT`: запрашивать primary-сигнал ПЛЮС `alternates[]` (обходы) и
`test_positives[]`/`test_negatives[]`; **перестать pop'ать alternates** (signal_drafter.py:142);
персистить на `ProposedSignal` (новые JSON-колонки). На propose/approve: компилировать
regex eagerly, авто-прогон bundled-тестов (чистый regex, on-prem-safe) И бэктест против
последних N `ToolUseEvent`; прикладывать «matches 4/4 positives, 0/3 negatives; сработал бы
на X из N tool-calls». Рендер вариантов + зелёно/красная таблица тестов + match-count.
**Это делает ревью осмысленным и поднимает потолок.** Failing self-tests → красный флаг.

### P3.6 — Ручной триггер + телеметрия прогонов
`POST /admin/discovery/run-now` (зеркало `enqueue_rescan_all`: one-shot DateTrigger или
сброс `discovery.last_run_at`; inline при выключенном scheduler). Персистить summary
каждого tick (DiscoveryRun-строка или SettingsRecord-blob) + per-monitor last-success/last-error;
на странице очереди «последний sweep: видел N, предложил M, мёртвые фиды: …».

### P3.7 — Retire/rollback + provenance аппрува
`POST /admin/proposed-signals/<id>/retire` — удалить `catalog.override.<id>`
SettingsRecord (следующий /policy ETag убирает его у агентов) + штамп строки.
Audit-строка на approve: override-key → ProposedSignal.id → reviewed_by → source.
Закрывает no-rollback.

### Отложено (НЕ в этом раунде)
- **P3.8** — ship PI-паттернов (approve уже пишет `pi.override.*`, но /policy его не
  отдаёт и агент не читает — нужен pi_overrides loader). Помечать PI-драфты «not yet enforced».
- **P3.9** — chain-scenario драфтинг (`chain.override.*` ship-ключ + второй prompt).

## 5. Обработка ошибок / on-prem
- Ollama недоступен → драфтер preflight-fail → `app.state.signal_drafter=None` →
  scheduler пропускает sweep (уже fail-safe) + баннер. Никогда не валит сервер.
- Источники offline (air-gap) → монитор возвращает `[]` тихо. Per-monitor base-URL
  override — задел на потом.
- Approve компилирует regex (как сейчас) + (P3.5) прогоняет тесты — битый regex не шипается.

## 6. Тестирование
- P3.1: `OllamaSignalDrafter.draft` с фейковым httpx → корректный JSON-парс, model-missing → fail-safe.
- P3.2: `build_signal_drafter` — ollama по умолчанию, anthropic при ключе; `app.state.signal_drafter`
  ставится без ключа; preflight-fail → None.
- P3.3: страница в навигации; pending-счётчик — ссылка.
- P3.4: pending, чей id совпал с baked CATALOG → карточка показывает diff + OVERWRITES.
- P3.5: draft с alternates+tests персистится; backtest-аннотация рендерится; failing positives → красный флаг.
- P3.6: run-now триггерит sweep (или сбрасывает курсор); summary персистится и рендерится.
- P3.7: retire удаляет override-строку; следующий /policy ETag её не содержит.
- Полный регресс зелёный на каждом куске; корреляция не тронута.

## 7. Критерии приёмки (DoD раунда P3.1–7)
1. На on-prem-боксе БЕЗ `ANTHROPIC_API_KEY` (но с поднятым `ollama` + `qwen2.5:7b-instruct`)
   hourly discovery-tick реально опрашивает источники и создаёт `ProposedSignal`.
2. Оператор попадает в очередь через сайдбар; карточка показывает что/откуда/почему + diff/коллизии + варианты + таблицу тестов + backtest-аннотацию.
3. Approve шипает `catalog.override.<id>`; агент подхватывает на следующем /policy; retire убирает.
4. Anthropic — опциональный фолбэк по конфигу, не требуется для работы.
5. Корреляционные движки и существующие ship-механики не изменены; полный регресс зелёный.
