# Hooks TOFU baseline + drift detection

**Date:** 2026-06-01
**Status:** Approved (brainstorming → spec)
**Predecessor work:** MCP rug pull detection (`src/ccguard/server/services/mcp_baseline_service.py`), hooks ownership UX fix (`fix/inventory-findings-ux`).

## Mission

Сделать так, чтобы `~/.claude/settings.json` хуки на машине пользователя:

1. перестали быть «общим warn-шумом» (сейчас на нормальной dev-машине 40+ warn'ов про сторонние плагины),
2. поднимали **block-уровень** алерт, когда у уже известного хука **изменилось содержимое скрипта** под капотом без обновления `settings.json` (классический supply chain rug pull),
3. поднимали warn, когда **команда хука изменилась** (видимое изменение конфигурации) или появился **новый** хук,
4. имели UX-симметрию с уже существующей фичей MCP rug pull (та же модель «accept baseline», те же шаблоны finding-карточек).

## Non-goals

- Каталог «known-good» по именам/идентификаторам плагинов. Сознательный отказ: имя `claude-mem` подделывается за 0 секунд, доверять можно только конкретным байтам, попавшим в baseline на этой машине.
- Глубокий анализ зависимостей хука (`import`-цепочка Python-скриптов, `node_modules`). Out of scope для v1: хешируем только верхний файл-шим. Известное ограничение.
- Fleet-wide auto-discovery («хук видели на N машинах — значит common»). Требует multi-tenant и крупного флита, бессмысленно в персональном single-tenant сценарии.
- Code-signing от автора плагина. Требует ecosystem-buy-in. Если появится — добавим в v2 как ortho-источник доверия.
- Снятие алертов с MCP: эта фича не трогает MCP rug pull pipeline, только хуки.

## Identity хука (fingerprint)

Идентичность хука — это **четырёхполевой композитный SHA-256**:

```
hook_fingerprint = sha256(
    event_name      ||  # "PreToolUse" | "PostToolUse" | etc.
    matcher         ||  # "Bash" | "Write|Edit" | "*"
    command_string  ||  # точная command-line как в settings.json
    file_content    ||  # sha256 содержимого файла, если command указывает на существующий файл
)
```

### Почему четыре компонента

- **`event_name` + `matcher`** — определяют «слот» в `settings.json`. Хук на `PreToolUse Bash` и `PostToolUse Write` — разные хуки, даже если content одинаков; без этого атакующий может «переехать» payload с одного события на другое и проскочить.
- **`command_string`** — ловит «тот же скрипт, новые флаги». Пример: было `python script.py --safe`, стало `python script.py --no-sandbox`.
- **`file_content`** — главный защитный слой. Ловит **supply chain rug pull**: команда та же, но `script.py` под капотом обновился молча.

### Что НЕ входит в fingerprint (осознанно)

- `mtime`, `inode`, абсолютный путь к интерпретатору (`/usr/bin/python` vs `/usr/local/bin/python`) — шум без сигнала.
- Вложенные импорты / dependencies — only top-level shim file. Известное ограничение v1.
- Inline-команды без файла (`bash -c "echo hi"`) — для них `file_content = ""`, fingerprint работает только на event+matcher+command. Меньше защиты, помечаем в UI значком «inline».

### Граничные случаи чтения файла

- Файл существует, нет прав читать → `file_content_hash = None`, `file_unreadable_reason = "permission_denied"`. В UI бейдж «не удалось прочитать». Алерт не поднимается (это шум).
- Файл существует, размер > 256 KB → `file_content_hash = None`, `file_unreadable_reason = "too_large"`. Хешируем верх для быстрого детекта drift, но 256 KB — потолок.
- Файла нет → `file_content_hash = None`, `file_unreadable_reason = "missing"`. Drift detection деградирует до command-string.

## Lifecycle baseline-записи

```
       первый sync               accept в UI
   ─────────────────────►  pending  ──────────►  active
                            │                      │
                            │ reject               │ fingerprint меняется
                            ▼                      ▼
                          removed             drift detected
                                                   │
                                                   ▼
                                          accepted_drift
                                (либо «новый baseline» сохранён)
```

### Случаи детекта при каждом sync (порядок приоритета)

| Случай | rule_id | Severity | UI |
|---|---|---|---|
| Slot существует, fingerprint совпадает | — | silent | обновляем `last_seen_at` |
| Новый хук (slot не существовал) | `hook.new` | **warn** | карточка «Появился новый хук» + accept/reject |
| File content drift (тот же slot, file_content_hash изменился) | `hook.rug_pull.content` | **block** | красная карточка «Скрипт хука изменился без обновления» + diff |
| Command drift (тот же slot, command_string изменился) | `hook.rug_pull.command` | **warn** | карточка «Команда хука изменилась» |
| Hook исчез (slot был, теперь нет) | `hook.removed` | info, silent v1 | помечаем `status=missing`, finding не emit |
| File перестал читаться (был content_hash, стал None) | `hook.unreadable` | warn | «Не могу прочитать файл шима — проверь права» |

### Почему content drift = block, а command drift = warn

- **Content drift** — *скрытый* supply chain: `settings.json` не менялся, но payload — да. Главный вектор атаки на endpoint AI-агенты (npm/pypi-style rug pull). Block оправдан.
- **Command drift** — *видимое* изменение конфигурации, либо юзер сам менял `settings.json`, либо был запущен инсталлер. Менее изящная атака — warn достаточно, без эскалации.

### Bootstrap (первый sync на машине с уже стоящими 45 хуками)

Все обнаруженные хуки идут в baseline сразу со статусом `pending`. Никаких warn `hook.new` для них не поднимается — иначе пользователь утопает в шуме при первом подключении машины.

**Важное уточнение к таблице выше:** rule_id `hook.new` emit'ится **только если на машине уже есть хотя бы одна baseline-запись со статусом `active`**. Иначе считаем это первым sync'ом / bootstrap'ом, всё уходит в `pending` молча. Это маркер «admin уже подтверждал baseline раньше, значит появление нового хука сейчас — потенциальная аномалия».

В UI на `/machines/<id>` появляется bootstrap-баннер:

> «Найдено **N** хуков на этой машине. Подтверди baseline или удали хуки.»

Кнопки: `Подтвердить все (N)` → bulk-перевод в `active`. `Просмотреть по одному` → раскрыть список. После accept-all drift-детект включается **с этого момента**.

### Re-accept после обновления (`claude-mem v2`)

Юзер видит block-карточку content drift → жмёт `Принять новый baseline` → `fingerprint` обновляется на новый, `status = accepted_drift`, `accepted_at = now`, `accepted_by = admin_user`. Finding закрывается. В журнале остаётся аудит-след «drift was accepted at T by U», чтобы при будущей форензике можно было увидеть, что admin сам поднял версию.

## Архитектура

```
agent (scan/hooks.py)              server (api/inventory.py)
─────────────────────              ─────────────────────────
HookEntry {                         POST /api/v1/inventory
  event_name                        ↓
  matcher                           hook_baseline_service.update_and_detect()
  command_string                    ├── вычисляет composite fingerprint
  file_path                         ├── INSERT pending для новых slot'ов
  file_content_hash      ──────►    ├── matches fingerprint?     → bump last_seen
  file_unreadable_reason            │     no, content_hash diff? → emit hook.rug_pull.content (block)
}                                   │     no, command diff?      → emit hook.rug_pull.command (warn)
                                    │     missing in this sync?  → status=missing
                                    └── создаёт FindingRecord для accept-flow

web UI (machine_detail.html)
────────────────────────────
- bootstrap-баннер если есть pending записи
- карточки drift findings рядом с MCP rug pull
- статус-бейдж на каждом хуке в существующем блоке
- POST /machines/{id}/hook-baseline/{id}/accept     → status=active (или accepted_drift)
- POST /machines/{id}/hook-baseline/accept-all-pending → bulk
- POST /machines/{id}/hook-baseline/{id}/reject     → status=removed
```

## Компоненты и интерфейсы

### Schema extension — `src/ccguard/schemas/inventory.py`

Расширить `HookEntry` (поля Optional для backward compat с v0.1 агентом):

```python
class HookEntry(BaseModel):
    # existing fields preserved
    event_name: str
    matcher: str | None = None
    command: str | None = None
    source: str | None = None
    is_ccguard_owned: bool = False
    # new in this design
    file_path: str | None = None              # путь, на который указывает command, если есть
    file_content_hash: str | None = None      # sha256[:32] первых 256 KB
    file_unreadable_reason: str | None = None # "missing" | "permission_denied" | "too_large"
```

### Agent — `src/ccguard/agent/scan/hooks.py`

Дополнить парсер: при наличии `command` пытаемся:

1. shlex-парсить command, искать первый аргумент, похожий на путь к скрипту (есть `/`, файл существует).
2. Если найден — открываем, читаем до 256 KB, sha256.hexdigest()[:32].
3. Любая ошибка → `file_content_hash = None` + `file_unreadable_reason` соответственно.

Composite `hook_fingerprint` **не** вычисляется на агенте — это серверная ответственность. Агент шлёт сырые поля, чтобы новые сервера с обновлённой логикой могли пересчитать у старых клиентов.

### Server model — `src/ccguard/server/db/models.py`

```python
class HookBaseline(SQLModel, table=True):
    __tablename__ = "hook_baselines"
    id: int | None = Field(default=None, primary_key=True)
    machine_id: int = Field(index=True, foreign_key="machines.id")

    event_name: str = Field(index=True)
    matcher: str = ""   # "" если в settings.json не указан
    command_string: str
    file_path: str | None = None
    file_content_hash: str | None = None
    fingerprint: str = Field(index=True)

    status: str = Field(default="pending")   # pending | active | accepted_drift | missing | removed
    first_seen_at: datetime
    last_seen_at: datetime
    accepted_at: datetime | None = None
    accepted_by: str | None = None
```

DDL: composite UNIQUE `(machine_id, event_name, matcher, command_string)` (это «слот» — атакующему всё равно придётся ставить новый slot, чтобы обойти; через UNIQUE сразу гарантируем что content drift = тот же row).

Миграция — через тот же шаблон `ALTER TABLE IF EXISTS` / `CREATE TABLE IF NOT EXISTS` в `db/session.py`, как делалось для `MCPServerBaseline` и `ScanResult.explanation`.

### Service — `src/ccguard/server/services/hook_baseline_service.py`

```python
def update_and_detect(
    session: Session,
    machine_id: int,
    current_hooks: list[HookEntry],
) -> list[FindingRecord]:
    """
    Сравнивает текущий sync с baseline. Возвращает findings для commit на caller-стороне.
    Не коммитит сама — у inventory POST handler своя транзакция.
    """

def compute_fingerprint(event_name: str, matcher: str, command: str,
                        file_content_hash: str | None) -> str:
    """sha256 из четырёх полей. None → пустая строка."""

def accept_baseline(session: Session, machine_id: int, baseline_id: int,
                    accepting_user: str) -> HookBaseline:
    """pending/accepted_drift → active, fingerprint фиксируется."""

def accept_all_pending(session: Session, machine_id: int,
                       accepting_user: str) -> int:
    """Bulk для bootstrap-баннера. Возвращает количество переведённых."""

def reject_and_mark(session: Session, machine_id: int,
                    baseline_id: int) -> None:
    """status=removed; используется когда юзер сказал 'не доверять' в UI.
    Сам хук из settings.json не удаляем — это юзеру делать руками."""
```

Вызов `update_and_detect` встраивается в существующий handler `POST /api/v1/inventory` рядом с `mcp_baseline_service.update_and_detect`.

### Web routes — `src/ccguard/server/web/routes.py`

```
POST /machines/{machine_id}/hook-baseline/{baseline_id}/accept
POST /machines/{machine_id}/hook-baseline/accept-all-pending
POST /machines/{machine_id}/hook-baseline/{baseline_id}/reject
```

Все три — `require_session` + CSRF, redirect на `/machines/{machine_id}`.

### UI — `src/ccguard/server/web/templates/machine_detail.html`

Три точки изменений:

1. **Bootstrap-баннер** — над текущим блоком «Хуки». Виден если `count(pending) > 0` для машины. Жёлтый, две кнопки.
2. **Drift-карточки** — между rug-pull MCP карточками и блоком «Хуки». Шаблон совпадает с `_mcp_rug_pull_card.html` (короткий title, severity badge, описание, «было/стало» с hash-сокращением, кнопки accept/reject).
3. **Статус-бейдж на каждом хуке** в существующем блоке «Хуки»: `pending review` (амбар), `active` (зелёный), `accepted drift` (синий), `missing` (серый). Это маленькая надпись справа от текущей "ccguard / unknown" метки — они ortho.

Цвета и стиль — security-console тема, как в остальном UI. Никаких эмодзи.

## Тесты (TDD)

### Unit — `tests/unit/test_hook_fingerprint.py`

- `compute_fingerprint`: четыре идентичных входа → один и тот же hash; смена любого компонента → другой hash.
- `None` для file_content_hash → пустая строка в composition.
- Inline-команда (`file_path=None`) → fingerprint всё равно стабильный.

### Unit — `tests/unit/test_hook_baseline_service.py`

Шесть случаев из таблицы lifecycle:
1. no_change: same fingerprint → bump last_seen, no finding
2. new_hook: slot not in baseline → `hook.new` warn, status=pending
3. content_drift: same slot, different file_content_hash → `hook.rug_pull.content` block, status=drift_detected
4. command_drift: same slot, different command_string → `hook.rug_pull.command` warn
5. removed: slot was in last sync, not in this → status=missing, no finding (v1)
6. unreadable: file_content_hash transition Some→None → `hook.unreadable` warn

Плюс bootstrap: первый sync, 3 хука → 3 pending, **0 finding'ов** `hook.new` (т.к. до accept всё в pending, не triggering warn'ы).

### Unit — `tests/unit/test_hook_baseline_accept_flow.py`

- accept_baseline: pending → active
- accept_baseline: accepted_drift → active (re-accept после обновления)
- accept_all_pending: count верный, переходят все
- reject_and_mark: status=removed, не возвращается в update_and_detect

### Integration — `tests/integration/test_machine_detail_hook_baseline_ui.py`

- Bootstrap-сценарий: создать машину с 3 pending → GET /machines/{id} → виден баннер с «3 хука» и кнопка accept-all.
- POST accept-all-pending → redirect → 0 pending в БД.
- Симуляция content drift: записать baseline с hash=X, послать новый sync с hash=Y → видна красная карточка с rule_id и кнопкой accept.
- Accept drift → новый fingerprint сохранён, status=active, finding закрыт.

### Integration — `tests/integration/test_inventory_emits_hook_findings.py`

POST /api/v1/inventory с HookEntry'ми покрывающими все шесть случаев → проверить какие FindingRecord появились в БД и какие rule_id.

## Edge cases и known limitations

- **Inline `bash -c`** без файла — `file_content_hash=None`, защита деградирует до command-string. UI помечает значком «inline» и предупреждением «защита ослаблена, рассмотри вынос в отдельный скрипт».
- **256 KB cap** — файл > 256 KB → `too_large`. Реальные shim'ы 0.5–10 KB, лимит щедрый, но честно сообщаем когда не справились.
- **Multi-line / `&&` chain в command** — хешируется как одна строка, без парсинга. Перестановка `cmd1 && cmd2` → `cmd2 && cmd1` будет drift. Это OK: семантически это разные хуки.
- **ccguard-owned hooks** — у них `is_ccguard_owned=True` (детект из UX-фикса). Они **тоже** идут в baseline (зачем? — чтобы поймать ситуацию когда атакующий подменил наш собственный `ccguard-enforce` шим). Bootstrap для них автоматически даёт `status=active` без UI-promote — мы знаем что только что их установили через `ccguard install`.
- **Известное trade-off для ccguard-owned**: при штатном `pip install -U ccguard` shim-файлы могут перегенериться, и `file_content_hash` изменится → поднимется `hook.rug_pull.content` (block) на наши же собственные хуки. Решения два, оба не входят в v1: (а) `ccguard upgrade` команда, которая отмечает «следующий drift на ccguard-owned ожидаем» с TTL 1 час; (б) хешировать не сам shim, а реальный entrypoint (`ccguard.agent.enforce:run_enforce`), который стабилен между релизами. До v2 — юзер должен принять drift руками через UI, как и любой другой apgrade.
- **Hook на network filesystem / симлинк** — file_content_hash считается по тому что фактически прочитали через `open()`. Симлинк подменили → file_content_hash изменится → drift catches. Корректно.

## Версионирование и совместимость

- Старые агенты (v0.1) шлют `HookEntry` без новых полей → server treats `file_content_hash=None`, drift-детект работает в degraded режиме (только по command_string).
- Старые сервера получают новых агентов с новыми полями → backward compat через Optional fields.

## Что меняем в `MEMORY.md` после имплементации

Дополнить `project_positioning_2026_05.md`: hook TOFU baseline — вторая «signature» фича (после MCP rug pull), оба используют одинаковый паттерн доверия. В будущем питче можно говорить «два рельса rug-pull: MCP-метаданные и hook-script content».

## Открытые вопросы для v2 (не блокируют v1)

- Глубокий dependency scan (Python imports / Node modules) — не входит в v1, но фундамент уже есть в виде `file_content_hash`. Расширение — иерархия хешей.
- Fleet-wide auto-discovery — если ccguard вырастет до multi-tenant, можно докинуть «N машин видели тот же hash → low-severity отметка».
- CF API integration для fail2ban (см. memory `project_vps_security_state`) — отдельная задача безопасности инфраструктуры, не связана с hooks TOFU напрямую.
