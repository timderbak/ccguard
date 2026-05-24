# ccguard Web UI — Design Spec

**Date:** 2026-05-24
**Status:** Approved, ready for implementation plan
**Author:** brainstorming session with project owner

## Цель

Дать ccguard веб-интерфейс, который закрывает три сценария:

1. **Смотреть статистику** по машинам и findings — кто на чём, что нарушает policy, кто отстал по версиям.
2. **Создавать правила** (policy) через UI без ручной правки YAML.
3. **Распространять policy** — через явный двухстадийный flow Draft → Publish с историей версий и возможностью rollback.

MVP, single-tenant, single-admin. Архитектура должна позволять позднее расширение (multi-user, channels, SSO), но сами эти фичи **в scope MVP не входят**.

## Архитектурные решения

| Решение | Выбор | Обоснование |
|---|---|---|
| Каркас | Сайдбар слева + main | Классика EDR, масштабируется при добавлении разделов |
| Overview-фокус | Fleet-first | Главный сценарий — управление флотом эндпоинтов |
| Policy editor | Form-only, без YAML-редактирования | Безопаснее для не-инженеров; невозможно ввести невалидный YAML; убирает Monaco из зависимостей |
| Распространение | Draft → Publish, с историей | Защищает от случайных правок; даёт rollback |
| Стек фронта | HTMX + Jinja2 + Tailwind | Server-rendered, без npm, один Docker, минимум moving parts |
| Auth для UI | Basic login → cookie session | Один admin-юзер; токены агентов не трогаем |
| Realtime | Polling 30 сек через HTMX | Достаточно для compliance; SSE/WebSocket — лишняя сложность |

## Архитектура

```
┌─────────────────────────────────────────────────────────────────┐
│                     ccguard-server (FastAPI)                    │
│                                                                 │
│  /api/v1/*    ─── existing JSON API (header: X-CCGuard-Token)   │
│  /  /machines /policy /findings /login                          │
│      ─── new web routes (cookie auth, Jinja2 + HTMX partials)   │
│                                                                 │
│              ↓ shared service layer ↓                           │
│   inventory_service · policy_service · machine_service          │
│   finding_service · auth_service                                │
│              ↓                                                  │
│           SQLite (existing tables + PolicyVersion + WebSession) │
└─────────────────────────────────────────────────────────────────┘
```

Один процесс, один Docker-образ. Бэкенд остаётся FastAPI; добавляются веб-роуты и сервисный слой. Никакого отдельного фронтенд-приложения, npm-сборок, прокси.

## Изменения в схеме данных

Три новых SQL-таблицы (SQLModel):

```python
class PolicyVersion(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    revision: int = Field(index=True)
    status: str = Field(index=True)  # "draft" | "published" | "archived"
    yaml_text: str
    comment: str | None = None
    created_at: datetime
    published_at: datetime | None = None
    created_by: str  # admin username


class WebSession(SQLModel, table=True):
    id: str = Field(primary_key=True)  # cookie value (random 32 bytes hex)
    user_id: str = Field(index=True)
    created_at: datetime
    expires_at: datetime = Field(index=True)


class AgentToken(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    label: str
    token_hash: str = Field(index=True)  # sha256(token)
    created_at: datetime
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None
```

**Bootstrap:** при старте сервера, если в `PolicyVersion` нет записей со `status=published`, читается YAML из файлового `policy_path` и записывается как published rev 1. После этого файл становится опциональным seed'ом.

**Чтение policy:** `PolicyLoader` переписывается на чтение из БД (самая свежая `status=published`). ETag = `"rev-{revision}"`. Файл больше не используется в runtime — только bootstrap.

## Auth model

- **Веб (UI):** HTTP basic-форма (логин/пароль) → cookie `ccg_session` (HttpOnly, SameSite=Lax, Secure если HTTPS). Один admin-юзер. Креды из env: `CCGUARD_ADMIN_USER`, `CCGUARD_ADMIN_PASSWORD_HASH` (bcrypt). Сессии хранятся в `WebSession`, истечение — 24 часа неактивности.
- **API (агенты):** существующий `X-CCGuard-Token`, не трогаем.
- **Кросс-доступ запрещён:** web-routes отклоняют `X-CCGuard-Token`, API-routes отклоняют cookie. Чтобы не случилось эскалации в обе стороны.
- **CSRF:** все POST/DELETE web-роуты требуют CSRF-токен в форме (через `itsdangerous`).

## Страницы UI

Все маршруты под `Depends(require_session)`.

### 1. `GET /` → Overview (fleet-first)
- Шапка: total / synced ≤24h / stale >7d.
- Таблица машин (host, OS, last sync, policy rev, W/B counts, status).
- CTA-кнопки в футере: `Recent findings →`, `Push policy →`, `Add machine →`.
- HTMX polling раз в 30 сек на `/_partials/overview/fleet-table`.

### 2. `GET /machines/{id}` → Machine detail
- Шапка: hostname, label, agent_version, OS, machine_id (short).
- Табы:
  - **Inventory** — текущий snapshot, раскрывающиеся секции (mcp_servers / skills / hooks / agents / commands / env_keys / permissions).
  - **Findings** — фильтры severity / rule_id, до 200 строк, пагинация.
  - **History** — последние 20 sync'ов, клик → snapshot этой ревизии.
- `[ Revoke machine ]` → DELETE, агент при следующем sync получит 404.

### 3. `GET /findings` → Findings feed
- Лента по всему флоту. Фильтры: severity, rule_id, machine_id, date-range.
- Сортировка `discovered_at desc`.
- Каждая строка → ссылка на `/machines/{id}#finding-{n}`.
- Lazy-load по скроллу через `/_partials/findings/feed`.

### 4. `GET /policy` → Policy editor (form-only)
- Заголовок: `Current rev N (published 2h ago) → Draft rev N+1 (unsaved)`. Кнопки `[Validate] [Save draft] [Publish]`.
- Аккордеоны по секциям: MCP / Network / Commands / Skills / Hooks / Agents / Env. У каждой свои контролы (allowlist/denylist + severity dropdown + чекбоксы).
- Под аккордеонами — diff vs published (`+`/`-`/`~`).
- Submit через HTMX: `POST /policy/draft` → возвращает обновлённый diff partial.

### 5. `GET /policy/history` → Version history
- Список `PolicyVersion`. Колонки: rev, status, published_at, comment, кто опубликовал.
- На каждой строке: `[view]` (modal с YAML), `[diff vs current]`, `[rollback to this]` (создаёт draft с содержимым).

### 6. `GET /settings` → Settings
- **Agent tokens:** CRUD над токенами для агентов (имя + ротация). Хранятся как sha256-хеш в БД (`AgentToken.token_hash`). При старте, если `AgentToken` пустая, токены из env `CCGUARD_TOKENS` мигрируются в таблицу (один раз, с label=`"env-bootstrap-{n}"`). После миграции env читается только как fallback, если БД-таблица пустая — это покрывает кейс ручной очистки таблицы.
- **Admin password change:** форма смены пароля.
- **About:** версия сервера, БД-путь, uptime.

## Routes API (полный список новых)

### Auth
| Метод | Путь | Назначение |
|---|---|---|
| `GET` | `/login` | Форма логина |
| `POST` | `/login` | basic creds → cookie, redirect `/` |
| `POST` | `/logout` | удалить session, redirect `/login` |

### Pages (full HTML)
| Метод | Путь | Шаблон |
|---|---|---|
| `GET` | `/` | `overview.html` |
| `GET` | `/machines` | `machines_list.html` |
| `GET` | `/machines/{machine_id}` | `machine_detail.html` |
| `GET` | `/findings` | `findings_feed.html` |
| `GET` | `/policy` | `policy_editor.html` |
| `GET` | `/policy/history` | `policy_history.html` |
| `GET` | `/settings` | `settings.html` |

### HTMX partials и действия
| Метод | Путь | Что делает |
|---|---|---|
| `GET` | `/_partials/overview/fleet-table` | пере-рендер таблицы (polling) |
| `GET` | `/_partials/findings/feed` | пагинация findings, lazy-load |
| `POST` | `/policy/draft` | upsert draft → возвращает `_diff_panel.html` |
| `POST` | `/policy/publish` | promote draft → published, bump revision |
| `POST` | `/policy/rollback/{version_id}` | копия version → новый draft |
| `POST` | `/policy/validate` | dry-run валидация → JSON + partial |
| `DELETE` | `/machines/{id}` | revoke machine |
| `POST` | `/settings/tokens` | создать новый агент-токен |
| `DELETE` | `/settings/tokens/{id}` | отозвать токен |
| `POST` | `/settings/password` | сменить admin password |

## Service layer (новые модули)

```
src/ccguard/server/services/
├── __init__.py
├── machine_service.py     list_with_compliance(), get_inventory_history(),
│                           compliance_status(machine, current_rev)
├── policy_service.py      get_current(), get_draft(), save_draft(),
│                           publish(), rollback(), validate(), diff()
├── finding_service.py     query(severity, rule_id, machine_id, page)
├── token_service.py       list_tokens(), create(), revoke(),
│                           hash_token(), verify()
└── auth_service.py        verify_password(), create_session(),
                            require_session() FastAPI dependency
```

Существующие route-handler'ы рефакторятся: переносят бизнес-логику в сервисы. Это шаг, обязательный по гигиене (web и API должны звать одну функцию, а не дублировать SQL).

## Compliance status (для Overview)

Считается ad-hoc, не хранится. Правила в порядке приоритета:

1. `blocking` — у машины есть active findings с severity=`block`.
2. `stale` — `last_seen` старше 7 дней.
3. `policy-old` — `last_seen` ≤ 24h, но `policy_revision < current_published_revision`.
4. `compliant` — `last_seen` ≤ 24h, `policy_revision == current_published_revision`, нет block-findings.

## File layout (новое)

```
src/ccguard/server/
├── api/                  (existing, unchanged)
├── db/
│   └── models.py         (+ PolicyVersion, WebSession, AgentToken)
├── services/             (new, см. выше)
├── web/                  (new)
│   ├── __init__.py
│   ├── routes.py         FastAPI APIRouter(prefix="")
│   ├── auth.py           login/logout/session deps
│   ├── csrf.py           generate_token(), verify_token()
│   ├── templates/
│   │   ├── base.html
│   │   ├── login.html
│   │   ├── overview.html
│   │   ├── machines_list.html
│   │   ├── machine_detail.html
│   │   ├── findings_feed.html
│   │   ├── policy_editor.html
│   │   ├── policy_history.html
│   │   ├── settings.html
│   │   └── components/    (htmx partials, includes)
│   └── static/
│       ├── htmx.min.js
│       ├── app.js         (~50 lines, копы для confirm-dialog'ов)
│       └── tailwind.css   (prebuilt, ~30KB)
└── main.py                app.include_router(web_router)
```

## Зависимости

Новое в `pyproject.toml`:

```toml
"jinja2>=3.1",
"python-multipart>=0.0.9",   # form parsing
"passlib[bcrypt]>=1.7",
"itsdangerous>=2.2",          # signed cookies / CSRF
```

Tailwind поставляется как **prebuilt CSS** (генерируется один раз во время `make build-css` и коммитится в репо). Это держит билд однопроцессным без node.

## Стратегия тестирования

### Unit (быстрые, без HTTP)
- `tests/unit/test_policy_service.py` — save_draft/publish/rollback/diff.
- `tests/unit/test_machine_service.py` — `compliance_status()` для 4 состояний.
- `tests/unit/test_auth_service.py` — verify_password, create_session, истечение.
- `tests/unit/test_web_security.py` — cookie HttpOnly/SameSite, CSRF-валидация на POST.

### Integration (FastAPI TestClient, in-memory SQLite)
- `tests/integration/test_web_auth.py` — редирект на `/login`; cookie не работает на API; токен не работает на web.
- `tests/integration/test_web_policy_flow.py` — bootstrap, draft, publish, rollback, агент видит свежий ETag.
- `tests/integration/test_web_machines.py` — compliance status, revoke machine.

### E2E
- `tests/e2e/test_web_smoke.py` — один docker-compose сценарий: логин по httpx, открыть `/`, получить fleet-table partial. Без Playwright.

### Не тестируем
- Визуальная регрессия Tailwind.
- Браузерный JS (~50 строк, проверяется HTMX-трипом).
- Concurrent edits в Policy Editor (не в scope MVP).

## Out of scope (явно, чтобы не разрасталось)

- Multi-user / RBAC.
- Channels (stable / canary / beta), per-machine targeting.
- Push-уведомления / webhook'и / Slack-интеграция.
- Графики / charts / timeseries.
- SSO (OIDC, SAML).
- Конкурентное редактирование policy.
- i18n (только русский/английский в шаблонах, без runtime-переключения).

## Manual QA checklist

1. Поднять compose, открыть `http://localhost:8080/`, залогиниться.
2. Создать draft, изменить mcp denylist, validate, save → агент видит старый revision.
3. Publish → `ccguard sync` → агент получает новый revision.
4. Поломать YAML через SQL → старт сервера падает с понятным сообщением (не запускается с пустой policy).
5. Войти кривым паролем 5 раз — ожидание; rate-limit опционально, не блокирует MVP.

## Открытые вопросы (для implementation plan)

1. Где брать иконки сайдбара — Heroicons CDN или вшить SVG?
2. Дата/время — UTC в БД, локальное в UI (через `<time>` + JS), или просто ISO-строки?
3. Какие именно поля показывать в Machine inventory accordion (полный snapshot большой — стоит ли подгружать lazy по табу)?

Эти вопросы не блокируют дизайн; разрешим во время writing-plans.
