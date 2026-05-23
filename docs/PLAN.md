# PLAN: ccguard MVP — порядок реализации

> Фаза 3 lifecycle. Декомпозиция [SPEC.md](SPEC.md) на этапы. Каждый
> этап имеет вход/выход и проверяемый critery of done. Этапы можно
> выполнять последовательно — параллелизм оставлен на усмотрение, но
> зависимости явные.

## Структура репозитория

```
ccguard/
├── pyproject.toml
├── README.md                   # RU, см. ТЗ §«Артефакты»
├── docs/
│   ├── BRAINSTORM.md
│   ├── SPEC.md
│   ├── PLAN.md
│   └── HOOKS_PROTOCOL.md
├── examples/
│   ├── policy.example.yaml
│   ├── config.example.yaml         # для агента
│   └── server_config.example.yaml
├── src/
│   └── ccguard/
│       ├── __init__.py
│       ├── schemas/               # § 1 — общая библиотека
│       │   ├── __init__.py
│       │   ├── inventory.py
│       │   ├── finding.py
│       │   ├── policy.py
│       │   ├── enforce.py
│       │   └── audit.py
│       ├── agent/                 # CLI
│       │   ├── __init__.py
│       │   ├── cli.py             # entrypoint (typer)
│       │   ├── scan/              # § 3
│       │   │   ├── __init__.py
│       │   │   ├── settings.py
│       │   │   ├── mcp.py
│       │   │   ├── skills.py
│       │   │   ├── hooks.py
│       │   │   └── plugins.py
│       │   ├── check.py           # § 4 — policy engine
│       │   ├── install.py         # § 5
│       │   ├── enforce.py         # § 6 — hot path
│       │   ├── sync.py            # § 7
│       │   ├── report.py          # § 8
│       │   ├── audit.py
│       │   ├── config.py
│       │   ├── masking.py
│       │   └── machine_id.py
│       └── server/                # FastAPI app
│           ├── __init__.py
│           ├── main.py            # FastAPI app factory
│           ├── api/
│           │   ├── __init__.py
│           │   ├── deps.py        # auth dep
│           │   ├── inventory.py
│           │   ├── policy.py
│           │   ├── machines.py
│           │   ├── findings.py
│           │   └── health.py
│           ├── db/
│           │   ├── __init__.py
│           │   ├── models.py      # SQLModel
│           │   └── session.py
│           ├── policy_loader.py
│           └── config.py
├── tests/
│   ├── conftest.py
│   ├── unit/
│   │   ├── test_scan_settings.py
│   │   ├── test_scan_mcp.py
│   │   ├── test_scan_skills.py
│   │   ├── test_scan_hooks.py
│   │   ├── test_check_engine.py
│   │   ├── test_masking.py
│   │   ├── test_machine_id.py
│   │   ├── test_enforce_decision.py
│   │   └── test_enforce_protocol.py
│   ├── integration/
│   │   ├── test_server_inventory.py
│   │   ├── test_server_policy_etag.py
│   │   ├── test_server_machines.py
│   │   ├── test_server_findings.py
│   │   ├── test_server_auth.py
│   │   └── test_agent_install_idempotent.py
│   └── e2e/
│       ├── fixtures/              # «грязные» ~/.claude
│       │   ├── dirty_settings.json
│       │   ├── dirty_mcp/
│       │   └── ...
│       └── test_end_to_end.py
├── docker/
│   ├── Dockerfile.agent
│   ├── Dockerfile.server
│   └── docker-compose.yml
└── .github/
    └── workflows/
        └── ci.yml
```

## Зависимости (требования к окружению)

- Python 3.12
- Runtime: `pydantic>=2.7`, `typer>=0.12`, `fastapi>=0.110`, `uvicorn`,
  `sqlmodel`, `httpx`, `pyyaml`, `platformdirs`
- Dev: `pytest`, `pytest-asyncio`, `pytest-cov`, `ruff`, `mypy`,
  `pyinstaller`

## Этап 0: Bootstrap (foundation)

**Цель:** репозиторий собирается, тесты-пустышки проходят, lint-чистый.

**DoD:**
- `pyproject.toml` с deps и entrypoint'ами `ccguard` и `ccguard-server`.
- `src/ccguard/` пакет, `__init__.py` с `__version__`.
- `tests/conftest.py` с базовыми фикстурами.
- `ruff check .` чисто, `mypy src/ccguard` чисто.
- `pytest` запускается (нулевой test).

## Этап 1: Schemas (общая библиотека)

**Цель:** все pydantic-модели из SPEC §2 реализованы, валидация
тестами.

**Зависимости:** Этап 0.

**Выход:** `ccguard.schemas.*` импортируется и из агента, и из сервера.

**DoD:**
- Все классы из SPEC §2.
- `model_dump_json()` / `model_validate_json()` round-trip тесты.
- Edge cases: `extra="forbid"` отвергает лишние поля; unknown
  `schema_version` ловится отдельным валидатором.
- `policy.example.yaml` валидируется `Policy.model_validate(...)`.

## Этап 2: Server core

**Цель:** FastAPI-приложение поднимается, БД создаётся, health
работает, аутентификация.

**Зависимости:** Этап 1.

**DoD:**
- `uvicorn ccguard.server.main:app` поднимается.
- SQLite-БД создаётся при первом запуске (SQLModel `create_all`).
- WAL mode включён.
- Dep `require_token` — 401 если нет/невалид токен.
- `GET /health` отвечает 200.
- Тест: `test_server_auth.py` — два сценария 200/401.

## Этап 3: Server endpoints

**Цель:** все 6 endpoints работают по SPEC §3.

**Зависимости:** Этап 2.

**DoD:**
- Все эндпоинты возвращают по SPEC.
- ETag для `/policy` через `If-None-Match`.
- Политика читается из `server_config.policy_path`, инвалидация по
  mtime + revision.
- Интеграционные тесты для каждого: create → get → verify.
- `test_server_policy_etag.py` проверяет 200 + 304 кейсы.
- Маска токенов в логах сервера.

## Этап 4: Agent — config & machine_id

**Цель:** `~/.ccguard/config.yaml` управляется, `machine_id`
вычисляется детерминированно.

**Зависимости:** Этап 1.

**DoD:**
- При первом запуске `ccguard` без config → генерируется
  template + install_salt.
- `derive_machine_id()` стабилен между запусками на одной машине.
- Unit test: два разных salt → разные id; один salt → один id.
- Поддержка `--config` для тестов (override path).

## Этап 5: Agent — scan

**Цель:** `ccguard scan` собирает `InventoryReport` из всех источников.

**Зависимости:** Этап 4.

**DoD:**
- Парсеры:
  - `settings.py` — все четыре scope (user/project/project_local/managed).
  - `mcp.py` — извлекает MCP-серверы из `mcpServers` / `.mcp.json`.
  - `skills.py` — обходит `~/.claude/skills/` и плагинные skills,
    считает `dir_hash`.
  - `hooks.py` — собирает все hooks из всех settings.json с
    указанием source.
  - `plugins.py` — marketplaces / `plugins` секции.
- Negative cases: битый JSON → finding `parse_error`, не падаем.
- Отсутствующий файл → `SettingsSource.exists=false`.
- `dangerously_skip_detected` — детект по rc-файлам и
  `~/.bashrc`/aliases.
- Unit tests с фикстурами на каждый парсер.
- Команда `ccguard scan --format json` валидно сериализуется.

## Этап 6: Agent — check (policy engine)

**Цель:** `ccguard check` применяет policy к inventory и выдаёт
findings.

**Зависимости:** Этап 5.

**DoD:**
- Алгоритмы матчинга по SPEC §5 для всех типов правил.
- Регекс-предкомпиляция при load policy.
- Маскирование секретов в `matched_value` (SPEC §9).
- Exit codes: 0 чисто / 1 если есть warn / 2 если есть block.
- `--format json` корректен.
- Unit tests: матрица «правило × inventory-фикстура → ожидаемые
  findings».
- Negative: пустая policy → 0 findings, exit 0.

## Этап 7: Agent — install / uninstall

**Цель:** `ccguard install` / `uninstall` идемпотентны, не затирают
чужие хуки.

**Зависимости:** Этап 4.

**DoD:**
- `install [--scope=user|project|managed]`:
  - Создаёт `~/.ccguard/bin/ccguard-enforce` (shim).
  - Добавляет в hooks PreToolUse для matcher'ов `Bash`, `mcp__.*`,
    `WebFetch`, `WebSearch` (или один `*` + фильтрация в enforce —
    решение: четыре отдельные записи, чтобы Claude Code звал хук
    реже).
  - Если запись уже есть с нашим shim — no-op.
  - Если в hooks есть чужие — оставляем.
- `uninstall` — удаляет только наши записи + shim.
- Backup settings.json перед изменением в `~/.ccguard/backups/`.
- Idempotency test: `install` → `install` → diff settings.json == 0
  после первого.

## Этап 8: Agent — enforce (hot path)

**Цель:** `ccguard enforce` отвечает по hook-протоколу < 100 мс.

**Зависимости:** Этапы 1, 6.

**DoD:**
- Stdin parser устойчив к мусору.
- Decision engine реиспользует policy-engine из этапа 6 (без findings,
  только allow/deny).
- Render hook-output по SPEC §4.
- Audit-запись пишется через `RotatingFileHandler` (10MB × 5).
- fail-open / fail-closed по `block_fail_mode`.
- Tamper-check встроен в `check` (не в `enforce`, чтобы не замедлять):
  `check` сверяет settings.json с ожидаемым шаблоном.
- Unit tests:
  - allow → stdout empty.
  - deny → корректный JSON с `permissionDecision: deny`.
  - битый stdin → exit 0, audit fail_open.
  - перфоманс-тест (smoke): 100 итераций < 10 сек суммарно (т.е. ~100мс
    на запуск; реальный <100 мс будет после бинарной сборки).

## Этап 9: Agent — sync

**Цель:** `ccguard sync` отправляет inventory, получает policy с ETag.

**Зависимости:** Этапы 3, 5, 6.

**DoD:**
- `httpx` клиент с таймаутом 5с.
- `If-None-Match` посылается, `304` корректно обрабатывается (cache
  не трогается).
- `200` → новая policy валидируется и пишется в cache atomically (через
  temp + rename).
- Audit-события с прошлого `sync` собираются и шлются; после успеха —
  помечаются как отправленные (отдельный pointer-файл
  `~/.ccguard/audit.cursor`).
- Server down → exit 1, понятное сообщение, cache не трогается.
- Integration test: agent ↔ server в одной сети.

## Этап 10: Agent — report

**Цель:** `ccguard report` — сводка для человека.

**Зависимости:** Этапы 5, 6.

**DoD:**
- Текстовый вывод: «найдено N MCP-серверов, X хуков, Y findings (block:
  Z, warn: W, info: V)».
- `--json` сохраняет в файл.
- Unit test на форматирование.

## Этап 11: Docker

**Цель:** одна команда поднимает всё.

**Зависимости:** Этапы 3, 9.

**DoD:**
- `Dockerfile.server` — multi-stage, slim image, non-root, healthcheck.
- `Dockerfile.agent` — image с подложенными «грязными» фикстурами
  `~/.claude/` для тестов.
- `docker-compose.yml` — два сервиса, общая network, сервер слушает 8080.
- `docker compose up` поднимается без ручных шагов.
- Volumes: `./data` под SQLite для персистентности (опционально).

## Этап 12: PyInstaller binary для enforce

**Цель:** `ccguard-enforce-bin` — статически собранный бинарник <30 мс
startup.

**Зависимости:** Этап 8.

**DoD:**
- `pyinstaller --onefile` собирает `ccguard-enforce-bin` из
  отдельного entrypoint `ccguard.agent.enforce_main`.
- Размер < 30 МБ.
- Smoke-perf: запуск из shim < 100 мс на стандартной Linux-машине.
- В CI собирается под Linux x64 (macOS/Windows — best effort, отдельный
  matrix-job).
- shim сначала пробует bin, при отсутствии — fallback на
  `python -m ccguard.agent.enforce_main` (для dev-окружения).

## Этап 13: E2E тест

**Цель:** полный сценарий проходит в Docker.

**Зависимости:** Этапы 11, 12.

**DoD:**
- Compose поднимает server + agent.
- Сценарий: `scan` → `check` (findings есть) → `install` →
  симуляция enforce с allow и deny payload (stdin/stdout) →
  `sync` → `GET /machines` показывает машину и findings →
  `uninstall`.
- Все шаги в одном `pytest -m e2e`.
- Очистка между тестами (новый volume).

## Этап 14: README и examples

**Цель:** документация на русском.

**Зависимости:** все.

**DoD:**
- README на русском, секции: проблема, архитектура, быстрый старт
  (agent + server), описание `policy.yaml` с примерами, enforcement
  через хуки, синхронизация, ограничения MVP, развитие.
- `examples/policy.example.yaml` с комментариями по каждому правилу.
- `examples/config.example.yaml` для агента.
- `examples/server_config.example.yaml`.

## Этап 15: Reflexion-критика

**Цель:** ревью качества после имплементации.

**Зависимости:** все.

**DoD:**
- Отдельный документ `docs/REFLEXION.md`:
  - Что работает не так, как планировалось.
  - Найденные slippery slopes (например, fail-open покрывает слишком
    много кейсов).
  - Что упростить, что усложнить.
  - Список follow-up issues для v2.

## Pre-completion checklist (из ТЗ)

Прогнать перед объявлением MVP готовым (SPEC §12 + ТЗ):

- [ ] Все 7 CLI команд: scan, check, install, uninstall, enforce, sync,
      report — работают.
- [ ] Все 6 эндпоинтов сервера — работают и покрыты integration test.
- [ ] E2E проходит в Docker.
- [ ] Парсинг всех источников + негативные кейсы.
- [ ] Секреты нигде не утекают (отдельный тест).
- [ ] `install`/`uninstall` идемпотентны.
- [ ] `enforce` соответствует hook-протоколу.
- [ ] Exit codes у `check` соответствуют severity.
- [ ] Невалидный токен → 401.
- [ ] Агент работает на закэшированной policy при недоступном сервере.
- [ ] `docker compose up` поднимает всё.
- [ ] README на русском, код/идентификаторы на английском.
- [ ] Reflexion проведена.

## Порядок исполнения

Линейный, по этапам 0 → 15. Distinct PR / commit per этап для
ревизионности.
