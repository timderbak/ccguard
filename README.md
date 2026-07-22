# ccguard

**EDR-слой для AI-агентов на машинах разработчиков.** Endpoint-агент +
центральный сервер: инвентаризация, проверка, enforcement **и поведенческий
детект** конфигурации и активности Claude Code в организации. Классический EDR и
AI-WAF не видят, что агент делает на эндпоинте через Bash/Write/Edit — ccguard
закрывает это слепое пятно.

Лицензия: MIT. Статус: **v0.2** (behavioral EDR + compliance), не для
продакшена без понимания [ограничений](#-известные-ограничения-mvp).

---

## Зачем это нужно

Разработчики ставят Claude Code и самостоятельно подключают MCP-серверы,
скиллы, хуки и плагины. У security-команды нет:

- **видимости** — никто не знает, какие MCP-серверы стоят у Alice,
  какие скиллы у Bob, и не запускает ли Charlie скрипты с
  `--dangerously-skip-permissions`;
- **контроля** — нет способа запретить опасные команды или MCP-серверы
  централизованно;
- **аудита** — даже если что-то опасное случилось, нет лога.

`ccguard` закрывает эти три gap'а как governance-слой, **не** заменяя
нативные permissions Claude Code и **не** претендуя на sandbox-изоляцию.

## Архитектура

```
┌──────────────────────────┐                         ┌─────────────────────┐
│  Машина разработчика     │   POST /inventory       │   ccguard-server    │
│                          │ ─────────────────────► │   FastAPI + SQLite  │
│  Claude Code             │                         │                     │
│   ↓ PreToolUse           │   GET /policy           │   - inventory       │
│  ccguard-enforce shim    │ ◄───────────────────── │   - policy (ETag)   │
│   ↓ allow/deny           │   (ETag)                │   - machines        │
│                          │                         │   - findings        │
│  ccguard CLI:            │                         │   - health          │
│    scan / check / install│                         │                     │
│    enforce / sync / report                        │   storage: SQLite   │
└──────────────────────────┘                         └─────────────────────┘
```

**Агент** инвентаризирует конфигурацию из всех источников
(`~/.claude/settings.json`, `.claude/settings.json`, managed-настройки,
`mcpServers`, скиллы, хуки, плагины), проверяет против policy и
enforce'ит запреты через штатный механизм `PreToolUse` хуков Claude
Code. Решения allow/deny идут по
[hook-протоколу Claude Code](docs/HOOKS_PROTOCOL.md).

**Сервер** принимает inventory + findings + audit-события, отдаёт актуальную
policy (с HTTP `ETag` кэшированием), показывает сводку через REST + HTMX-UI и
**гоняет фоновые движки детекта** (sequence/staging/exfil-корреляции, TOFU
rug-pull для MCP/hooks/skills, anomaly/risk, sensor-heartbeat, chain-сценарии),
мапя findings на карту покрытия ATLAS / ATT&CK / OWASP ASI. Подробнее —
[docs/OVERVIEW.md](docs/OVERVIEW.md).

## Быстрый старт

### 1. Поднять сервер

```bash
git clone <repo>
cd ccguard
docker compose -f docker/docker-compose.yml up -d server
curl -s http://localhost:8080/health
# → {"status":"ok","policy_revision":1,"db":"ok"}
```

По умолчанию сервер берёт политику из
[`examples/policy.example.yaml`](examples/policy.example.yaml). Замени
её на свою, обновив `meta.revision`.

API-токен в compose-файле: `demo-token-replace-me`. Замени через
`CCGUARD_TOKENS` env-переменную или серверный
[`config.yaml`](examples/server_config.example.yaml).

### 2. Установить агент

```bash
pip install -e .   # из исходников
```

При первом запуске агент создаст `~/.ccguard/config.yaml` с
сгенерированным `install_salt`. Дополни вручную поля `server.url` и
`server.token`.

### 3. Использовать

```bash
ccguard scan                 # инвентаризация — что у тебя стоит
ccguard sync                 # отправить на сервер, забрать policy
ccguard check                # проверить inventory против policy
                              # exit 0 / 1 (warn) / 2 (block) — для CI
ccguard install              # подключить PreToolUse-хук в settings.json
ccguard report               # сводный отчёт для человека
ccguard uninstall            # убрать хук
```

`ccguard enforce` Claude Code вызывает сам — руками не запускай.

### Запуск на удалённом VPS

Для one-liner-установки `ccguard-server` на чистую Ubuntu/Debian-машину
и подключения агента с dev-машины см. [`docs/REMOTE_INSTALL.md`](docs/REMOTE_INSTALL.md).
Используется отдельный `docker/docker-compose.remote.yml` с bind-mount'ами
для `data/`, `logs/`, `config/` — данные переживают пересборку контейнера.

## Описание политики

См. [`examples/policy.example.yaml`](examples/policy.example.yaml) —
полный пример с комментариями по каждому правилу. Кратко:

```yaml
meta:
  schema_version: 1
  revision: 1                   # увеличивать при каждом изменении
  updated_at: "2026-05-23T12:00:00Z"

block_fail_mode: open           # open|closed: что делать при битой policy

mcp_servers:
  severity: warn
  allowlist_names: [filesystem, memory]
  denylist_names: [shell-mcp]   # runtime-блок mcp__shell-mcp__*
  denylist_url_patterns: ["http://*"]  # static check
  deny_all_unknown: false       # true = whitelist-режим

network:
  severity: block
  allowlist_hosts: [api.anthropic.com, "*.github.com"]
  denylist_hosts: [pastebin.com, "*.ngrok.io"]

commands:
  severity: block
  denylist_patterns: ['\brm\s+-rf\s+/']
  always_deny: ['\bcurl\s+.*\|\s*(sh|bash)\b']  # вшитые, всегда

skills:
  allowlist_names: [claude-code-default]
  trusted_dir_hashes: []        # sha256 hex
  deny_all_unknown: false

hooks:
  allowlist_commands: [/root/.ccguard/bin/ccguard-enforce]
  deny_unknown: true            # любой не-в-allowlist хук = finding
```

Подробности — [SPEC.md §2.4](docs/SPEC.md).

## Enforcement через хуки

`ccguard install` пишет в `~/.claude/settings.json` запись типа:

```json
{
  "hooks": {
    "PreToolUse": [
      {"matcher": "Bash", "hooks": [{"type": "command", "command": "~/.ccguard/bin/ccguard-enforce", "timeout": 5}]},
      {"matcher": "mcp__.*", "hooks": [{"type": "command", "command": "~/.ccguard/bin/ccguard-enforce", "timeout": 5}]},
      {"matcher": "WebFetch", "hooks": [...]},
      {"matcher": "WebSearch", "hooks": [...]}
    ]
  }
}
```

Claude Code на каждый tool-use вызывает наш shim, тот читает stdin
(payload хука), сверяет с локальным кэшем policy и отвечает в stdout
JSON'ом с `permissionDecision: allow|deny`. См.
[HOOKS_PROTOCOL.md](docs/HOOKS_PROTOCOL.md) для точного формата.

Существующие хуки **не затираются**, только дописываются наши. При
`uninstall` удаляются только наши записи.

## Синхронизация с сервером

`ccguard sync`:

1. POST `SyncPayload` (inventory + findings + audit-события с момента
   прошлого sync, только deny + fail_open) → `/api/v1/inventory`.
2. GET `/api/v1/policy` с `If-None-Match: <cached-etag>`. Если `304` —
   используем кэш. Если `200` — атомарно перезаписываем
   `~/.ccguard/policy.yaml`.

Если сервер недоступен — `sync` возвращает exit 1, агент **продолжает
работать на закэшированной policy**. Network на критическом пути
`enforce` отсутствует.

## Поведенческий детект и карта покрытия

Помимо статической policy-проверки, ccguard ведёт **поведенческий детект** на
сервере. PostToolUse-хук размечает каждое событие приватными **сигналами**
(`cred.read.aws`, `egress.network_tool`, `content.read.external`, …; сырой ввод
дропается сразу), а фоновые движки коррелируют их:

- **Sequence/IOA-цепочки** — staging-chain, exfil-sequence, external-trigger в
  пределах окна и одной сессии (session-scoped), с additive-scoring и
  allowlist-подавлением шума сборки.
- **Chain-сценарии (движок-данные)** — сценарий = последовательность **СТАДИЙ**
  kill-chain, а не каналов. Шаг ловит любую технику стадии, поэтому вывод через
  новый канал (видели Telegram — поймается WhatsApp) детектится без изменения
  сценария; новый сценарий = строки в seed, не код.
- **TOFU rug-pull** — MCP-описания, hook-скрипты, skills/agents: любое тихое
  изменение baseline → алерт с diff «было/стало».
- **Sensor self-protection** — агент шлёт heartbeat; сервер ловит, что сенсор
  тихо отключили или убрали hook (детект по ОТСУТСТВИЮ сигнала).
- **Anomaly / risk** — z-score всплески и decay-взвешенный риск-скор по машине.

Findings мапятся на **карту покрытия** трёх фреймворков — ATLAS, ATT&CK, OWASP
ASI — с типом контроля **PREV / DETECT / SCOPE** («блокируем / видим /
ограничиваем»). Детали и механики — [docs/OVERVIEW.md](docs/OVERVIEW.md).

## Что НЕ уходит на сервер

`ccguard` соблюдает data minimization:

- ❌ значения env-переменных MCP-серверов (только имена ключей);
- ❌ содержимое команд в audit (только `tool_input_fingerprint`);
- ❌ содержимое файлов скиллов (только sha256 от папки);
- ❌ значения, мэтчащие regex'ы для секретов (API-токены, JWT, AWS
  keys и т.д. → `***MASKED***`);
- ❌ allow-события из audit (только deny + fail_open).

Проверено отдельным e2e-тестом
(`tests/e2e/test_end_to_end.py::test_secrets_not_leaked_to_server`).

## ⚠️ Известные ограничения MVP

1. **Хук можно удалить.** Разработчик может убрать запись из
   `settings.json` или поставить `disableAllHooks: true`. Контрмера:
   `ccguard check` детектирует это как block-finding; для жёсткого
   контроля используйте `--scope=managed` с системным
   `managed-settings.json` (требует root).
2. **MCP-серверы → внешние хосты.** Хук видит вызов MCP-инструмента,
   но не видит, куда MCP-сервер ходит по сети. Контролируется только
   статически (через `mcp_servers.denylist_url_patterns` и анализ
   `command`/`args` конфига).
3. **Нет mTLS, нет per-machine токенов.** Один shared token на агенты
   — bootstrap-слабость. Mitigation: ротация через
   `CCGUARD_TOKENS` env.
4. **Подпись скиллов не проверяется** (`signature` поле в policy —
   заглушка под Sigstore/cosign).
5. **Один tenant.** Сервер раздаёт одну policy всем агентам.
   Multi-tenancy — за скоупом.
6. **Performance enforce.** В MVP `enforce` запускает Python (~150мс
   cold). PyInstaller-сборка для <100мс — follow-up.
7. **Windows — best effort.** Тестировалось на Linux. macOS обычно
   работает, Windows — без гарантий.

См. [SPEC.md §10](docs/SPEC.md) (threat model) и
[REFLEXION.md](docs/REFLEXION.md) (follow-up issues) для деталей.

## Структура репозитория

```
ccguard/
├── docs/                # OVERVIEW, SPEC, PLAN, HOOKS_PROTOCOL, TEST_AUDIT, …
├── examples/            # policy.example.yaml, config.example.yaml
├── src/ccguard/
│   ├── schemas/         # общие pydantic-модели
│   ├── agent/           # CLI + хуки: scan/check/install/enforce/sync, audit, findings, daemon, signals
│   └── server/          # FastAPI + SQLModel: api/, services/ (движки детекта), web/ (HTMX UI), data/ (seed-файлы)
├── tests/
│   ├── unit/            # юнит-тесты (~925)
│   ├── integration/     # интеграционные (~482)
│   └── e2e/             # docker-compose сценарий (15, gated через CCGUARD_E2E=1)
└── docker/              # Dockerfile.{server,agent,test} + compose
```

## Тестирование

**Demo-стенд одной командой** — поднять сервер, уже наполненный по одной находке
каждого яруса (exfil-цепочка, low-and-slow, MCP/hook rug-pull, prompt-injection,
anomaly, risk, sensor-silence, MOAT-эскалация, fleet-кампания), 4 машины,
опубликованная policy и очередь предложенных сигналов. Ровно то, что нужно, чтобы
«увидеть продукт» или показать коллеге — без ручного сева и ожидания планировщика:

```bash
scripts/demo-env.sh          # → http://127.0.0.1:8080 (admin / admin), данные уже внутри
```

Автотесты локально через `uv`:

```bash
uv run pytest                # полный прогон (e2e — skipped, окруженческие)
uv run pytest -m "not integration"   # быстрая полоса: только юниты
CCGUARD_E2E=1 uv run pytest  # + e2e против живого docker-стека
```

Или в Docker:

```bash
# Юнит + интеграционные
docker build -f docker/Dockerfile.test -t ccguard-test .
docker run --rm ccguard-test

# E2E (полный цикл агент ↔ сервер)
docker compose -f docker/docker-compose.yml up -d server
docker compose -f docker/docker-compose.yml --profile e2e run --rm agent
```

## Roadmap

Текущий MVP — фундамент. Что планируется (см.
[REFLEXION.md](docs/REFLEXION.md) для деталей):

- **v0.2:** PyInstaller-сборка enforce-бинарника (<100мс).
- **v0.3:** Sigstore/cosign подписи скиллов и плагинов.
- **v0.4:** Multi-tenancy: разные policy по командам/проектам.
- **v0.5:** Cursor / Codex (та же модель governance, другие источники
  конфига).

## Лицензия

MIT — см. [LICENSE](LICENSE). Pull request'ы приветствуются.
