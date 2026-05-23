# SPEC: ccguard MVP

> Фаза 2 lifecycle. Источник истины по схемам данных, контрактам API и
> формату hook-ответов. Решения из [BRAINSTORM.md](BRAINSTORM.md)
> применяются без обсуждения. Ссылки на hook-протокол —
> [HOOKS_PROTOCOL.md](HOOKS_PROTOCOL.md).

## 1. Архитектура

```
┌──────────────────────────┐                         ┌─────────────────────┐
│  Машина разработчика     │                         │   ccguard-server    │
│                          │   POST /inventory       │   (FastAPI+SQLite)  │
│  ┌────────────────────┐  │ ─────────────────────► │                     │
│  │  Claude Code       │  │                         │  - /inventory       │
│  │   ↓ PreToolUse     │  │   GET /policy           │  - /policy          │
│  │  ~/.claude/        │  │ ◄───────────────────── │  - /machines        │
│  │    settings.json   │  │   (ETag)                │  - /machines/{id}   │
│  └──────────┬─────────┘  │                         │  - /findings        │
│             │ stdin/JSON │                         │  - /health          │
│             ▼            │                         │                     │
│  ┌────────────────────┐  │                         │  storage:           │
│  │  ccguard-enforce   │  │                         │  - SQLite (WAL)     │
│  │  (shim → binary)   │  │                         │  - server_policy.   │
│  │   ↓ JSON allow/deny│  │                         │      yaml (FS)      │
│  └────────────────────┘  │                         └─────────────────────┘
│                          │
│  ┌────────────────────┐  │
│  │ ccguard CLI        │  │
│  │  scan/check/install│  │
│  │  /uninstall/enforce│  │
│  │  /sync/report      │  │
│  └────────────────────┘  │
│                          │
│  ~/.ccguard/             │
│   ├── config.yaml        │
│   ├── policy.yaml (cache)│
│   ├── audit.log (rot.)   │
│   └── bin/               │
│        └── ccguard-enforce
└──────────────────────────┘
```

### Поток данных

1. `ccguard scan` → читает все источники конфига → формирует
   `InventoryReport`.
2. `ccguard check` → применяет cached `policy.yaml` к
   `InventoryReport` → список `Finding`'ов.
3. `ccguard install` → пишет shim в `~/.ccguard/bin/` и добавляет
   запись в `~/.claude/settings.json` (или managed/project по `--scope`).
4. На каждый tool-use Claude Code вызывает shim → `ccguard enforce`
   читает stdin → отвечает JSON'ом в stdout → пишет audit-запись.
5. `ccguard sync` → POST inventory + findings + deny-audit на сервер →
   GET policy (с `If-None-Match`) → обновляет cache.

## 2. Pydantic-схемы

Все схемы — `pydantic` v2, лежат в пакете `ccguard.schemas` (общий между
агентом и сервером).

### 2.1. SchemaBase

```python
class SchemaBase(BaseModel):
    model_config = ConfigDict(
        extra="forbid",          # неизвестные поля = ошибка валидации
        str_strip_whitespace=True,
        frozen=False,
    )
```

### 2.2. Inventory

```python
class HookEntry(SchemaBase):
    event: Literal["PreToolUse", "PostToolUse", "SessionStart",
                   "SessionEnd", "UserPromptSubmit", "Stop",
                   "Notification", "SubagentStop", "PreCompact",
                   "PostCompact"]
    matcher: str | None
    type: Literal["command", "http", "mcp_tool", "prompt", "agent"]
    command: str | None = None          # для type="command"
    url: str | None = None              # для type="http"
    timeout_sec: int | None = None
    source: str                          # абсолютный путь файла settings.json

class McpServerEntry(SchemaBase):
    name: str
    transport: Literal["stdio", "http", "sse"]
    command: str | None = None           # для stdio
    args: list[str] = []
    url: str | None = None               # для http/sse
    env_keys: list[str] = []             # ТОЛЬКО ИМЕНА переменных, не значения
    source: str

class SkillEntry(SchemaBase):
    name: str
    path: str                            # абсолютный путь к папке скилла
    origin: Literal["local", "marketplace", "plugin"]
    dir_hash: str                        # sha256 от отсортированного списка
                                          # path:sha256(content) всех файлов
    has_referenced_scripts: bool

class PluginEntry(SchemaBase):
    name: str
    source: str                          # marketplace URL или local path
    enabled: bool

class PermissionsSnapshot(SchemaBase):
    allow: list[str] = []
    deny: list[str] = []
    ask: list[str] = []
    dangerously_skip_detected: bool      # обёртки/алиасы вида
                                          # `alias claude='claude --dangerously-...'`

class SettingsSource(SchemaBase):
    path: str
    scope: Literal["user", "project", "project_local", "managed"]
    exists: bool
    parse_error: str | None = None        # если файл битый

class InventoryReport(SchemaBase):
    schema_version: Literal[1] = 1
    machine_id: str                      # см. §6
    machine_label: str | None = None
    timestamp: datetime
    agent_version: str
    os: Literal["linux", "macos", "windows", "other"]
    settings_sources: list[SettingsSource]
    mcp_servers: list[McpServerEntry]
    skills: list[SkillEntry]
    hooks: list[HookEntry]
    plugins: list[PluginEntry]
    permissions: PermissionsSnapshot
    claude_code_version: str | None      # если детектируется
```

### 2.3. Finding

```python
Severity = Literal["info", "warn", "block"]

class Finding(SchemaBase):
    rule_id: str                         # e.g. "mcp_servers.denylist.name"
    severity: Severity
    title: str                           # human-readable, RU
    description: str                     # детали + что найдено
    source: str                          # откуда (файл или объект)
    recommendation: str                  # что сделать
    matched_value: str | None = None     # что именно сматчилось
```

### 2.4. Policy

```python
class RuleBase(SchemaBase):
    severity: Severity = "warn"

class McpServersPolicy(RuleBase):
    allowlist_names: list[str] = []
    denylist_names: list[str] = []
    allowlist_url_patterns: list[str] = []
    denylist_url_patterns: list[str] = []
    deny_all_unknown: bool = False       # whitelist-mode

class NetworkPolicy(RuleBase):
    allowlist_hosts: list[str] = []      # exact host или *.example.com
    denylist_hosts: list[str] = []
    deny_all_unknown: bool = False

class CommandsPolicy(RuleBase):
    denylist_patterns: list[str] = []    # regex
    allowlist_patterns: list[str] = []   # если задан, применяется whitelist-mode
    always_deny: list[str] = [           # вшитые «никогда не разрешать»
        r"\\becho\\s+.*>>\\s*~/.bashrc",
        r"\\becho\\s+.*>>\\s*~/.zshrc",
        r"\\becho\\s+.*>>\\s*~/.profile",
        r"\\bcurl\\s+.*\\|\\s*(sh|bash)\\b",
    ]

class SkillsPolicy(RuleBase):
    allowlist_names: list[str] = []
    trusted_dir_hashes: list[str] = []   # sha256 hex
    deny_all_unknown: bool = False
    signature: dict[str, Any] = {}       # заглушка под cosign в v2, MVP игнор

class HooksPolicy(RuleBase):
    allowlist_commands: list[str] = []   # абсолютные пути или substring
    deny_unknown: bool = True            # любой не-в-allowlist хук = finding

class PolicyMeta(SchemaBase):
    schema_version: Literal[1] = 1
    revision: int                         # монотонный счётчик
    name: str = "default"                 # на будущее multi-policy
    updated_at: datetime

class Policy(SchemaBase):
    meta: PolicyMeta
    block_fail_mode: Literal["open", "closed"] = "open"
    mcp_servers: McpServersPolicy = McpServersPolicy()
    network: NetworkPolicy = NetworkPolicy()
    commands: CommandsPolicy = CommandsPolicy()
    skills: SkillsPolicy = SkillsPolicy()
    hooks: HooksPolicy = HooksPolicy()
```

### 2.5. Enforce (hook protocol envelope)

```python
class EnforceHookInput(SchemaBase):
    """То, что Claude Code присылает в stdin. Только нужные поля."""
    hook_event_name: Literal["PreToolUse"]
    tool_name: str
    tool_input: dict[str, Any]
    cwd: str | None = None
    session_id: str | None = None

class EnforceDecision(SchemaBase):
    """Внутреннее представление, до сериализации в hook-формат."""
    permission: Literal["allow", "deny"]
    reason: str
    rule_id: str | None = None
    fail_open: bool = False              # сработал fail-open
```

Сериализация в hook-формат (см. §4) делается отдельным рендером, **не**
схемой — формат продиктован Claude Code.

### 2.6. AuditEntry

```python
class AuditEntry(SchemaBase):
    timestamp: datetime
    tool_name: str
    decision: Literal["allow", "deny"]
    rule_id: str | None = None
    reason: str | None = None
    fail_open: bool = False
    # ВНИМАНИЕ: tool_input НЕ логируется (может содержать секреты)
    # Вместо этого логируется fingerprint:
    tool_input_fingerprint: str          # sha256(json.dumps(tool_input))[:16]
```

### 2.7. SyncPayload (что агент шлёт на сервер)

```python
class SyncPayload(SchemaBase):
    inventory: InventoryReport
    findings: list[Finding]
    audit_events: list[AuditEntry] = []  # только deny + fail_open с
                                          # предыдущего sync
```

## 3. REST API контракты

База: `/api/v1`. Все ответы — JSON. Заголовок аутентификации:
`X-CCGuard-Token: <token>`. Невалидный/отсутствующий — `401`.

### 3.1. `POST /api/v1/inventory`

Приём `SyncPayload` от агента.

**Request body:** `SyncPayload`.

**Response 200:**
```json
{
  "accepted": true,
  "machine_id": "...",
  "stored_inventory_id": 42,
  "stored_findings_count": 7,
  "stored_audit_count": 3
}
```

**Errors:** `401` (no/bad token), `422` (валидация pydantic), `500`.

### 3.2. `GET /api/v1/policy`

Отдаёт текущую политику. Поддерживает `If-None-Match`.

**Request headers (опционально):** `If-None-Match: "rev-<revision>"`.

**Response 200:**
```yaml
# Content-Type: application/x-yaml
# ETag: "rev-7"
meta:
  schema_version: 1
  revision: 7
  ...
```

или Content-Type `application/json` если `Accept: application/json` —
тело идентично `Policy`-схеме.

**Response 304 Not Modified:** пустое тело, тот же ETag.

**Errors:** `401`, `500`.

### 3.3. `GET /api/v1/machines`

Список машин.

**Query params:**
- `severity` (опционально) — фильтр: only machines with finding >= severity.
- `limit` (default 100, max 500).

**Response 200:**
```json
{
  "machines": [
    {
      "machine_id": "...",
      "machine_label": "laptop-anton",
      "last_seen": "2026-05-23T10:00:00Z",
      "agent_version": "0.1.0",
      "findings_summary": {"info": 2, "warn": 5, "block": 1}
    }
  ],
  "total": 17
}
```

### 3.4. `GET /api/v1/machines/{machine_id}`

Детали по машине: последний inventory + findings.

**Response 200:**
```json
{
  "machine_id": "...",
  "machine_label": null,
  "last_seen": "...",
  "inventory": { /* InventoryReport */ },
  "findings": [ /* Finding[] */ ],
  "recent_audit_events": [ /* AuditEntry[] */ ]
}
```

**Response 404:** машина не найдена.

### 3.5. `GET /api/v1/findings`

Findings со всех машин.

**Query params:**
- `severity` (опционально) — `info|warn|block`.
- `rule_id` (опционально).
- `limit` (default 100, max 500).

**Response 200:**
```json
{
  "findings": [
    {
      "machine_id": "...",
      "machine_label": "...",
      "discovered_at": "...",
      "finding": { /* Finding */ }
    }
  ],
  "total": 142
}
```

### 3.6. `GET /health`

**Response 200:**
```json
{"status": "ok", "policy_revision": 7, "db": "ok"}
```

## 4. Hook enforce-протокол (точный формат)

Согласно [HOOKS_PROTOCOL.md](HOOKS_PROTOCOL.md). `ccguard enforce`:

1. Читает `stdin` → парсит `EnforceHookInput`.
2. Игнорирует, если `hook_event_name != "PreToolUse"` → exit 0 без JSON.
3. Применяет политику (см. §5).
4. Решение `allow` → exit 0, **никакого JSON в stdout** (это
   эквивалентно `defer`, не мешает обычным permission-rules Claude Code).
5. Решение `deny` → exit 0, stdout:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "ccguard: <rule_id> — <human reason>"
  },
  "suppressOutput": false
}
```

6. Ошибка / битая policy / отсутствие политики:
   - `block_fail_mode == "open"`: exit 0 без JSON, audit-запись с
     `fail_open: true`.
   - `block_fail_mode == "closed"`: exit 0 со stdout как в (5), reason
     `"ccguard: fail-closed (policy unavailable)"`.

7. Невалидный stdin / непарсируемый JSON: exit 0 без JSON
   (fail-open + audit).

## 5. Алгоритм матчинга политики

### 5.1. Bash (`tool_name == "Bash"`)

`tool_input.command` → строка. Применяется по порядку:

1. Любой паттерн из `commands.always_deny` → deny, `rule_id =
   commands.always_deny`.
2. Если `commands.allowlist_patterns` непустой и команда **не** мэтчит
   ни один паттерн → deny, `rule_id = commands.allowlist`.
3. Любой `commands.denylist_patterns` мэтчит → deny, `rule_id =
   commands.denylist`.
4. Иначе → allow.

Регекс компилируется один раз при загрузке policy в кэше.

### 5.2. MCP (`tool_name.startswith("mcp__")`)

Извлекаем `server = tool_name.split("__")[1]`. Применяется:

1. `server in mcp_servers.denylist_names` → deny.
2. `mcp_servers.deny_all_unknown` и `server not in
   allowlist_names` → deny.
3. Иначе → allow.

URL/host MCP-сервера в runtime недоступен (он в конфиге, не в payload) —
эти правила работают только в `ccguard check`.

### 5.3. WebFetch / WebSearch

`tool_name in {"WebFetch", "WebSearch"}` → извлечь host из
`tool_input.url`:

1. `network.deny_all_unknown` и host не мэтчит ни одного
   `allowlist_hosts` → deny.
2. Любой `network.denylist_hosts` мэтчит → deny.
3. Иначе → allow.

Глобы: `*.example.com` мэтчит `foo.example.com` и
`foo.bar.example.com`. `example.com` — только exact.

### 5.4. Прочие тулы

Не обрабатываются — exit 0 без JSON (= defer to permission system).

## 6. Деривация `machine_id`

```python
def derive_machine_id(install_salt: str, uid: int) -> str:
    raw_machine_id = read_first_existing([
        "/etc/machine-id",                  # Linux
        "/var/lib/dbus/machine-id",         # Linux fallback
    ]) or platform.node()                   # hostname fallback (macOS/Windows)

    digest = hashlib.sha256(
        f"{raw_machine_id}|{uid}|{install_salt}".encode()
    ).digest()
    return base64.b32encode(digest[:16]).decode().rstrip("=").lower()
```

`install_salt` — 32 случайных байта, генерируется при первом
`ccguard install` (если ещё не сгенерирован) и сохраняется в
`~/.ccguard/config.yaml`.

## 7. Локальные файлы агента

### `~/.ccguard/config.yaml`

```yaml
server:
  url: https://ccguard.example.com
  token: <static-api-token>          # required for sync
machine_label: "laptop-anton"        # опционально, человекочитаемая метка
install_salt: <32-bytes-hex>         # сгенерирован при install
audit:
  max_bytes: 10485760                # 10 MiB
  backup_count: 5
policy:
  cache_path: ~/.ccguard/policy.yaml
  block_fail_mode: open              # МОЖЕТ переопределить policy
sync:
  interval_minutes: 60               # для будущего демона, MVP — ручной
```

### `~/.ccguard/policy.yaml`

Кэш скачанной политики. Формат — `Policy` в YAML.

### `~/.ccguard/audit.log`

JSON-lines, ротация. Каждая строка — `AuditEntry`.

### `~/.ccguard/bin/ccguard-enforce`

Bash-shim (~20 строк), сгенерирован при install. Содержание:

```bash
#!/usr/bin/env bash
set -e
exec /opt/ccguard/bin/ccguard-enforce-bin "$@"
# или fallback на python:
# exec /usr/local/bin/python -m ccguard.enforce "$@"
```

При недоступности бинарника shim фиксирует это в audit (через
`logger -t ccguard` или прямой запись) и exit 0 (fail-open).

## 8. Серверный конфиг

### `server_config.yaml`

```yaml
tokens:
  - value: <token-1>
    label: "team-frontend"
  - value: <token-2>
    label: "team-backend"
policy_path: /etc/ccguard/server_policy.yaml
db_url: sqlite:///./ccguard.db
host: 0.0.0.0
port: 8080
log_level: INFO
```

Перезагрузка политики: сервер watch'ит `policy_path` через
`watchdog` или просто читает на каждом `GET /policy` (MVP — на каждом
запросе, кэш в памяти, инвалидация по mtime файла).

## 9. Data minimization

### Что НИКОГДА не покидает машину агента

- Значения env-переменных MCP-серверов.
- Содержимое `tool_input` в audit (только `tool_input_fingerprint`).
- Полный `command` Bash'а (в findings допускается `matched_value`
  обрезанный до 200 символов и с маской токенов: см. ниже).
- Содержимое `transcript_path`.
- Содержимое файлов скиллов (только хэши).
- Файлы из `Read`/`Write`/`Edit` (мы их не enforce'им вообще, не видим).

### Маскирование

Перед попаданием в `matched_value`, `description`, `recommendation`:

- Подстроки, мэтчащие regex'ы из встроенного списка
  (`r"sk-[A-Za-z0-9]{20,}"`, `r"ghp_[A-Za-z0-9]{20,}"`,
  `r"AKIA[A-Z0-9]{16}"`, и т.д.) → заменяются на `***MASKED***`.

## 10. Threat model & known limits

### В скоупе защиты

- Видимость конфига Claude Code для security-команды.
- Блокировка известных опасных bash-команд.
- Блокировка вызовов запрещённых MCP-серверов (по имени).
- Блокировка обращений к запрещённым доменам через `WebFetch`/
  `WebSearch`.
- Аудит deny-решений + fail_open.

### Известные обходы (документировать в README)

1. **Удаление хука** разработчиком из `~/.claude/settings.json`.
   Компенсация: `ccguard check` детектирует отсутствие; `--scope=managed`
   с root доступом блокирует пользователю запись.
2. **`disableAllHooks: true`** в любом из settings.json. Детектируется
   `check`.
3. **Запуск Claude Code из другого `$HOME`** или с альтернативным
   `--settings`. Не покрывается.
4. **MCP-сервер делает исходящие обращения к произвольным хостам.**
   Хук не видит. Покрывается частично через static-check конфига
   MCP-сервера (`url`, `args`).
5. **Подмена бинарника `ccguard-enforce-bin`.** Не проверяется
   подписью в MVP (заложено в `signature` поле, реализация в v2).
6. **Гонка между `sync` и обновлением policy на сервере.** Eventually
   consistent — окно до следующего sync. Документировать.

### Не покрывается принципиально

- Sandbox escape Claude Code'а или MCP-серверов.
- Перехват системных вызовов на уровне ядра.
- Защита от привилегированного пользователя на той же машине.

## 11. Versioning

- **Pydantic-схемы** — поле `schema_version: Literal[1]` на каждой
  корневой схеме. Сервер при `POST /inventory` валидирует и отказывает
  с `422` если неизвестный version.
- **Policy** — `meta.schema_version` + `meta.revision`. Агент:
  - При parse'е policy с неизвестным `schema_version` → fail-open,
    finding `policy.unknown_schema_version`, остаётся на предыдущем кэше.
  - При получении `revision <= cached_revision` — игнорирует (защита от
    отката).
- **REST API** — версия в URL (`/api/v1`). Несовместимые изменения = `/v2`.

## 12. Тестируемые контракты (для test plan)

- `POST /inventory` + `GET /machines/{id}` возвращают то же, что
  отправили.
- `GET /policy` с правильным `If-None-Match` возвращает `304`.
- `GET /policy` после правки файла на сервере возвращает новую policy
  с `+1` к revision.
- Невалидный `X-CCGuard-Token` → `401` на всех `/api/v1/*`.
- Битый JSON в inventory → `422`.
- `enforce` для запрещённой команды → exit 0 + `permissionDecision: deny`
  в stdout.
- `enforce` для разрешённой команды → exit 0, пустой stdout.
- `enforce` при отсутствии policy.yaml и `block_fail_mode=open` →
  exit 0, пустой stdout, audit-запись с `fail_open: true`.
- `enforce` при том же + `block_fail_mode=closed` → exit 0 + `deny`.
- `install` дважды подряд не дублирует запись в hooks.
- `uninstall` после `install` возвращает settings.json в исходное
  состояние (с поправкой на другие хуки, добавленные параллельно).
- Секреты не попадают в `Finding.matched_value` (тест на маскировку).
