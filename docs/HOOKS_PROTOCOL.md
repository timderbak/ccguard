# Claude Code Hooks — Protocol Reference (для ccguard)

> Источник: <https://code.claude.com/docs/en/hooks>. Снято 2026-05-23. Формат
> хуков менялся — перед внесением правок в `ccguard enforce` свериться с
> актуальной версией.

Документ — выжимка под нужды `ccguard`. Для общего обзора см. оригинал.

## 1. События, которые нужны ccguard

`ccguard` использует подмножество событий. Полный список — в оригинальной
доке.

| Событие | Когда | Matcher | Используется ccguard? |
|---|---|---|---|
| `PreToolUse` | До вызова тула | `tool_name`: `"Bash"`, `"Edit"`, ..., `"mcp__.*"` | **Да** — основное для enforce |
| `PostToolUse` | После успешного вызова | `tool_name` | Возможно (audit) |
| `SessionStart` | Старт/возобновление сессии | `"startup"`, `"resume"`, `"clear"`, `"compact"` | Возможно (предупреждение о просроченной политике) |

## 2. Формат payload на stdin

### Общие поля (все события)

```json
{
  "session_id": "abc123",
  "transcript_path": "/path/to/transcript.jsonl",
  "cwd": "/current/working/directory",
  "hook_event_name": "PreToolUse",
  "permission_mode": "default"
}
```

### PreToolUse — Bash

```json
{
  "session_id": "abc123",
  "transcript_path": "...",
  "cwd": "/Users/.../repo",
  "permission_mode": "default",
  "hook_event_name": "PreToolUse",
  "tool_name": "Bash",
  "tool_input": {
    "command": "npm test",
    "description": "Run test suite",
    "timeout": 120000,
    "run_in_background": false
  },
  "tool_use_id": "tool_123"
}
```

### PreToolUse — MCP tool

```json
{
  "hook_event_name": "PreToolUse",
  "tool_name": "mcp__memory__create_entities",
  "tool_input": { "entities": [{"name": "Alice", "type": "person"}] },
  "tool_use_id": "tool_456"
}
```

Имя MCP-тула формируется как `mcp__<server>__<tool>` — это позволяет
ccguard'у фильтровать по серверу через matcher `mcp__<server>__.*` или по
конкретному инструменту.

## 3. Варианты ответа

### Exit codes

| Код | Поведение |
|---|---|
| `0` | Успех. stdout парсится как JSON (если валиден). |
| `2` | Блокирующая ошибка. stdout/JSON игнорируется. stderr идёт в Claude. Для `PreToolUse` — блок тула. |
| Прочие | Non-blocking error. Первая строка stderr — в transcript. |

### JSON в stdout (только при exit 0)

#### Универсальные поля

```json
{
  "continue": true,
  "stopReason": "...",
  "suppressOutput": false,
  "systemMessage": "..."
}
```

#### PreToolUse-specific

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow",
    "permissionDecisionReason": "matches policy rule mcp_allowlist",
    "updatedInput": { "command": "npm run lint" },
    "additionalContext": "..."
  }
}
```

`permissionDecision`:

- `"allow"` — разрешить (минует обычный permission check).
- `"deny"` — отказать. `permissionDecisionReason` обязателен.
- `"ask"` — спросить пользователя. `permissionDecisionReason` обязателен.
- `"defer"` — отдать решение на стандартный механизм permissions.

`updatedInput` — опционально подменяет `tool_input` (мы НЕ используем —
ccguard не модифицирует, только allow/deny).

## 4. Конфигурация в settings.json

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "ccguard enforce",
            "timeout": 5
          }
        ]
      },
      {
        "matcher": "mcp__.*",
        "hooks": [
          {
            "type": "command",
            "command": "ccguard enforce",
            "timeout": 5
          }
        ]
      }
    ]
  }
}
```

### Семантика matcher

| Шаблон | Интерпретация |
|---|---|
| `"*"`, `""`, отсутствует | Любой |
| Только `[a-zA-Z0-9_|]` | Точное совпадение или pipe-list (`"Edit|Write"`) |
| Любой другой символ | JS-regex (`"mcp__.*"`, `"^Notebook"`) |

### Где находится файл

- `~/.claude/settings.json` — пользовательский, все проекты.
- `.claude/settings.json` — проектный (шарится через VCS).
- `.claude/settings.local.json` — проектный локальный (не шарится).
- managed settings — системный (если есть).

`ccguard install` пишет в `~/.claude/settings.json` (пользовательский
уровень), потому что enforcement должен покрывать ВСЕ проекты, а не один.

## 5. Что ccguard НЕ видит через хуки

- **Исходящий сетевой трафик внутри MCP-сервера.** Хук получает только
  `tool_name` и `tool_input` MCP-вызова, но не знает, куда MCP-сервер
  пойдёт по сети дальше. Контроль `network` denylist в policy реализуется
  только статически — через `ccguard check` на этапе инвентаризации
  (анализ конфига MCP-сервера: command, args, env, URL).
- **WebFetch/WebSearch — частично:** хук видит URL в `tool_input.url`,
  это можно проверять против `network` denylist в runtime. Заложить.

## 6. Производительность

- Хук вызывается синхронно перед каждым tool-use.
- Требование ccguard: < 100 мс.
- Следствия: никаких сетевых вызовов, политика читается из кэша, JSON
  policy валидируется один раз и кэшируется в памяти (либо используется
  pre-compiled regex кэш на диске).
