<!-- GSD:project-start source:PROJECT.md -->
## Project

**ccguard**

**EDR-слой для AI-агентов на developer-эндпоинтах.** Self-hosted central server + endpoint agent, которые инвентаризируют, контролируют и enforcement'ят конфигурацию Claude Code (MCP-серверы, skills, hooks, agents, commands, permissions) в организации. Целевая аудитория — AppSec/SecOps команды в финтехе, healthtech и гос-секторе, для которых классический EDR (CrowdStrike, SentinelOne) и cloud-AI-WAF (Cisco AI Defense, Lakera) не покрывают слепое пятно: shell-execution через AI dev-tooling.

**Core Value:** **Полная visibility + behavioral enforcement на каждом developer-эндпоинте, где живёт AI-агент с правом на Bash/Write/Edit.** Если ИБ не видит и не блочит — атака через supply chain плагин с `tools: Bash` обходит весь EDR.

### Constraints

- **Tech stack**: Python 3.12, FastAPI, SQLModel, HTMX + Jinja2 — не меняем стек для v0.2
- **Self-hosted**: ВСЁ должно работать on-prem без внешних SaaS; единственное внешнее зависимость — Anthropic API для LLM-сканера, опциональная
- **Single-tenant**: один org на инстанс; multi-tenant перенесён в v0.3
- **Backward compat**: agent v0.1 должен продолжить работать против server v0.2 (graceful degradation новых endpoints)
- **DB**: SQLite WAL-режим, не Postgres — пока < 100 машин; миграция на Postgres в v0.3 если потребуется
- **Performance**: PreToolUse hook latency < 100ms (текущий enforce-shim ≈30ms); prompt-injection scan не должен этого ломать
- **Security**: всё что хранится — хеши или шифрованно (Fernet через `SECRET_KEY` env); никаких plain-text токенов в БД
- **Schema versioning**: `schema_version` в InventoryReport и Policy — повышаем при breaking changes, агент шлёт свою версию, сервер graceful
<!-- GSD:project-end -->

<!-- GSD:stack-start source:STACK.md -->
## Technology Stack

Technology stack not yet documented. Will populate after codebase mapping or first phase.
<!-- GSD:stack-end -->

<!-- GSD:conventions-start source:CONVENTIONS.md -->
## Conventions

Conventions not yet established. Will populate as patterns emerge during development.
<!-- GSD:conventions-end -->

<!-- GSD:architecture-start source:ARCHITECTURE.md -->
## Architecture

Architecture not yet mapped. Follow existing patterns found in the codebase.
<!-- GSD:architecture-end -->

<!-- GSD:skills-start source:skills/ -->
## Project Skills

No project skills found. Add skills to any of: `.claude/skills/`, `.agents/skills/`, `.cursor/skills/`, `.github/skills/`, or `.codex/skills/` with a `SKILL.md` index file.
<!-- GSD:skills-end -->

<!-- GSD:workflow-start source:GSD defaults -->
## GSD Workflow Enforcement

Before using Edit, Write, or other file-changing tools, start work through a GSD command so planning artifacts and execution context stay in sync.

Use these entry points:
- `/gsd-quick` for small fixes, doc updates, and ad-hoc tasks
- `/gsd-debug` for investigation and bug fixing
- `/gsd-execute-phase` for planned phase work

Do not make direct repo edits outside a GSD workflow unless the user explicitly asks to bypass it.
<!-- GSD:workflow-end -->



<!-- GSD:profile-start -->
## Developer Profile

> Profile not yet configured. Run `/gsd-profile-user` to generate your developer profile.
> This section is managed by `generate-claude-profile` -- do not edit manually.
<!-- GSD:profile-end -->
