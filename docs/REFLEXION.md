# REFLEXION: ccguard MVP

> Фаза 5 lifecycle. Критика после имплементации: что вышло не как
> планировалось, какие slippery slopes найдены, что упростить и что
> усложнить. Список follow-up issues для v0.2+.

Дата: 2026-05-23. Тесты: **112 unit/integration + 6 e2e = 118 passed**.

## 1. Что в итоге сделано (vs SPEC)

| Раздел SPEC | Статус | Комментарий |
|---|---|---|
| §2 Pydantic-схемы | ✅ | 11 round-trip тестов, `extra="forbid"` везде, `EnforceHookInput` с `extra="ignore"` (мотивация — Claude Code присылает больше полей). |
| §3 REST API (6 endpoints) | ✅ | Auth, ETag, 401, 422, 404 — all covered. |
| §4 Hook enforce | ✅ | exit-code 0 + `permissionDecision` через `hookSpecificOutput`. Allow = пустой stdout. |
| §5 Алгоритмы матчинга | ✅ | Bash (always_deny → allowlist → denylist), MCP (denylist/whitelist), Web (host/glob). |
| §6 machine_id | ✅ | sha256(raw‖uid‖salt), base32 lower, 26 символов. |
| §7 Локальные файлы | ✅ | config.yaml с 0600, atomic write, audit с ротацией. |
| §8 Server config | ✅ | YAML + env-fallback, токены маскируются. |
| §9 Data minimization | ✅ | Покрыто отдельным e2e-тестом `test_secrets_not_leaked_to_server`. |
| §10 Threat model | ✅ | Задокументирована в README. |
| §11 Versioning | ✅ | `revision` + ETag, anti-rollback в sync. |
| §12 Test contracts | ✅ | Все 12 пунктов в тестах. |

## 2. Что отклонилось от плана

### 2.1. PyInstaller перенесён в follow-up (was Stage 12)

**Причина:** dev-feedback loop важнее. Shim-fallback `python -m
ccguard.agent.enforce_main` работает; cold-start ≈150мс на нашей
тестовой машине — это больше плановых 100мс, но допустимо для MVP.

**Риск:** в реальном проде разработчики заметят лаг. Поправимо
сборкой в v0.2.

**Mitigation сейчас:** Audit-лог не блокирует поток (через
`RotatingFileHandler` буферизация).

### 2.2. `policy.paths` (Edit/Write/Read denylist) убран по решению пользователя

В Brainstorm-фазе пользователь сначала выбрал «фильтровать всё», потом
сказал «paths не надо». Финальный enforce-scope: **Bash + MCP +
WebFetch/WebSearch**. Edit/Write/Read не enforce'ятся. Это в README
явно записано как ограничение MVP — кто захочет, поднимет в v2.

### 2.3. Tamper-detection вынесен в `check`, не встроен в `enforce`

**Reason:** enforce — горячий путь, любая лишняя IO-операция бьёт по
100мс. `check` запускается раз в N часов/в CI и спокойно проверяет.

`verify_installation()` в `install.py` детектирует:

- отсутствие нашего хука для любого из matcher'ов;
- `disableAllHooks: true`;
- отсутствующий или модифицированный shim (по marker'у).

## 3. Slippery slopes, найденные после имплементации

### 3.1. `extra="ignore"` в `EnforceHookInput`

Только эта схема **не** запрещает лишние поля. Мотивация — Claude
Code присылает много полей, мы тащим только нужные. Но это создаёт
прецедент: «расширили в одном месте — расширят и в других». В коде
оставлен комментарий, в тесте `test_enforce_hook_input_ignores_extra`
явно проверяется. Если кто-то добавит ещё одну схему-исключение, надо
обсудить отдельно.

### 3.2. Atomic write через `tmp + rename` не работает на Windows

`Path.replace()` на Windows кидает `PermissionError` если target
открыт другим процессом. Linux — ок. Windows ниже в приоритете, но
если будем пилить — переписать с `os.replace` + retry-loop.

### 3.3. `_load_policy` в enforce использует `lru_cache`

```python
@lru_cache(maxsize=4)
def _load_policy(path: str) -> Policy | None: ...
```

В CLI-процессе (короткоживущем) это норм. Если когда-нибудь сделаем
daemon-режим — кэш не инвалидируется по mtime, надо переписать. В
коде комментарий стоит.

### 3.4. `httpx.MockTransport` в integration-тестах

Нестабильный API: в новых версиях httpx может смениться. Если упадёт
в CI после bump'а версии — переписать на real-server-in-subprocess. В
плане v0.2.

### 3.5. `_filter_audit_for_sync` молча отбрасывает allow-записи

Если когда-нибудь захотим стриминговый аудит (всё на сервер), надо
помнить, что эта функция фильтрует. Метрика: сколько allow vs deny
пропущено — не считается. Можно добавить counter в response.

## 4. Что упростить / что усложнить

### Упростить

- **`tests/integration/conftest.py`** — два раза переписывает
  `app.state` (до lifespan и после). Сделано из паранойи. Можно убрать
  один из двух присваиваний — lifespan уже корректно подхватывает
  config, если правильно патчить env.
- **`install.py:_managed_paths`** — список из двух путей, но один из
  них (`/Library/...`) тестами не покрыт. Можно убрать до того, как
  будет macOS-юзер.

### Усложнить

- **Add metrics endpoint** в сервере — `/metrics` в Prometheus
  формате (число inventories, findings по severity, audit-событий).
  Полезно при росте.
- **Add policy validator CLI** — `ccguard validate-policy
  policy.yaml` чтобы админу не нужно было перезапускать сервер
  чтобы понять, что YAML валиден.

## 5. Follow-up issues (для v0.2+)

| # | Priority | Что | Зачем |
|---|---|---|---|
| 1 | high | PyInstaller-сборка `ccguard-enforce-bin` | <100мс enforce + меньше зависимостей в shim |
| 2 | high | Daemon-mode для enforce (UNIX socket) | Альтернатива (1), сохраняет policy в RAM |
| 3 | medium | Sigstore/cosign подписи скиллов | Защита от подмены |
| 4 | medium | Per-agent токены + registration endpoint | mTLS-альтернатива |
| 5 | medium | Multi-tenancy: policies по командам | Реалистично для org 50+ человек |
| 6 | medium | Cursor / Codex поддержка | Та же модель, другие источники |
| 7 | low | Web-UI dashboard (read-only) | Удобнее JSON'а для security-команды |
| 8 | low | Streaming audit | Когда нужен real-time SOC |
| 9 | low | LLM Gateway коннектор | Контроль на уровне API, не агента |
| 10 | low | macOS/Windows polish | Сейчас best-effort |

## 6. Метрики MVP

- **Строк кода (src/):** ~1500
- **Тестов:** 118 (включая 6 e2e в Docker)
- **Зависимостей runtime:** 7 (pydantic, typer, fastapi, uvicorn,
  sqlmodel, httpx, pyyaml + platformdirs)
- **Время сборки Docker-server-образа:** ~5с (cached), ~30с (clean)
- **Время прогона всех unit+integration тестов:** ~3с
- **Время прогона e2e цикла:** ~4с (включая старт сервера)

## 7. Что научило

- **Brainstorm перед SPEC окупается.** Пользователь развернул скоп
  paths-rules ещё до того, как был написан первый матчер — это
  сэкономило ~200 строк policy и тестов.
- **Hook-протокол менялся, верификация документации — критична.** На
  старте я мог бы взять память из training data, формат был бы
  частично правильный (deprecated `decision: "block"` вместо
  `hookSpecificOutput.permissionDecision: "deny"`). Web-fetch перед
  Spec'ом снял весь риск.
- **Pydantic `extra="forbid"` ловит больше багов, чем юнит-тесты.**
  Любая опечатка в YAML-policy валится с человекочитаемой ошибкой
  на load, а не неожиданным `None` глубоко в матчинге.
- **Test container с фиксированными «грязными» фикстурами** даёт
  e2e-сценарий, который воспроизводим и независим от хоста.
