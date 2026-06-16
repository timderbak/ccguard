# Anti-tamper: что ccguard блокирует, что фиксирует, и где предел

**Угроза.** ccguard-enforce работает как PreToolUse-хук ВНУТРИ Claude Code, под
тем же пользователем (same-user), что и сам агент. Значит агент (которого мы и
мониторим) технически может попытаться снять защиту: убрать хук из
`~/.claude/settings.json`, удалить/занулить шим, остановить сервис, испортить
политику. EDR, который мониторимый агент может тихо выключить, — наполовину
театр.

## Фундаментальный принцип (честно)

**Устойчивость к удалению (tamper-resistance) для same-user-атакующего в принципе
недостижима** — enforcement *есть* хук, который удаляют (вещь, решающая «блокировать
ли снятие хука», и есть снимаемый хук; циклично). Реальная резистентность требует
**границы привилегий** (privilege boundary): root / отдельный пользователь /
неизменяемый бит — заведённой ОДИН раз при установке. Поэтому ccguard работает в
двух ярусах:

1. **Дефолт (same-user): hard-deny очевидного + tamper-EVIDENCE** — сломать можно,
   но сервер узнаёт мгновенно и громко (сервер за границей привилегий). Нулевая
   цена установки.
2. **Опциональный `ccguard harden` (privilege boundary): tamper-RESISTANCE** —
   агент физически не может убрать хук/подменить шим. Требует root один раз.

---

## Ярус 1 — дефолт (same-user)

### Hard-deny ИЗ КОРОБКИ (не флипается режимом `observe`)

**Bash (`hard.disable_security` / `hard.reverse_shell` / `hard.cred_exfil`):**
- `ccguard uninstall|disable|stop|remove`, `uninstall|remove ccguard`
- `rm|rmdir|mv|chattr|shred|truncate|unlink|chmod|cp|tee|dd|install … (.ccguard | ccguard-enforce | ccguard-audit)` — удаление/занулление/перезапись шима/конфига, **включая снос `~/.ccguard` целиком** (A2)
- `> … (.ccguard | ccguard-enforce|audit)` — перезапись через redirect
- `jq|sed … ccguard … .claude/settings` (и наоборот); `jq … del(.hooks …`
- `systemctl [--user] stop|disable|mask … ccguard`, `launchctl unload|bootout … ccguard`
- `pkill|killall|kill … ccguard` (а также falcon/crowdstrike/osquery/auditd/sentinelone)

**Write/Edit:**
- `hard.ccguard_self_tamper` — запись в собственные файлы ccguard (policy/config/шим)
- `hard.ccguard_hook_tamper` — Edit `settings.json`, чей `old_string` содержит
  `ccguard`, а `new_string` — нет (удаление/нейтрализация хука)
- `hard.ccguard_disableallhooks` (A3) — запись `"disableAllHooks": true` в
  `.claude/settings*.json` (гасит ВСЕ хуки разом). Матч только по записываемому
  контенту в settings-файл; упоминание ключа в доке/фикстуре не блокируется.

**Корректность (A1):** при отсутствующей/битой политике hard-deny ярус всё равно
прогоняется — раньше `policy is None` давал fail-open ДО hard-deny (тихий полный
обход). Только policy-driven правила подчиняются `block_fail_mode`.

FP≈0 by construction: всё привязано к имени `ccguard`/`.ccguard` или к ключу
`disableAllHooks` в settings. Сторожевые benign-корпуса (`test_antitamper_*_benign`,
`benign_dev_corpus`) проверяют 0 ложных блоков.

### Tamper-EVIDENCE (сервер за границей привилегий)

- **`sensor.silent`** — dead-man switch: сервер фиксирует, когда сенсор замолчал.
  Объявленный агентом интервал **клампится** серверно (`sensor.max_interval_sec`,
  C1) — скомпрометированный агент не оттянет детект, объявив 24ч. Метётся
  **выделенным быстрым sweep'ом раз в ~60с** (не часовым тиком), так что
  подавление всплывает за ~минуту.
- **`sensor.hook_drift`** (C2) — агент шлёт sha256 конфигурации хука; сервер
  TOFU-пинит и фиксирует дрейф. Ловит **repoint хука на no-op/decoy-шим**, чей
  путь содержит «ccguard» (подстрочная проверка `hooks_intact` это пропускала).
- **`sensor.hooks_removed`** — переход `hooks_intact` True→False (хук исчез).
- TOFU-baseline дрейф skill/agent/hook (`*.rug_pull` / `*.removed`).

### Предел яруса 1

Это НЕ резистентность. Удаление/перезапись самой записи хука в **user**
`settings.json` через полный `Write` неотличимо от легитимного свежего конфига и
НЕ блокируется (документированный residual same-user-предела). Такой путь
покрыт **EVIDENCE** (`sensor.hook_drift` + `sensor.silent` срабатывают за ~минуту),
а не блокировкой. Обфусцированные/косвенные варианты — поднимаем планку, ловим
остальное детектом.

---

## Ярус 2 — `ccguard harden` (privilege boundary, опционально)

Закрывает главный residual яруса 1 — удаление записи хука — настоящей
резистентностью. `ccguard harden` печатает ревьюируемый bash-скрипт (применять
root'ом: `ccguard harden | sudo bash`), который:

1. **Закрепляет хуки в root-owned managed-settings** Claude Code. Подтверждено
   против Claude Code v2.1.178: он читает `managed-settings.json` как отдельный
   policy/MDM-источник из системных путей (macOS
   `/Library/Application Support/ClaudeCode/`, Linux `/etc/claude-code/`). Файл
   root-owned → same-user-агент его не правит → **хук нельзя убрать**.
2. **Root-own + неизменяемый бит** на шим/audit/policy (`chown root`, `chmod
   0555/0444`, `chattr +i` Linux / `chflags schg` macOS) → шим/политику нельзя
   подменить без root.

Контент managed-settings строится тем же генератором, что и обычный install
(`install._install_event`) — структура хуков не дрейфит.

**Честные residual'ы яруса 2:**
- Шим всё ещё `exec`'ает venv-python — same-user, способный писать в venv, может
  подменить модуль. Полное закрытие — self-contained бинарь (bin-only deploy),
  отдельная задача.
- Переживает ли managed-хук пользовательский `disableAllHooks: true` — Anthropic
  не документирует. Правило A3 независимо hard-deny'ит запись `disableAllHooks`,
  так что агент его не выставит; но это стоит подтвердить полевым тестом.
- Генерация скрипта проверена тестами (`test_harden.py`) и вживую; **живое
  применение под root — полевой тест на эндпоинте** (как deploy read_file-сканера).

**Windows** в hardened-ярусе пока не моделируется (ACL/registry-based) — TODO.
