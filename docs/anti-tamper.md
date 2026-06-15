# Anti-tamper: что ccguard блокирует и где предел

**Угроза.** ccguard-enforce работает как PreToolUse-хук ВНУТРИ Claude Code, под
тем же пользователем, что и сам агент. Значит агент (которого мы и мониторим)
технически может попытаться снять защиту: убрать хук из `~/.claude/settings.json`,
удалить/занулить шим, остановить сервис. EDR, который мониторимый агент может
выключить, — наполовину театр. Этот ярус закрывает очевидные пути.

## Что блокируется ИЗ КОРОБКИ (hard-deny, даже в observe-режиме)

Блок не флипается режимом `observe` — это `hard_deny`.

**Bash (`hard.disable_security`):**
- `ccguard uninstall|disable|stop|remove`, `uninstall|remove ccguard`
- `rm|rmdir|mv|chattr|shred|truncate|unlink|chmod … (.ccguard/ | ccguard-enforce | ccguard-audit)` — удаление/занулление/блокировка шима или конфига
- `> … ccguard-enforce|audit` — перезапись шима
- `jq|sed … ccguard … .claude/settings` (и наоборот) — вырезать ccguard-хук
- `jq … del(.hooks …` — снести блок хуков целиком
- `systemctl [--user] stop|disable|mask … ccguard`, `launchctl unload|bootout … ccguard`
- `pkill|killall|kill … ccguard` (а также falcon/crowdstrike/osquery/auditd/sentinelone)

**Write/Edit:**
- `hard.ccguard_self_tamper` — запись в собственные файлы ccguard
  (`~/.ccguard/policy.yaml`, `~/.ccguard/config.yaml`, шим `ccguard-enforce/audit`)
- `hard.ccguard_hook_tamper` — Edit `~/.claude/settings.json`, чей `old_string`
  содержит `ccguard`, а `new_string` — нет (удаление/нейтрализация хука).
  Обычные правки settings (добавить MCP-сервер и т.п.) НЕ трогаются.

FP≈0 by construction: всё привязано к имени `ccguard`/`.ccguard` или к удалению
блока хуков. Бенчмарк-набор benign-команд (`rm -rf node_modules`, `chmod +x …`,
`jq '.scripts' package.json`, правка `.zshrc`, чтение settings) проверяется
тестом `test_antitamper_*_benign` — ни одна не блокируется.

## Архитектурный предел (честно)

Это НЕ полная tamper-resistance. Поскольку enforce работает под тем же
пользователем, что и агент, у достаточно изобретательного агента остаются пути,
которые этот regex-ярус не покрывает (например, полная перезапись `settings.json`
через `Write` неотличима от легитимного свежего конфига и потому НЕ блокируется;
обфусцированные варианты shell-команд; косвенные пути). Мы поднимаем планку на
очевидных путях и ДЕТЕКТИМ остальное (`defense.disable_security`,
`config.agent_settings_edit`, `sensor.*removed` — удаление security-хука эмитит
finding).

**Настоящая tamper-resistance (v0.3):** запускать enforce/сенсор как отдельного
пользователя или root-демон, чтобы агент физически не мог править ни конфиг, ни
хук-реестр. Тогда этот ярус становится «вторым эшелоном», а не единственным.
