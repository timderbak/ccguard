# Роадмап: 3 воркстрима (идём постепенно, шаг = коммит)

Грунтовано по коду (планировочный воркфлоу, 14.06). Каждый шаг — отдельный коммит с TDD. Порядок внутри воркстрима — по возрастанию риска / убыванию ценности-на-усилие.

## A. Углубить моат (AI-trigger → escalation)

Коррелятор `ioa.ai_trigger_escalation` уже работает. Три незакрытых конца: алерт не виден в UI, триггер не в таймлайне, MCP-описания не сканируются моделью.

1. **[S] Explainer для `ioa.ai_trigger_escalation`** (`finding_view.py`) — по образцу `_slow_chain_explainer`. Риск 0 (read-only view). ⬅️ **делаем первым**
2. **[S] Ветка рендера в `machine_detail.html`** — карточка-история TRIGGER → ESCALATION + gap/окно. Риск: хрупкие render-тесты (аккуратно).
3. **[S] Семейство `ai_trigger.*` → initial-access** в catalog + chain_constants (без эмита — только словарь). Риск 0 (никто ещё не эмитит).
4. **[M] Синтетическое событие** при rug-pull/PI → `ai_trigger.*` в таймлайн + risk. Не петлит моат (initial-access ∉ ESCALATION_STAGES).
5. **[L] Семантический скан MCP-описаний** моделью (out-of-band, закрыть TODO в `mcp_baseline_service`; `scope='mcp_description'` уже готов в ScanService) — ловит инъекцию прозой в описании MCP, невидимую регексам.

## B. Блок очевидно-злого из коробки (hard_deny, переживающий observe)

Сейчас observe флипает ВСЕ deny→allow. Нужен ярус `hard_deny`, который блочит НЕЗАВИСИМО от режима — только то, что НИКОГДА не легитимно.

1. **[M] Механизм `hard_deny`** — поле в `EnforceDecision` + ранний возврат в `_apply_enforcement_mode` (не флипать hard). Без правил — нулевое изменение поведения. ⬅️ фундамент
2. **[M] hard_block: reverse shell** (`/dev/tcp/`, `nc -e`, `bash -i >&`). FP≈0 (в обычном dev почти не встречается).
3. **[L] hard_block: cred-store read + сеть в ОДНОЙ команде** (`cred_exfil` детектор). Самый тонкий FP — оба условия + внешний таргет (не localhost/private-IP).
4. **[M] hard_block: `curl|bash` только с внешнего хоста** (localhost/CI исключены).
5. **[M] hard_block: отключение ccguard-хука** (anti-tamper).
6. **[L] Ветка Write/Edit в `_decide_inner`** — опасные таргеты (authorized_keys hard; shell-rc — block/observe).

## C. Усилить детект (техники + обфускация + FP-калибровка)

1. **[M] Benign-корпус реального dev-трафика + CI-гард** (как obfuscation_corpus). Закрывает главную слабость ревью — «critical не доказан на реальном benign». ⬅️ самый ценный
2. **[S] `egress.git_push_remote`** (remote-add внешний + push).
3. **[S] `cred.read.ci_token`** (CI-секреты, READ-форма) + cred-варианты.
4. **[S] `persist.scheduled_task`** (systemd-timer, `at`, schtasks).
5. **[S] osascript clipboard-скрейп** (узко: `the clipboard`).
6. **[M] ROT13/`tr` charmap** как bounded-модель в нормализаторе (осторожно с precision).
7. **[S] `exec.lolbin_download`** (certutil/bitsadmin download-cradle).

---

## Прогресс (14.06)
- ✅ **A.1+A.2** (`98965ee`) — explainer + карточка-история для moat-алерта (скрин снят).
- ✅ **B.1+B.2+B.5** (`544674a`) — `hard_deny` tier: reverse shell + отключение ccguard/EDR блочатся ИЗ КОРОБКИ (даже в observe). FP≈0.
- ✅ **B.3** (`5375186`) — single-command cred-exfil hard-block (cred-файл = payload egress'а; FP-safe by construction).
- ✅ **C.1** (`7149417`) — benign-корпус (77 dev-команд) + CI-гард: 0 ложных hard-блоков. Страховка блок-яруса.
- ✅ **C.7** (`f78f1ce`) — `exec.lolbin_download` (certutil/bitsadmin/mshta).
- ✅ **C.4+C.5** (`2d8815a`) — `persist.scheduled_task` (systemd-timer/schtasks/`at`, команд-якорь на `at`) + osascript clipboard-read (`set the clipboard` исключён). TDD attack+benign.
- ✅ **C.6** (`4cc6a54`) — деобфускация `rev` (разворот) + `tr` charmap/ROT13 в нормализаторе. Additive + junk-filtered (FP-safe by construction). Корпус обфускации 124→126/127, флор поднят до 126.

**Веха:** ccguard теперь НЕ только смотрит — он БЛОКИРУЕТ 3 однозначно-злые вещи из коробки (reverse shell · отключение защиты · угон ключей), с FP-страховкой. Камера → охранник.
**B.4 (curl|bash external) НЕ берём в hard** — легит-инсталлеры (docker/rustup) делают так; остаётся block-severity (флипается в observe).

**A.4 — решение (не катим без присмотра):** «синтетическое событие триггера» через firehose `ToolUseEvent` читают 6+ потребителей (risk, slow_chain, sequence, chain_engine, anomaly-volume) → риск двойных алертов + загрязнения volume-бейзлайнов. Чистый вариант — in-memory `RiskInputEvent` из trigger-FindingRecord только в risk-скоринге (без персиста). НО: это поднимет risk и на benign `skill.drift`/`agent.drift` (часто — обычное обновление версии), а критичный moat-алерт опасный случай УЖЕ покрывает. Вывод: наименьшая доп.ценность при наибольшем behavior-риске → делать осознанно с Тимом (дифф-веса rug_pull≫drift), не автономно. Триггер уже виден в таймлайне как finding; «→ таймлайн» по сути закрыт.

**Следующее:** B.6 (Write-ветка enforce, нужен hook-matcher на Write) · C.2/C.3 (`egress.git_push_remote` / `cred.read.ci_token` — оба FP-рискованны через обычный push/env, нужен узкий якорь) · A.4 risk-priming (с Тимом).
