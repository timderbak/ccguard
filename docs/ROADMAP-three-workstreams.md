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
- ✅ **A.1+A.2** (`98965ee`) — explainer + карточка-история для moat-алерта.
- ✅ **B.1+B.2+B.5** (`544674a`) — `hard_deny` tier: reverse shell + отключение ccguard/EDR блочатся ИЗ КОРОБКИ (даже в observe). FP≈0.
- ✅ **C.7** (`f78f1ce`) — `exec.lolbin_download` (certutil/bitsadmin/mshta).

**Следующее:** B.3 (single-command cred-exfil hard-block — нужна аккуратная FP-калибровка корпусом) · A.3/A.4 (синтетические события триггера) · C.1 (benign-корпус) · C.2-C.5 (ещё техники).
