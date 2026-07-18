---
marp: true
title: ccguard EDR Review
description: Насколько ccguard является EDR, а где остается governance/decorative layer
theme: default
paginate: true
size: 16:9
---

<!-- _class: lead -->

# ccguard EDR Review

## Не декорация, но еще не полноценный EDR

Короткий security review: что реально работает, где слепые зоны, что чинить первым.

---

# Executive Verdict

**ccguard не бутафория.**

Есть реальные механики:

- PreToolUse enforcement
- PostToolUse audit и signal extraction
- IOA/sequence/chain correlation
- TOFU baselines для MCP/hooks/skills/agents
- heartbeat self-protection
- coverage map с detector liveness

**Но:** это пока скорее **Claude Code governance + behavioral telemetry/guardrail**, а не классический endpoint EDR.

---

# Что Делает Его Реальным

- Блокирует часть опасных действий до tool-use.
- Собирает privacy-preserving tool telemetry.
- Коррелирует события по session_id.
- Ловит drift в MCP/hooks/skills/agents.
- Видит sensor silence через heartbeat.
- Не хранит raw tool input на сервере.

Это уже полезный security layer для AI-agent среды.

---

# Главная Слабость

## Обещание EDR шире фактической видимости

ccguard видит в основном:

- Claude Code hook payload
- статические config/inventory snapshots
- извлеченные regex/action signals
- фоновые correlation findings

ccguard **не видит**:

- процессы ОС как классический EDR
- сетевой трафик внутри MCP
- runtime behavior stdio MCP
- действия вне Claude Code hooks

---

# Finding 1: Read PI Block Не Ставится

Код умеет блокировать `Read` до чтения файла:

- [`enforce.py`](../src/ccguard/agent/enforce.py:511)

Но installer регистрирует PreToolUse только:

```python
["Bash", "mcp__.*", "WebFetch", "WebSearch"]
```

- [`install.py`](../src/ccguard/agent/install.py:18)

**Итог:** Read prompt-injection prevention существует в коде, но обычная установка его не включает.

---

# Finding 2: MCP Blind Spot

MCP runtime visibility ограничена протоколом hooks.

Hook получает:

- `tool_name`
- `tool_input`

Hook не получает:

- куда MCP-сервер ходит по сети
- что реально делает внутри
- runtime `tools/list` для stdio MCP

Подтверждение: [`HOOKS_PROTOCOL.md`](HOOKS_PROTOCOL.md:165), [`mcp_probe.py`](../src/ccguard/agent/mcp_probe.py:8)

---

# Finding 3: Shared Token Trust Gap

Сервер проверяет, что token валиден:

- [`deps.py`](../src/ccguard/server/api/deps.py:35)

Но token не привязан к `machine_id`.

Сам код документирует это как v0.2 limitation:

- [`audit.py`](../src/ccguard/server/api/audit.py:23)

**Риск:** агент с валидным токеном может подделать telemetry/finding под чужую машину.

---

# Finding 4: Prevention Мягкий По Умолчанию

Default policy:

- `enforcement_mode: observe`
- `block_fail_mode: open`

См. [`policy.py`](../src/ccguard/schemas/policy.py:612)

В observe deny превращается в allow:

- [`enforce.py`](../src/ccguard/agent/enforce.py:394)

**Итог:** из коробки это больше наблюдение и would-block, чем жесткая блокировка.

---

# Finding 5: Sensor Integrity Слабее Заявки

Heartbeat self-check считает hooks intact, если в любом hook command есть строка `ccguard`.

- [`heartbeat.py`](../src/ccguard/agent/heartbeat.py:23)

Но строгий verifier уже есть отдельно:

- проверяет required matchers
- проверяет shim markers
- проверяет `disableAllHooks`

См. [`install.py`](../src/ccguard/agent/install.py:376)

**Проблема:** daemon heartbeat не использует строгий verifier.

---

# Finding 6: TOFU Bootstrap Blind Spot

Первое состояние принимается как baseline без finding.

Пример MCP:

- [`mcp_baseline_service.py`](../src/ccguard/server/services/mcp_baseline_service.py:148)

После drift finding baseline обновляется:

- [`mcp_baseline_service.py`](../src/ccguard/server/services/mcp_baseline_service.py:280)

**Риск:** вредоносное состояние до установки становится “нормой”.

---

# Finding 7: Дедуп Может Скрыть Повторы

Sequence и chain detection уже session-scoped.

Это хорошо:

- [`sequence_service.py`](../src/ccguard/server/services/sequence_service.py:12)

Но finding dedup остается machine/day:

- [`sequence_service.py`](../src/ccguard/server/services/sequence_service.py:375)
- [`chain_engine.py`](../src/ccguard/server/services/chain_engine.py:319)

**Риск:** второй независимый инцидент в другой сессии в тот же день может не всплыть.

---

# Finding 8: Risk Weights Не Тюнятся

Комментарии обещают:

```text
risk.weight.<signal_id>
```

- [`risk_constants.py`](../src/ccguard/server/services/risk_constants.py:3)

Но `_load_tunables()` читает только:

- threshold
- window
- half-life

См. [`risk_service.py`](../src/ccguard/server/services/risk_service.py:115)

**Итог:** risk score менее управляемый, чем заявлено.

---

# Что Уже Сильное

- Хороший signal catalog: creds, egress, persistence, C2, impact.
- Session-scoped deterministic IOA без warm-baseline blind spot.
- LLM backstop для suspicious Read content.
- Coverage map различает `armed`, `dark`, `detecting`.
- Privacy model: fingerprint/signals вместо raw input.
- Большой test corpus для PI escalation gate.

Это ядро, из которого можно вырастить серьезный продукт.

---

# Evidence

Проверил targeted suite:

```bash
./.venv/bin/pytest \
  tests/unit/test_install.py \
  tests/unit/test_enforce_read_pi_block.py \
  tests/unit/test_signal_extractor.py \
  tests/integration/test_sequence_session_scope.py \
  tests/integration/test_coverage_detection_reality.py -q
```

Результат:

```text
116 passed
```

Полный regressions suite и live pentest в этом проходе не запускались.

---

# Priority Fixes

1. Добавить `Read` в PreToolUse matcher install flow.
2. Привязать agent token к machine identity.
3. Использовать строгий `verify_installation()` в heartbeat.
4. Сделать MCP stdio/runtime blind spot явным в UI и docs.
5. Перейти с machine/day dedup на session-aware dedup.
6. Реально загрузить `risk.weight.<signal_id>` из settings.
7. Развести marketing language: EDR-like governance сейчас, EDR позже.

---

# Final Positioning

## Лучшее честное описание

**ccguard is an EDR-like governance and behavioral detection layer for Claude Code agents.**

Он полезен уже сейчас для:

- visibility
- centralized guardrails
- audit
- AI-agent-specific IOA
- MCP/hooks/skills drift detection

Но пока не должен продаваться как полноценная замена EDR или sandbox.

