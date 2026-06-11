# Spec — P4: MCP blind spot (injection via tool-result)

**Дата:** 2026-06-12
**Под-проект:** P4 программы «ccguard → EDR для AI-агентов» — дифференциация (MCP-слой)
**Статус:** design (лёгкий цикл, реализуем сразу TDD)

## Проблема (из аудита)

Тезис продукта — слепое пятно ИБ это AI dev-tooling, и главный AI-специфичный вектор —
**MCP**. Но именно он почти не покрыт:
- **Результат MCP-тула не тегается как внешний контент** (`extractor._external_content_signals`,
  TODO на extractor.py:98-101). Малициозный MCP-сервер может вернуть в результате
  indirect prompt injection — но `content.read.external` (→ стадия initial-access) не
  возникает, поэтому ни одна цепочка `injection→action→exfil` не стартует. Под это стоит
  `xfail(strict)` в `tests/integration/test_evasion_corpus.py::test_mcp_tool_result_is_external_content`.

## Решение (этот раунд — P4a)

Любой инструмент с именем `mcp__<server>__<tool>` — это, по построению, вызов
**стороннего/недоверенного** MCP-сервера; его **результат — внешний недоверенный контент**
(модель угроз: все MCP-серверы third-party по умолчанию). Поэтому
`_external_content_signals` эмитит `content.read.external` для любого `tool_name`,
начинающегося на `mcp__`.

- Реюз существующего: `content.read.external` уже маппится в стадию **initial-access**
  (`chain_constants._SIGNAL_STAGE_RULES`), уже tool-gated (в `ACTION_SIGNAL_IDS`), уже имеет
  risk-вес. **Никаких изменений корреляции/каталога/весов** — только источник тега.
- Severity голого тега низкая; критичность даёт цепочка (initial-access → … → exfil),
  ровно как у egress в P1. Одинокий MCP-вызов finding не создаёт — нет шума.
- Privacy неизменна: наружу только signal-ID.

## Не в этом раунде (follow-up P4b)
- **Runtime rug-pull описаний MCP**: rug-pull-сканер хеширует `description` из статического
  `.mcp.json`, а реальные описания приходят в рантайме через `tools/list`. Чтобы это
  закрыть, агенту нужно фактически опрашивать MCP-серверы (spawn + tools/list) на скане —
  это отдельный, больший объём (touches agent/scan/mcp.py + mcp_baseline_service). Отложено.
- MCP-канальный egress/объём: из хука не отличить локальный stdio-сервер от удалённого —
  отложено.

## Тестирование
- `extract_signals("mcp__untrusted__fetch", {...})` → содержит `content.read.external`
  (снять `xfail` с corpus-теста — он теперь проходит).
- Не-MCP инструменты не затронуты (регресс `test_signal_extractor`).
- Цепочка: MCP-инъекция (initial-access) + cred-read + egress → корреляция стартует
  (интеграционный smoke по аналогии с P1 evasion-тестом).

## DoD
1. MCP tool-result даёт `content.read.external` → стадия initial-access достижима.
2. `xfail` в evasion-корпусе снят, тест зелёный.
3. Корреляция/каталог/веса не тронуты; полный регресс зелёный.
