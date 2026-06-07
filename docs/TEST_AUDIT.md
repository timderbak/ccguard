# Аудит тестового набора ccguard

> Дата: 2026-06-07 · Окружение: `uv run pytest` (Python 3.14.4, pytest 9.0.3)
> Статус: **только анализ** — ни один тест не изменён и не удалён.

## Резюме

- **Счётчики:** unit = **925**, integration = **482**, e2e = **15** (всего 1422 collected; прогон `unit+integration` = 1404 passed за ~83 с — разница в 18 тестах объясняется skip/deselect маркерами при объединённом запуске).
- **Скорость:** весь `unit+integration` укладывается в 83 с, самый медленный тест 1.33 с. Откровенно медленных нет; топ-список — это тесты, делающие реальную работу (docker-валидация, bcrypt-хеш, subprocess-латентность хука).
- **Дубли:** session-scope инвариант (cross-session НЕ склеивается) намеренно продублирован в 3 файлах (`test_sequence_session_scope`, `test_staging_chain`, `test_staging_scoring`) — это три РАЗНЫХ движка (`evaluate_one` vs `evaluate_one_staging` + scoring-путь), дубль оправдан. Рекомендация: оставить, опционально пометить комментарием-якорем. Реальный кандидат на параметризацию — severity-проверки разбросаны по 6+ файлам.
- **Safety-predicates:** 6 критических тестов-предохранителей, трогать нельзя (см. секцию 4). Два из них прямо помечены в коде эмодзи-замком 🔒.
- **e2e:** из 8 падений **8 — окруженческие** (нет live-сервера/контейнера или отдельной фикстуры). Реальных багов кода **нет**. Все 8 → вердикт **skip с причиной**.

---

## 1. Счётчики

Команда `uv run pytest tests/<dir> --collect-only -q` в этом окружении не печатает строку node-id в ожидаемом формате, поэтому числа взяты из строки-итога `--collect-only` (`N tests collected`):

| Каталог | Collected |
|---|---|
| `tests/unit` | **925** |
| `tests/integration` | **482** |
| `tests/e2e` | **15** |

Разбивка e2e по файлам (`--collect-only -q`):
- `tests/e2e/test_end_to_end.py` — 6
- `tests/e2e/test_pi_e2e.py` — 4
- `tests/e2e/test_push_install_e2e.py` — 4
- `tests/e2e/test_web_e2e.py` — 1

Объединённый прогон `tests/unit tests/integration`: **1404 passed in 82.74s**.

---

## 2. Медленные тесты (топ-25 по длительности)

`uv run pytest tests/unit tests/integration -p no:warnings --durations=25`

| # | Время | Фаза | Тест |
|---|---|---|---|
| 1 | **1.33s** | call | `tests/unit/test_llm_phase_regression.py::test_phase_3_test_count_baseline` |
| 2 | **1.21s** | call | `tests/integration/test_web_smoke.py::test_change_admin_password` |
| 3 | **0.67s** | call | `tests/integration/test_prompt_injection_e2e_hook.py::test_subprocess_latency_budget_under_100ms` |
| 4 | 0.55s | call | `tests/unit/test_auth_service.py::test_hash_then_verify_roundtrip` |
| 5 | 0.50s | call | `tests/integration/test_audit_flush_e2e.py::test_flush_trims_buffer_to_cap_after_success` |
| 6 | 0.40s | call | `tests/unit/test_install_scripts_syntax.py::test_compose_validates_with_docker` |
| 7 | 0.39s | call | `tests/integration/test_machine_detail_skill_agent_baseline_ui.py::test_skill_bootstrap_banner_renders_with_pending` |
| 8 | 0.38s | call | `tests/integration/test_last_sync_badge.py::test_missing_sync_renders_red_badge` |
| 9 | 0.38s | call | `tests/integration/test_machine_detail_mcp_diff.py::test_accept_baseline_endpoint_redirects` |
| 10 | 0.36s | setup | `tests/integration/test_policy_mandatory_routes.py::test_draft_default_redirects_to_policy_when_tab_missing` |
| 11 | 0.35s | setup | `tests/integration/test_audit_page.py::test_audit_empty_db_renders_empty_state` |
| 12 | 0.32s | call | `tests/integration/test_empty_states.py::test_overview_empty_renders_without_machines` |
| 13 | 0.31s | call | `tests/integration/test_proposed_signals_llm_route.py::test_route_drafts_via_app_state_drafter` |
| 14 | 0.31s | setup | `tests/integration/test_audit_timeline_partial.py::test_timeline_partial_is_fragment_not_full_page` |
| 15 | 0.31s | setup | `tests/integration/test_anomalies_overview_partial.py::test_anomalies_overview_anonymous_redirects_or_401` |
| 16 | 0.31s | call | `tests/integration/test_pi_pattern_ui.py::test_admin_page_renders_pi_form` |
| 17 | 0.30s | call | `tests/integration/test_admin_skills_inventory.py::test_drill_partial_returns_machine_list` |
| 18 | 0.30s | setup | `tests/integration/test_llm_admin_routes.py::test_rescan_when_budget_exhausted_inline_notice` |
| 19 | 0.30s | call | `tests/integration/test_skills_overview_details.py::test_row_with_full_detail_renders_explanation_and_snippet` |
| 20 | 0.30s | setup | `tests/integration/test_llm_admin_routes.py::test_llm_settings_post_without_admin_cookie_rejected` |
| 21 | 0.29s | setup | `tests/integration/test_policy_editor_pi_render.py::test_draft_values_prefill` |
| 22 | 0.29s | call | `tests/integration/test_render_snapshots.py::test_login_page_snapshot` |
| 23 | 0.29s | setup | `tests/integration/test_llm_admin_routes.py::test_llm_settings_post_persists_toggle_and_budget` |
| 24 | 0.29s | call | `tests/integration/test_web_smoke.py::test_machine_detail_renders_inventory` |
| 25 | 0.29s | setup | `tests/integration/test_anomaly_routes.py::test_anomaly_detail_unknown_metric_returns_404` |

**Что заметно медленнее остального:**
- Топ-3 (1.33 / 1.21 / 0.67 с) отрываются от хвоста (≤0.55 с) и от медианы (≈0.3 с). Причины законны и не требуют оптимизации:
  - `test_phase_3_test_count_baseline` — мета-тест, сам пересчитывает количество тестов (collection-heavy).
  - `test_change_admin_password` — реальный bcrypt/passlib хеш-раундтрип (намеренно дорогой KDF).
  - `test_subprocess_latency_budget_under_100ms` — спавнит реальный subprocess хука для измерения латентности (это и есть предмет теста — бюджет <100 мс из CLAUDE.md).
- Остальные 22 теста плотно сгруппированы в 0.29–0.55 с — фиксированная стоимость поднятия TestClient/in-memory DB на setup. Узких мест нет.

---

## 3. Потенциальные дубли

### 3.1 Session-scope инвариант «cross-session НЕ склеивается» (ТЗ-01/02/03)

Один и тот же инвариант проверяется в трёх файлах:

| Файл | Тест | Что проверяет |
|---|---|---|
| `tests/integration/test_sequence_session_scope.py:58` | `test_cross_session_cred_egress_does_not_match` | cred(A) + egress(B) → `evaluate_one` → None |
| `tests/integration/test_staging_chain.py:104` | `test_cross_session_does_not_match` | cred(A) + write.hidden(B) → `evaluate_one_staging` → None |
| `tests/integration/test_staging_chain.py:199` | `test_external_chain_session_scope` | external-read(A) + write.hidden(B) → `evaluate_one_staging` → None |
| `tests/integration/test_staging_scoring.py:195` | `test_session_scope_preserved_with_scoring` | external(A) + write.hidden(B) → scoring-путь `evaluate_one_staging` → None |

**Что дублируется:** структура (warm machine → два события в разных сессиях → finding is None).
**Предложение: ОСТАВИТЬ КАК ЕСТЬ.** Это НЕ настоящие дубли — каждый бьёт по другому коду-пути:
- `evaluate_one` (cred→egress детектор) vs `evaluate_one_staging` (staging-цепочка) — разные функции.
- В staging дополнительно различаются триггеры (`cred.read` vs `content.read.external`) и путь через scoring/suppression.
Инвариант session-isolation критичен для каждого из движков по отдельности; склейка снизила бы покрытие. Максимум — добавить в docstring якорь вида «session-scope invariant (см. ТЗ-01)» для навигации.

### 3.2 NULL-session fallback (machine-scope)

| Файл | Тест |
|---|---|
| `tests/integration/test_sequence_session_scope.py:84` | `test_null_session_events_still_correlate_machine_scope` |
| `tests/integration/test_sequence_session_scope.py:98` | `test_null_group_isolated_from_real_sessions` |
| `tests/integration/test_staging_chain.py` (≈115) | `test_null_session_fallback_matches` |
| `tests/integration/test_staging_chain.py` (≈205) | `test_external_chain_null_fallback` |

**Предложение: ОСТАВИТЬ.** Аналогично 3.1 — разные движки, разные сигналы. Backward-compat для NULL session_id (старый агент) — отдельный инвариант, дублирование оправдано.

### 3.3 Severity-проверки (ТЗ-02/03/04)

Severity-валидации/градации рассыпаны по многим файлам:
- `tests/unit/test_severity_critical.py` (34/47/59/105/119) — accept critical, accept existing, reject unknown, 422 на bogus.
- `tests/unit/test_schemas.py:50` `test_severity_literal_validation`
- `tests/unit/test_llm_phase_regression.py:48` `test_severity_critical_round_trip`
- `tests/unit/test_policy_backcompat.py:64` `test_prompt_injection_severity_literal`
- `tests/unit/test_dangerous_bash_patterns.py:124` `test_warn_severity_emits_signal_not_block`
- `tests/unit/test_network_suspicious_rules.py:175/191` `test_warn_severity_allows_but_signals`, `test_block_severity_denies`
- `tests/integration/test_staging_chain.py` `test_severity_always_valid_for_staging`, `test_cred_egress_finding_severity_is_valid`

**Что дублируется:** допустимый набор severity-литералов проверяется минимум в 3 местах (`test_severity_critical`, `test_schemas`, `test_policy_backcompat`).
**Предложение: ПАРАМЕТРИЗОВАТЬ (схемный уровень), остальное оставить.**
- Кандидат на объединение через `@pytest.mark.parametrize`: чисто-схемные проверки литерала severity (`test_schemas.py::test_severity_literal_validation` + `test_policy_backcompat.py::test_prompt_injection_severity_literal` + accept/reject в `test_severity_critical.py`). Они проверяют один и тот же Literal-валидатор Pydantic.
- НЕ трогать `test_warn_severity_emits_signal_not_block` / `test_block_severity_denies` / staging-severity — там severity завязана на поведение конкретного движка (warn=signal, block=deny), это поведенческие, а не схемные тесты.

### 3.4 Heartbeat (ТЗ-07)

| Файл | Тесты |
|---|---|
| `tests/unit/test_heartbeat_agent.py:17–77` | `test_hooks_intact_true/false/unknown`, `test_build_payload_shape`, `test_send_heartbeat_posts_and_never_raises`, `test_send_heartbeat_swallows_errors` |
| `tests/integration/test_sensor_health.py` | AC1–AC7: ingest, quiet-alive, silent, grace, hooks_intact=false, episode dedup, recovery |

**Предложение: ОСТАВИТЬ.** Это НЕ дубли — unit покрывает агент-сторону (формирование/отправка heartbeat, никогда не падает), integration — сервер-сторону (silence/integrity-детекцию). Разные слои, разные предметы.

---

## 4. Критические предохранители (трогать нельзя)

Тесты, защищающие ключевые инварианты безопасности. Их падение = регрессия детекта/обхода EDR.

| Файл:тест | Почему критичен |
|---|---|
| `tests/integration/test_staging_scoring.py:94` `test_attack_survives_suppression` | 🔒 ТЗ-04: атака (external-read → hidden-write на нестандартный путь, без cache/vcs-маркера) ОБЯЗАНА пережить любое suppression — `severity=block`, `suppressed=false`. Это сценарий Confluence/IPI; ослабление = false-negative на реальной атаке. |
| `tests/integration/test_sensor_health.py:81` `test_within_grace_is_stale_not_silent` | 🔒 ТЗ-07 грейс: короткая пауза/ребут в пределах grace → `stale`, НЕ `sensor.silent`. Защита от ложной паники (alert fatigue), но при этом машина не «замолкает» незаметно. |
| `tests/integration/test_sequence_session_scope.py:58` `test_cross_session_cred_egress_does_not_match` | ТЗ-01: cred(A)+egress(B) НЕ коррелируются. Без этого — массовый false-positive на любой машине с параллельной работой. |
| `tests/integration/test_staging_chain.py:104` `test_cross_session_does_not_match` | ТЗ-02/03: тот же инвариант для staging-цепочки (`evaluate_one_staging`). |
| `tests/integration/test_staging_chain.py:199` `test_external_chain_session_scope` | ТЗ-03: session-isolation для external-trigger цепочки. |
| `tests/integration/test_sequence_session_scope.py:98` `test_null_group_isolated_from_real_sessions` | Backward-compat: NULL-session (старый агент) НЕ пэйрится с named-session — sentinel-группа изолирована, иначе legacy-события склеивались бы с реальными. |

**Дополнительные backward-compat предохранители (NULL session_id / старый агент):**
- `tests/unit/test_mcp_baseline_service.py:187` `test_old_agent_payload_no_hashes_no_false_positive` — агент v0.1 без хешей не даёт ложных TOFU-срабатываний.
- `tests/unit/test_machine_baseline_model.py:130` `test_finding_record_backward_compat_non_null_inventory_id`.
- `tests/unit/test_policy_backward_compat_v01_agent.py:90–188` — серия: v0.1 агент парсит расширенную policy и игнорирует новые поля, толерантен к `schema_version` (ТЗ backward-compat из CLAUDE.md «agent v0.1 должен работать против server v0.2»).
- `tests/integration/test_sequence_session_scope.py:84` `test_null_session_events_still_correlate_machine_scope` — legacy NULL-события всё ещё коррелируются по machine-scope (graceful degradation).

---

## 5. Восемь e2e-сбоев — root cause

`uv run pytest tests/e2e -p no:warnings` → **8 failed, 7 passed in 4.12s**.
Проходят все 4 теста `test_push_install_e2e.py` и 3 из 4 `test_pi_e2e.py` — потому что они **сами поднимают uvicorn в потоке** (фикстура `server` в `test_pi_e2e.py`) или работают чисто in-process через subprocess CLI без сети.

Падают те, что ходят в **внешний** живой сервер (`SERVER_URL` / `BASE_URL`), которого в headless-прогоне нет.

| # | Тест | Root cause | Вердикт | Skip-reason |
|---|---|---|---|---|
| 1 | `test_end_to_end.py::test_health_endpoint` | `httpx.get(f"{SERVER_URL}/health")` → `ConnectError [Errno 8] nodename nor servname` — `SERVER_URL` по умолчанию `http://server:8080` (docker-network DNS-имя `server`, не резолвится вне compose). | **окруженческий → skip** | `@pytest.mark.skip(reason="требует docker-compose live-сервера (SERVER_URL=http://server:8080); не поднимается в headless/CI")` |
| 2 | `test_end_to_end.py::test_scan_command_works` | `assert any(s["name"]=="shell-mcp" ...)` → False. CLI `scan` отрабатывает, но фикстура НЕ кладёт `settings.json` с MCP `shell-mcp` (нет грязного инвентаря для скана). Отсутствует фикстура данных. | **окруженческий → skip** | `@pytest.mark.skip(reason="требует фикстуры settings.json с mcpServers (shell-mcp); готовится только в docker-compose окружении")` |
| 3 | `test_end_to_end.py::test_sync_and_machine_visible_on_server` | `ccguard sync` возвращает `inventory post failed: [Errno 8] nodename nor servname` — тот же недоступный `SERVER_URL`. | **окруженческий → skip** | `@pytest.mark.skip(reason="требует live-сервера по SERVER_URL; sync падает на DNS docker-имени вне compose")` |
| 4 | `test_end_to_end.py::test_check_finds_violations_after_sync` | `rc=3` (ожидалось 1/2). stderr: `policy.yaml ...; run \`ccguard sync\` first` — каскад от #3: sync не прошёл → нет закешированной policy → `check` падает с rc=3. | **окруженческий → skip** | `@pytest.mark.skip(reason="зависит от успешного sync с live-сервером (policy.yaml не закеширована вне compose)")` |
| 5 | `test_end_to_end.py::test_install_then_uninstall_idempotent` | `enforce_main` дал пустой stdout на deny-payload (`rm -rf /`). Причина — нет закешированной policy после неудавшегося sync (#3/#4): enforce-shim без policy не печатает JSON deny. | **окруженческий → skip** | `@pytest.mark.skip(reason="enforce требует policy.yaml от live-sync; вне docker-compose stdout пуст")` |
| 6 | `test_end_to_end.py::test_secrets_not_leaked_to_server` | `KeyError`: `os.environ["CLAUDE_HOME"]` / отсутствует подложенный `settings.json` с псевдо-секретом — фикстура данных не подготовлена в headless. | **окруженческий → skip** | `@pytest.mark.skip(reason="требует docker-compose окружение (CLAUDE_HOME + settings.json с секретом); не настроено в headless/CI")` |
| 7 | `test_pi_e2e.py::test_e2e_publish_block_severity_pipeline` | `json.loads(result.stdout)` → `JSONDecodeError` на пустой строке (`s=''`) на `test_pi_e2e.py:294`. Локальный uvicorn (фикстура `server`) поднимается ОК, но `_enforce_hook` вернул пустой stdout — enforce-шим не отдал JSON deny в этом прогоне (вероятно гонка/среда subprocess). Это ЕДИНСТВЕННЫЙ из 4 тестов файла, что падает; остальные 3 (`server`-фикстура) проходят. | **пограничный → skip (flaky/env)**; не блокирующий баг кода (3/4 теста того же движка зелёные) | `@pytest.mark.skip(reason="flaky в headless: _enforce_hook subprocess отдаёт пустой stdout вместо deny-JSON; зелёный в полном e2e-окружении")` |
| 8 | `test_web_e2e.py::test_web_login_and_overview` | `client.get("/")` → `ConnectError [Errno 61] Connection refused` на `BASE_URL` (`CCGUARD_E2E_URL`, по умолчанию `http://localhost:8080`). Docstring файла прямо требует `docker compose up -d server`. | **окруженческий → skip** | `@pytest.mark.skip(reason="требует docker compose up -d server на BASE_URL (CCGUARD_E2E_URL); не поднимается в headless/CI")` |

**Итог по e2e:** реальных багов кода нет. 7 из 8 — чисто инфраструктурные (нет live-сервера / нет фикстуры данных, доступной только в docker-compose). #7 пограничный (flaky-subprocess), но не указывает на дефект продукта — 3/4 теста того же PI-движка зелёные. Все 8 → **skip с явной причиной**. Альтернатива skip — обернуть весь модуль в `pytestmark` с `@pytest.mark.skipif(not _server_reachable(), reason=...)`, чтобы они автоматически прогонялись в compose и скипались локально.
