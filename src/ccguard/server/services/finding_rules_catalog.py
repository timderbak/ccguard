"""Каталог правил-находок (finding rule_id registry) — витрина для UI.

Контекст: у поведенческих СИГНАЛОВ агента есть единый источник (``CATALOG`` в
``ccguard.agent.signals.catalog``), который витрина ``/signals`` показывает
целиком. У правил-НАХОДОК такого реестра не было: их ``rule_id`` разбросаны по
~15 сервисам как константы и литералы, и увидеть их можно было только дождавшись
срабатывания на ``/findings`` или читая код. Этот модуль — тот самый недостающий
реестр: курируемое зеркало всех ``rule_id``, которые порождают движки.

Две ПРИРОДЫ (поле ``kind``):
  * ``finding``  — записывается как FindingRecord (или уходит в findings-буфер
    агента) и появляется на странице ``/findings``.
  * ``decision`` — решение enforce (PreToolUse allow/deny), пишется только в
    ``audit.log``; это НЕ находка. Включено для полноты и чтобы показать разницу.

Это ДАННЫЕ, не логика детекта: движки не меняются. Реестр курируется вручную по
коду сервисов; при добавлении нового ``rule_id`` — дописать строку сюда.

Динамические семейства (``<...>``) порождают конкретный ``rule_id`` в рантайме:
  * ``ioa.chain.<scenario_key>``  — ключ сценария из ChainScenario
  * ``anomaly.<metric>``          — фиксированный набор из 10 метрик (ниже — все)
  * ``prompt_injection.<category>`` / ``*_result.<category>`` — категория PI-паттерна
  * ``llm.scan.<category>``        — категория вердикта LLM-сканера
  * ``dangerous.<id>`` / ``network.suspicious.<id>`` — id правила из политики
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FindingRule:
    rule_id: str
    severity: str
    kind: str  # "finding" | "decision"
    engine: str
    purpose: str


# key -> (заголовок, пояснение, icon-ключ, kind-по-умолчанию группы)
GROUP_META: dict[str, tuple[str, str, str]] = {
    "correlations": ("Корреляции (IOA)", "движки связывают последовательность событий в kill-chain", "chain"),
    "rug_pull": ("Rug-pull / TOFU baseline", "тихая подмена доверенного компонента (MCP · hook · skill · agent)", "swap"),
    "drift": ("Дрейф конфигурации", "агрегированное изменение inventory между снапшотами", "diff"),
    "sensor": ("Sensor self-protection", "детект по ОТСУТСТВИЮ heartbeat — сенсор замолчал/отключён", "pulse"),
    "anomaly_risk": ("Аномалии и риск", "статистические всплески (>3σ) и decay-взвешенный риск-скор", "spark"),
    "prompt_injection": ("Prompt injection (детект)", "инъекции в прочитанном/внешнем контенте", "inject"),
    "llm_scan": ("LLM-сканер", "семантический вердикт LLM по содержимому", "brain"),
    "static_check": ("Статическая проверка (ccguard check)", "inventory против политики — находки для CI и sync", "check"),
    "enforce_finding": ("Enforce → находка", "решения enforce, которые ТАКЖЕ эмитятся как находки", "shield"),
    "hard_deny": ("Enforce · hard-deny (PREV)", "«очевидное зло» — блок всегда, даже в observe; в audit.log", "stop"),
    "policy_enforce": ("Enforce · политика (PREV)", "deny по политике; решение в audit.log, не находка", "gate"),
}

CATALOG: tuple[FindingRule, ...] = (
    # --- Корреляции (IOA) --------------------------------------------------
    FindingRule("ioa.exfil_sequence", "critical", "finding", "sequence_service",
                "cred.read.* → egress.* в окне одной сессии — прямая кража и вынос секрета."),
    FindingRule("ioa.staging_chain", "info→critical", "finding", "sequence_service",
                "Триггер → скрытая/временная запись (staging) [→ опц. egress]; аддитивный скоринг."),
    FindingRule("ioa.staging_chain.suppressed", "info", "finding", "sequence_service",
                "Тот же staging-паттерн, но запись — build/пакетный кэш или VCS; шум, подавлен."),
    FindingRule("ioa.toxic_flow", "critical", "finding", "sequence_service",
                "Confused-deputy: внешний/недоверенный контент → «оружейный» сток "
                "(правка своего конфига · persistence · разрушение · exfil на sketchy-хост) "
                "властью самого агента. Ловит то, что exfil_sequence (нужен cred-read) и "
                "staging_chain (нужна fs-запись) пропускают."),
    FindingRule("ioa.chain.<scenario_key>", "по политике", "finding", "chain_engine",
                "Data-driven сценарий: последовательность стадий kill-chain завершилась в окне."),
    FindingRule("ioa.slow_chain", "warn", "finding", "slow_chain_service",
                "Низкий-и-медленный: ≥N разных продвинутых стадий, растянутых на дни."),
    FindingRule("ioa.ai_trigger_escalation", "critical", "finding", "supply_chain_escalation_service",
                "МОАТ: AI-триггер (rug-pull/drift/PI) → последующая endpoint-эскалация на машине."),
    FindingRule("ioa.fleet_campaign", "critical", "finding", "fleet_campaign_service",
                "Один скомпрометированный компонент на ≥N машинах флота — орг-уровневая кампания."),
    # --- Rug-pull / TOFU baseline -----------------------------------------
    FindingRule("mcp.rug_pull.description_changed", "critical", "finding", "mcp_baseline_service",
                "Описание MCP изменилось после первой регистрации (описание идёт в LLM как инструкция)."),
    FindingRule("mcp.rug_pull.tools_changed", "critical", "finding", "mcp_baseline_service",
                "Runtime tools/list MCP подменён — имена/описания инструментов изменены."),
    FindingRule("mcp.rug_pull.definition_changed", "warn", "finding", "mcp_baseline_service",
                "Изменились command/args/url запуска MCP (возможная подмена бинарника/endpoint)."),
    FindingRule("hook.rug_pull.content", "block", "finding", "hook_baseline_service",
                "Содержимое скрипта хука изменилось без правки settings.json — та же команда, новый payload."),
    FindingRule("hook.rug_pull.command", "warn", "finding", "hook_baseline_service",
                "Команда хука в том же слоте заменена — ручная правка settings.json или переустановка."),
    FindingRule("hook.new", "warn", "finding", "hook_baseline_service",
                "Появился новый хук после bootstrap (источник не подтверждён как baseline)."),
    FindingRule("hook.removed", "warn", "finding", "hook_baseline_service",
                "Принятый хук исчез из конфигурации — возможное отключение защитного хука."),
    FindingRule("hook.unreadable", "warn", "finding", "hook_baseline_service",
                "Файл шима хука раньше читался, теперь нет — drift-детект для него перестал работать."),
    FindingRule("skill.rug_pull.content", "block", "finding", "skill_baseline_service",
                "Содержимое скилла изменилось, и в директории есть исполняемые скрипты."),
    FindingRule("skill.drift.text", "warn", "finding", "skill_baseline_service",
                "Изменился текст скилла (SKILL.md), скриптов внутри нет — риск ниже."),
    FindingRule("skill.new", "warn", "finding", "skill_baseline_service",
                "Появился новый скилл после bootstrap (источник не подтверждён)."),
    FindingRule("skill.removed", "warn", "finding", "skill_baseline_service",
                "Принятый скилл исчез из конфигурации (supply-chain артефакт удалён)."),
    FindingRule("agent.rug_pull.dangerous", "block", "finding", "agent_baseline_service",
                "Промпт субагента изменился, а у него опасные tools (Bash/Write/Edit/NotebookEdit)."),
    FindingRule("agent.drift.text", "warn", "finding", "agent_baseline_service",
                "Промпт субагента изменился, но опасных tools нет — риск ниже."),
    FindingRule("agent.new", "warn", "finding", "agent_baseline_service",
                "Появился новый субагент после bootstrap (источник не подтверждён)."),
    FindingRule("agent.removed", "warn", "finding", "agent_baseline_service",
                "Принятый субагент исчез из конфигурации (supply-chain артефакт удалён)."),
    # --- Дрейф конфигурации ------------------------------------------------
    FindingRule("persist.agent_config", "warn", "finding", "drift_service",
                "Агрегированный config-drift между двумя inventory-снапшотами — одно drift-событие = один алерт."),
    # --- Sensor self-protection -------------------------------------------
    FindingRule("sensor.silent", "warn→block", "finding", "sensor_health_service",
                "Сенсор перестал слать heartbeat дольше grace-окна; block если хук уже снят."),
    FindingRule("sensor.hooks_removed", "block", "finding", "heartbeat (api)",
                "Агент жив, но сообщил, что его ccguard-хук больше не установлен — подавление защиты."),
    FindingRule("sensor.hook_drift", "warn", "finding", "heartbeat (api)",
                "Хеш конфига хука отклонился от TOFU-baseline (подмена на decoy-shim)."),
    FindingRule("sensor.recovered", "info", "finding", "heartbeat (api)",
                "Сенсор возобновил heartbeat после эпизода тишины — закрытие silence-эпизода."),
    # --- Аномалии и риск ---------------------------------------------------
    FindingRule("anomaly.bash_calls_per_day", "warn", "finding", "anomaly_service",
                "Всплеск числа Bash-вызовов в день (>3σ над скользящим baseline)."),
    FindingRule("anomaly.reads_per_day", "warn", "finding", "anomaly_service",
                "Всплеск числа чтений файлов в день."),
    FindingRule("anomaly.writes_per_day", "warn", "finding", "anomaly_service",
                "Всплеск числа записей файлов в день."),
    FindingRule("anomaly.webfetch_per_day", "warn", "finding", "anomaly_service",
                "Всплеск числа WebFetch в день."),
    FindingRule("anomaly.mcp_calls_per_day", "warn", "finding", "anomaly_service",
                "Всплеск числа MCP-вызовов в день."),
    FindingRule("anomaly.egress_signals_per_day", "warn", "finding", "anomaly_service",
                "Всплеск числа egress-сигналов в день."),
    FindingRule("anomaly.cred_signals_per_day", "warn", "finding", "anomaly_service",
                "Всплеск числа cred-сигналов в день."),
    FindingRule("anomaly.new_mcp_per_week", "warn", "finding", "anomaly_service",
                "Всплеск числа новых MCP-серверов за неделю."),
    FindingRule("anomaly.new_agents_per_week", "warn", "finding", "anomaly_service",
                "Всплеск числа новых субагентов за неделю."),
    FindingRule("anomaly.skill_dir_hash_changes_per_week", "warn", "finding", "anomaly_service",
                "Всплеск числа изменений хешей директорий скиллов за неделю."),
    FindingRule("risk.elevated", "warn", "finding", "risk_service",
                "Decay-взвешенный риск-скор машины превысил порог (только для «тёплых» машин)."),
    # --- Prompt injection (детект-находки) --------------------------------
    FindingRule("prompt_injection.<category>", "по политике", "finding", "prompt_injection_engine",
                "Совпадение PI-паттерна каталога по категории (default severity из политики)."),
    FindingRule("prompt_injection.admin_custom", "по политике", "finding", "prompt_injection_engine",
                "Совпадение admin-заданной кастомной PI-регулярки."),
    FindingRule("prompt_injection.base64_encoded_prompt", "по политике", "finding", "prompt_injection_engine",
                "Base64-энтропийная эвристика — закодированный промпт-инъекция."),
    FindingRule("prompt_injection.llama_guard", "по политике", "finding", "prompt_injection_engine",
                "Вердикт локального LlamaGuard (опц., через Ollama) — небезопасный контент."),
    FindingRule("prompt_injection.llama_guard.model_missing", "info", "finding", "prompt_injection_engine",
                "Диагностика: LlamaGuard включён, но модель недоступна (не блокирует)."),
    FindingRule("prompt_injection.read_file.<category>", "warn", "finding", "read_pi_scan / hook_main",
                "PI-паттерн в теле прочитанного файла (indirect injection), PostToolUse."),
    FindingRule("prompt_injection.web_result.<category>", "warn", "finding", "hook_main (PostToolUse)",
                "PI-паттерн в теле результата WebFetch/WebSearch."),
    FindingRule("prompt_injection.mcp_result.<category>", "warn", "finding", "hook_main (PostToolUse)",
                "PI-паттерн в теле результата MCP-инструмента."),
    FindingRule("prompt_injection.engine_crash", "info", "finding", "enforce (fail-open)",
                "PI-движок упал на скане — fail-open, эмитим info-находку для видимости."),
    # --- LLM-сканер --------------------------------------------------------
    FindingRule("llm.scan.<category>", "warn→critical", "finding", "scan_service",
                "Семантический вердикт LLM по содержимому (risk_score → info/warn/critical)."),
    # --- Статическая проверка (ccguard check) -----------------------------
    FindingRule("permissions.dangerously_skip", "block", "finding", "check",
                "Обнаружен --dangerously-skip-permissions в конфигурации Claude Code."),
    FindingRule("settings.parse_error", "warn", "finding", "check",
                "settings.json не парсится — конфигурация повреждена."),
    FindingRule("env.denylist", "по политике", "finding", "check",
                "Имя env-переменной совпало с denylist-паттерном политики."),
    FindingRule("agents.denylist", "по политике", "finding", "check",
                "Субагент в denylist политики."),
    FindingRule("agents.unknown", "по политике", "finding", "check",
                "Неизвестный субагент при deny_all_unknown."),
    FindingRule("agents.forbidden_tool", "по политике", "finding", "check",
                "У субагента запрещённый инструмент в frontmatter tools: (напр. Bash)."),
    FindingRule("agents.untrusted_hash", "по политике", "finding", "check",
                "Хеш файла субагента не в trusted_file_hashes."),
    FindingRule("skills.untrusted", "по политике", "finding", "check",
                "Скилл не в allowlist и хеш директории не доверен."),
    FindingRule("hooks.unknown", "по политике", "finding", "check",
                "Команда хука не в allowlist_commands при deny_unknown."),
    FindingRule("mcp_servers.denylist", "по политике", "finding", "check",
                "MCP-сервер в denylist политики (статическая проверка inventory)."),
    FindingRule("mcp_servers.unknown", "по политике", "finding", "check",
                "Неизвестный MCP-сервер при deny_all_unknown (статическая проверка)."),
    FindingRule("mcp_servers.url_denylist", "по политике", "finding", "check",
                "URL http/sse-MCP совпал с denylist_url_patterns."),
    # --- Enforce → находка (решение, которое ТАКЖЕ эмитится как находка) ---
    FindingRule("dangerous.<id>", "warn|block", "finding", "enforce → dangerous_findings",
                "Опасная Bash-команда по правилу политики dangerous_patterns."),
    FindingRule("dangerous.destructive/<category>", "warn|block", "finding", "enforce (detect_destructive)",
                "Деструктив по чувствительной цели (delete/overwrite/db)."),
    FindingRule("network.suspicious.<id>", "warn|block", "finding", "enforce → network_findings",
                "Сетевая цель совпала с suspicious_host_rules политики."),
    # --- Enforce · hard-deny (PREV, только audit.log) ---------------------
    FindingRule("hard.reverse_shell", "block (всегда)", "decision", "enforce (hard-deny)",
                "Reverse shell — интерактивный C2-канал. Блок всегда, даже в observe."),
    FindingRule("hard.disable_security", "block (всегда)", "decision", "enforce (hard-deny)",
                "Отключение security-тулинга или ccguard-хука."),
    FindingRule("hard.ssh_authorized_keys_write", "block (всегда)", "decision", "enforce (hard-deny)",
                "Запись в ~/.ssh/authorized_keys — закрепление ключа атакующего."),
    FindingRule("hard.cred_exfil", "block (всегда)", "decision", "enforce (hard-deny)",
                "Чтение секрет-стора + отправка наружу одной командой."),
    FindingRule("hard.fs_wipe", "block (всегда)", "decision", "enforce (hard-deny)",
                "Тотальный wipe корня/HOME (rm -rf / и т.п.)."),
    FindingRule("hard.ccguard_self_tamper", "block (всегда)", "decision", "enforce (hard-deny)",
                "Запись в собственные файлы ccguard (policy/config/shim)."),
    FindingRule("hard.ccguard_disableallhooks", "block (всегда)", "decision", "enforce (hard-deny)",
                "Попытка выставить disableAllHooks: true — глушит все хуки разом."),
    FindingRule("hard.ccguard_hook_tamper", "block (всегда)", "decision", "enforce (hard-deny)",
                "Правка settings.json, убирающая ccguard-хук."),
    # --- Enforce · политика (PREV, только audit.log) ----------------------
    FindingRule("commands.always_deny", "block (deny)", "decision", "enforce",
                "Вшитый always_deny (curl|bash, запись в rc-файлы) — всегда."),
    FindingRule("commands.denylist", "block (deny)", "decision", "enforce",
                "Команда совпала с denylist_patterns политики."),
    FindingRule("commands.allowlist", "block (deny)", "decision", "enforce",
                "Whitelist-режим: команда не в allowlist_patterns."),
    FindingRule("mcp_servers.denylist ", "block (deny)", "decision", "enforce",
                "Runtime-блок вызова инструмента denylist-MCP (mcp__<server>__*)."),
    FindingRule("mcp_servers.unknown ", "block (deny)", "decision", "enforce",
                "Runtime-блок неизвестного MCP при deny_all_unknown."),
    FindingRule("network.denylist", "block (deny)", "decision", "enforce",
                "Сетевая цель (WebFetch/Bash) в denylist_hosts."),
    FindingRule("network.unknown", "block (deny)", "decision", "enforce",
                "Whitelist-режим сети: хост не в allowlist_hosts."),
    FindingRule("prompt_injection.read_file.<category> ", "block (deny)", "decision", "enforce",
                "Opt-in read_pi_block: блок чтения файла с PI ДО того, как его увидит Claude."),
    FindingRule("prompt_injection.engine_error", "block (deny)", "decision", "enforce",
                "PI-движок упал, block_fail_mode=closed — fail-closed deny."),
    FindingRule("policy.unavailable", "block (deny)", "decision", "enforce",
                "Политика недоступна/битая при block_fail_mode=closed — fail-closed deny."),
)


def catalog_grouped() -> list[dict]:
    """Каталог, сгруппированный по source-домену в порядке GROUP_META."""
    # Порядок групп — из GROUP_META; правило → группа по префиксу rule_id + kind.
    def group_of(r: FindingRule) -> str:
        rid = r.rule_id.strip()
        if rid.startswith("ioa."):
            return "correlations"
        if rid.split(".")[0] in {"mcp", "hook", "skill", "agent"} and r.kind == "finding":
            return "rug_pull"
        if rid.startswith("persist."):
            return "drift"
        if rid.startswith("sensor."):
            return "sensor"
        if rid.startswith("anomaly.") or rid.startswith("risk."):
            return "anomaly_risk"
        if rid.startswith("llm.scan"):
            return "llm_scan"
        if rid.startswith("prompt_injection.") and r.kind == "finding":
            return "prompt_injection"
        if r.kind == "decision" and rid.startswith("hard."):
            return "hard_deny"
        if r.kind == "decision":
            return "policy_enforce"
        if rid.startswith(("dangerous.", "network.suspicious")):
            return "enforce_finding"
        return "static_check"

    buckets: dict[str, list[FindingRule]] = {}
    for r in CATALOG:
        buckets.setdefault(group_of(r), []).append(r)

    out: list[dict] = []
    for key, (label, desc, icon) in GROUP_META.items():
        rows = buckets.get(key, [])
        if not rows:
            continue
        out.append({
            "key": key,
            "label": label,
            "desc": desc,
            "icon": icon,
            "kind": rows[0].kind,
            "count": len(rows),
            "rows": [{"rule_id": r.rule_id.strip(), "severity": r.severity,
                      "kind": r.kind, "engine": r.engine, "purpose": r.purpose}
                     for r in rows],
        })
    return out
