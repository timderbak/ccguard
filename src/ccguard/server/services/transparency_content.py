"""Editorial transparency content for the coverage drilldown pages.

Curated, human-readable explanations that the DB schema does not carry:

  * ``DETECTOR_DETAIL`` — plain-language description of each behavioral detector
    (what it watches, which signals, the correlation window, what trips it) so a
    SecOps reader understands *how* a technique is actually caught, not just that
    it is. Keyed by ``Detector.detector_key``.
  * ``TECHNIQUE_INCIDENTS`` — real, public incidents that exemplify a technique,
    each with a STABLE source URL (CVE/NVD, arXiv, Wikipedia). Keyed by
    ``Technique.technique_id``. Only well-documented cases are listed; a
    technique with no entry simply renders without the incidents block.

This lives in code (not the DB) on purpose: it is editorial, versioned with the
app, easy to review in a diff, and needs no migration to extend.
"""
from __future__ import annotations


# --------------------------------------------------------------------------- #
# Detector / correlation explanations (keyed by Detector.detector_key)         #
# --------------------------------------------------------------------------- #
DETECTOR_DETAIL: dict[str, dict] = {
    "staging_chain": {
        "summary": (
            "Indicator-of-attack (IOA) correlation: untrusted external content "
            "being read and then driving a write to local disk. This is the "
            "‘staging’ move — an agent fetches a web page / file / MCP response, "
            "and that content makes it write something to disk for a later step "
            "(exfil, persistence, execution)."
        ),
        "watches": ["content.read.external", "fs.write.*"],
        "window": "оба сигнала в пределах одного окна корреляции (по умолчанию ~5 мин)",
        "fires_when": (
            "После чтения недоверенного внешнего контента происходит запись в "
            "файловую систему в том же сеансе и окне — классический staging перед "
            "выносом или закреплением."
        ),
        "why_matters": (
            "Ни ‘прочитать страницу’, ни ‘записать файл’ по отдельности не "
            "подозрительны. Опасна именно последовательность: внешний контент "
            "управляет тем, что агент пишет на диск."
        ),
        "engine": "sequence_service.detect_staging_chain",
    },
    "exfil_sequence": {
        "summary": (
            "IOA-корреляция выноса: чтение секрета/учётных данных, за которым в "
            "окне следует исходящий сетевой канал. Ловит сам ПАТТЕРН кражи, "
            "независимо от конкретного канала."
        ),
        "watches": ["cred.read.*", "recon.cloud_metadata", "egress.*", "cloud.exfil.*"],
        "window": "чтение секрета → egress в пределах окна (по умолчанию ~5 мин)",
        "fires_when": (
            "За чтением ~/.aws/credentials, .ssh/id_*, cloud-metadata и т.п. "
            "следует отправка данных наружу (HTTP, облачный API, новый хост)."
        ),
        "why_matters": (
            "Канал выноса может быть новым (другой домен, другой протокол) — но "
            "если он попадает под стадию exfiltration, цепочка ловится. Детект "
            "привязан к стадии, а не к сигнатуре канала."
        ),
        "engine": "sequence_service.detect_exfil_sequence",
    },
    "external_trigger": {
        "summary": (
            "Маркер initial-access: признак, что цепочку инициировал НЕдоверенный "
            "внешний контент (content.read.external). Сам по себе не алертит — он "
            "повышает приоритет staging-цепочки до настоящего IOA."
        ),
        "watches": ["content.read.external"],
        "window": "флаг на событии; учитывается staging_chain в его окне",
        "fires_when": (
            "Внешний/недоверенный источник (веб-страница, письмо, ответ MCP-сервера) "
            "оказывается отправной точкой последующих действий агента."
        ),
        "why_matters": (
            "Отличает ‘агент сам решил’ от ‘агентом управляет внешний текст’ — "
            "ядро угрозы indirect prompt injection."
        ),
        "engine": "sequence_service (content.read.external flag)",
    },
    "rug_pull_tofu": {
        "summary": (
            "Trust-on-first-use (TOFU) контроль дрейфа: при первой встрече каждый "
            "hook / skill фингерпринтится; алерт срабатывает, когда содержимое или "
            "команда ранее доверенного hook’а меняются. Это классический "
            "‘rug pull’ — плагин обновляется и добавляет вредоносное поведение "
            "ПОСЛЕ того, как ему начали доверять."
        ),
        "watches": ["hook.rug_pull.content", "hook.rug_pull.command"],
        "window": "сравнение с сохранённым базлайном при каждом инвентаре",
        "fires_when": (
            "Fingerprint hook’а расходится с TOFU-базлайном: изменилась команда "
            "запуска или содержимое скрипта."
        ),
        "why_matters": (
            "Supply-chain атака через AI-тулинг чаще всего не во вредоносном "
            "первом релизе, а в тихом обновлении уже доверенного компонента."
        ),
        "engine": "hook_baseline_service.update_and_detect",
    },
    "heartbeat_silent": {
        "summary": (
            "Контроль здоровья сенсора: следит за хартбитами агента и целостностью "
            "его hook’ов. Алертит, когда агент перестаёт отчитываться (тишина "
            "дольше ожидаемого интервала) или когда его PreToolUse/PostToolUse "
            "hooks сняты — то есть сам EDR-сенсор отключили."
        ),
        "watches": ["sensor.silent", "sensor.hooks_removed"],
        "window": "ожидаемый интервал хартбита на машину",
        "fires_when": (
            "Машина молчит дольше своего интервала, либо инвентарь показывает, что "
            "enforce/audit hooks удалены из конфигурации Claude Code."
        ),
        "why_matters": (
            "Если ИБ не видит и не слышит сенсор — атакующий мог его заглушить "
            "первым шагом (defense evasion). Тишина — это сигнал, а не норма."
        ),
        "engine": "sensor_health_service.tick + heartbeat endpoint",
    },
    "slow_chain": {
        "summary": (
            "Детектор low-and-slow: ловит многошаговую атаку, намеренно "
            "растянутую во времени. Где sequence работает на минутах, а chain — "
            "на часах, этот накопитель смотрит на 14-дневный горизонт и считает, "
            "сколько РАЗНЫХ продвинутых стадий kill-chain коснулась машина, "
            "независимо от того, как далеко они разнесены."
        ),
        "watches": [
            "credential-access", "exfiltration", "command-and-control",
            "defense-evasion", "lateral-movement", "persistence",
        ],
        "window": "14 дней (накопление; стадии должны охватывать ≥1 ч, иначе это burst для sequence/chain)",
        "fires_when": (
            "За 14 дней встретились ≥3 РАЗНЫХ продвинутых стадии (например, чтение "
            "креды в понедельник, egress в среду, чистка логов в пятницу), и они "
            "разнесены дольше часа — то есть оконные движки их пропустили."
        ),
        "why_matters": (
            "Грамотный атакующий разносит шаги во времени именно чтобы обойти "
            "оконную корреляцию. Рутинная разработка почти никогда не трогает три "
            "стадии «правой половины» kill-chain за две недели — а атака трогает."
        ),
        "engine": "slow_chain_service.tick",
    },
}


# --------------------------------------------------------------------------- #
# Real public incidents (keyed by Technique.technique_id)                      #
# Stable sources only: NVD/CVE, arXiv, Wikipedia.                              #
# --------------------------------------------------------------------------- #
_PI_GRESHAKE = {
    "title": "Indirect Prompt Injection против LLM-приложений",
    "year": "2023",
    "summary": (
        "Исследователи показали, что недоверенный веб-контент может перехватывать "
        "инструкции LLM-интегрированных приложений (на примере Bing Chat): текст "
        "на странице заставлял ассистента менять поведение и вытягивать данные."
    ),
    "url": "https://arxiv.org/abs/2302.12173",
    "source_name": "arXiv 2302.12173 (Greshake et al.)",
}
_XZ_BACKDOOR = {
    "title": "xz-utils backdoor (CVE-2024-3094)",
    "year": "2024",
    "summary": (
        "В широко используемую зависимость xz/liblzma в течение месяцев "
        "внедрялся бэкдор через доверенного мейнтейнера — почти попал в основные "
        "Linux-дистрибутивы. Эталон тихой supply-chain-компрометации."
    ),
    "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
    "source_name": "NVD · CVE-2024-3094",
}
_CAPITAL_ONE = {
    "title": "Capital One breach (SSRF → cloud-метаданные → вынос)",
    "year": "2019",
    "summary": (
        "Через SSRF атакующий дотянулся до сервиса cloud-метаданных, получил "
        "временные учётные данные роли и выгрузил ~100M записей из S3. Хрестоматийная "
        "цепочка credential-access → exfiltration."
    ),
    "url": "https://en.wikipedia.org/wiki/2019_Capital_One_data_breach",
    "source_name": "Wikipedia · Capital One 2019",
}
_NOTPETYA = {
    "title": "NotPetya (деструктивный вайпер)",
    "year": "2017",
    "summary": (
        "Под видом шифровальщика — необратимое уничтожение данных, распространённое "
        "через скомпрометированное обновление доверенного ПО. Пример стадии impact "
        "(data destruction)."
    ),
    "url": "https://en.wikipedia.org/wiki/Petya_and_NotPetya",
    "source_name": "Wikipedia · NotPetya",
}

TECHNIQUE_INCIDENTS: dict[str, list[dict]] = {
    "AML.T0051": [_PI_GRESHAKE],
    "ASI01": [_PI_GRESHAKE],
    "AML.T0010": [_XZ_BACKDOOR],
    "T1195": [_XZ_BACKDOOR],
    "ASI04": [_XZ_BACKDOOR],
    "T1552": [_CAPITAL_ONE],
    "T1552.001": [_CAPITAL_ONE],
    "T1485": [_NOTPETYA],
}


def detector_detail(detector_key: str) -> dict | None:
    """Authored explanation for one detector, or None if not curated."""
    return DETECTOR_DETAIL.get(detector_key)


def incidents_for(technique_id: str) -> list[dict]:
    """Real public incidents exemplifying a technique (possibly empty)."""
    return TECHNIQUE_INCIDENTS.get(technique_id, [])
