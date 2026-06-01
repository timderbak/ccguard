"""Server-side rendering helpers for ``prompt_injection.read_file.*`` findings.

Mirrors :mod:`ccguard.server.services.network_findings` and
:mod:`ccguard.server.services.dangerous_findings`. Agent emits findings via
``/api/v1/findings``; the wire schema is fixed (no ``file_path`` field, see
``api/findings.py``). Agent therefore composes ``matched_pattern`` as
``<file_path>::<snippet>`` so the server can split them back out here without
a schema bump.

The card shows:
* title from the agent ("Признаки prompt injection в файле (<category>)")
* file path (parsed out of ``matched_pattern``)
* category (parsed out of rule_id: ``prompt_injection.read_file.<category>``)
* short matched snippet (≤200 chars)
* fixed-template reason / remediation in Russian.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlmodel import Session, select

from ccguard.server.db.models import FindingRecord

_RULE_PREFIX = "prompt_injection.read_file."


def _category_from_rule(rule_id: str) -> str:
    """``prompt_injection.read_file.ignore_previous_instructions`` →
    ``ignore_previous_instructions``. Falls back to the full rule_id when
    the prefix is missing.
    """
    if rule_id.startswith(_RULE_PREFIX):
        return rule_id[len(_RULE_PREFIX) :] or "unknown"
    return rule_id


def _split_path_and_snippet(matched: str) -> tuple[str, str]:
    """Reverse the agent-side ``<file_path>::<snippet>`` composition.

    Tolerates either half being missing — empty file_path is rendered as
    ``"(unknown path)"`` in the card; missing snippet just yields empty.
    """
    if not matched:
        return "", ""
    sep = "::"
    if sep in matched:
        head, _, tail = matched.partition(sep)
        return head, tail
    # Legacy / malformed — treat the whole thing as the snippet.
    return "", matched


# Russian-language fixed copy. Kept here rather than per-rule because the
# Read-PI catalog is one homogenous detector — the variability is only the
# category (which file shape was matched), not the meaning.
_REASON = (
    "В содержимом файла найдены конструкции, типичные для prompt injection: "
    "попытка переопределить системные инструкции, навязать роль или скрыть "
    "вредоносный текст через base64. Claude мог интерпретировать их как ваши "
    "команды."
)
_REMEDIATION = (
    "Не доверяй ответам Claude по этому файлу, пока не убедишься, что "
    "инструкции внутри не повлияли на интерпретацию. При необходимости "
    "удали или экранируй подозрительный блок и попроси Claude перечитать."
)


def _format_card(record: FindingRecord) -> dict[str, Any]:
    try:
        payload = json.loads(record.payload_json) if record.payload_json else {}
    except (ValueError, TypeError):
        payload = {}
    matched = (
        payload.get("matched_value")
        or payload.get("matched_pattern")
        or payload.get("description")
        or ""
    )
    file_path, snippet = _split_path_and_snippet(str(matched))
    if isinstance(snippet, str) and len(snippet) > 200:
        snippet = snippet[:200] + "…"
    title = payload.get("title") or "Признаки prompt injection в файле"
    return {
        "rule_id": record.rule_id,
        "severity": record.severity,
        "machine_id": record.machine_id,
        "discovered_at": record.discovered_at,
        "ts_short": record.discovered_at.strftime("%Y-%m-%d %H:%M"),
        "title": title,
        "category": _category_from_rule(record.rule_id),
        "file_path": file_path or "(unknown path)",
        "snippet": snippet or "",
        "reason": _REASON,
        "remediation": _REMEDIATION,
    }


def recent_pi_read_cards_for_machine(
    session: Session,
    machine_id: str,
    *,
    hours: int = 24,
    limit: int = 30,
) -> list[dict[str, Any]]:
    """Findings rule_id LIKE ``prompt_injection.read_file.%`` for one machine
    within the last ``hours``.
    """
    cutoff = datetime.now(UTC) - timedelta(hours=hours)
    rows = list(
        session.exec(
            select(FindingRecord)
            .where(FindingRecord.machine_id == machine_id)
            .where(FindingRecord.rule_id.like(f"{_RULE_PREFIX}%"))  # type: ignore[attr-defined]
            .where(FindingRecord.discovered_at >= cutoff)
            .order_by(FindingRecord.discovered_at.desc())  # type: ignore[attr-defined]
            .limit(limit)
        )
    )
    return [_format_card(r) for r in rows]
