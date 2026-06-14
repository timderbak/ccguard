"""Explainable finding view-model for the machine detail page (Stage 4a).

Enriches ``FindingRecord`` rows with parsed payloads so the template can show
*why* the engine fired — the SOC-trust prerequisite. Pure: takes already-loaded
records, returns dicts. Tolerant of malformed payloads (degrades to a plain
row rather than 500'ing the page).

The catalog of signal → ATT&CK technique mapping is owned by
``ccguard.agent.signals.catalog``; this module is a read-only consumer.
"""
from __future__ import annotations

import json
from typing import Any, Iterable

from ccguard.agent.signals.catalog import CATALOG
from ccguard.server.services.risk_constants import RISK_RULE_ID
from ccguard.server.services.sequence_constants import SEQUENCE_RULE_ID
from ccguard.server.services.slow_chain_constants import SLOW_CHAIN_RULE_ID
from ccguard.server.services.supply_chain_escalation_service import (
    RULE_ID as AI_TRIGGER_RULE_ID,
)

_SIGNAL_TO_TECHNIQUE: dict[str, str] = {s.id: s.attack_technique for s in CATALOG}

# Human labels for the rule_ids that surface on the overview "active threats"
# panel. Raw rule_ids (``ioa.ai_trigger_escalation``) read as machine noise to a
# vibecoder — give the catch a plain-language name. Matched by exact id first,
# then by prefix; unknown ids fall back to the raw id so nothing is hidden.
_RULE_LABELS_EXACT: dict[str, str] = {
    AI_TRIGGER_RULE_ID: "AI-триггер → эскалация (supply-chain атака)",
    "ioa.fleet_campaign": "Орг-кампания: один компонент на N машинах",
    SLOW_CHAIN_RULE_ID: "Медленная kill-chain (растянута на дни)",
    SEQUENCE_RULE_ID: "Цепочка кражи → вынос",
    RISK_RULE_ID: "Повышенный риск активности",
}
_RULE_LABELS_PREFIX: tuple[tuple[str, str], ...] = (
    ("ioa.chain.", "Kill-chain цепочка"),
    ("ioa.", "Скоррелированная атака"),
    ("mcp.rug_pull", "Подмена MCP-сервера (rug-pull)"),
    ("hook.rug_pull", "Подмена hook (rug-pull)"),
    ("skill.rug_pull", "Подмена skill (rug-pull)"),
    ("agent.rug_pull", "Подмена sub-agent (rug-pull)"),
    ("skill.drift", "Дрейф skill"),
    ("agent.drift", "Дрейф sub-agent"),
    ("hook.content", "Дрейф содержимого hook"),
    ("persist.agent_config", "Правка конфигурации агента (tamper)"),
    ("sensor.", "Security-хук удалён (агент ослеплён)"),
    ("prompt_injection.web_result", "Инъекция в WebFetch-результате"),
    ("prompt_injection.mcp_result", "Инъекция в MCP-результате"),
    ("prompt_injection.read_file", "Инъекция в прочитанном файле"),
    ("prompt_injection.", "Prompt injection"),
    ("llm.scan", "Семантическая инъекция (LLM-вердикт)"),
    ("dangerous.", "Опасная команда"),
)


def humanize_rule(rule_id: str) -> str:
    """Plain-language label for a finding rule_id; raw id as fallback."""
    if rule_id in _RULE_LABELS_EXACT:
        return _RULE_LABELS_EXACT[rule_id]
    for prefix, label in _RULE_LABELS_PREFIX:
        if rule_id.startswith(prefix):
            return label
    return rule_id


def attack_url_for_signal(signal_id: str) -> str | None:
    """Return the MITRE ATT&CK URL for a catalog signal, or ``None`` if unknown.

    ``T1552.001`` → ``.../techniques/T1552/001/``;
    ``T1033`` → ``.../techniques/T1033/``.
    """
    tech = _SIGNAL_TO_TECHNIQUE.get(signal_id)
    if not tech or not tech.startswith("T"):
        return None
    if "." in tech:
        head, sub = tech.split(".", 1)
        return f"https://attack.mitre.org/techniques/{head}/{sub}/"
    return f"https://attack.mitre.org/techniques/{tech}/"


def _signal_card(signal_id: str, weight: float | None = None) -> dict[str, Any]:
    card: dict[str, Any] = {
        "signal_id": signal_id,
        "attack_url": attack_url_for_signal(signal_id),
        "technique": _SIGNAL_TO_TECHNIQUE.get(signal_id),
    }
    if weight is not None:
        card["weight"] = weight
    return card


def _risk_explainer(payload: dict[str, Any]) -> dict[str, Any] | None:
    contributions = payload.get("contributions")
    if not isinstance(contributions, dict):
        return None
    contribs = [
        _signal_card(str(sid), float(w))
        for sid, w in sorted(contributions.items(), key=lambda kv: -float(kv[1]))
    ]
    return {
        "kind": "risk",
        "score": float(payload.get("score", 0.0)),
        "threshold": float(payload.get("threshold", 0.0)),
        "window_hours": float(payload.get("window_hours", 0.0)),
        "half_life_hours": float(payload.get("half_life_hours", 0.0)),
        "event_count": int(payload.get("event_count", 0)),
        "contributions": contribs,
    }


def _sequence_explainer(payload: dict[str, Any]) -> dict[str, Any] | None:
    cred_signal = payload.get("cred_signal")
    egress_signal = payload.get("egress_signal")
    if not cred_signal or not egress_signal:
        return None
    return {
        "kind": "sequence",
        "cred": _signal_card(str(cred_signal)) | {"ts": payload.get("cred_ts")},
        "egress": _signal_card(str(egress_signal)) | {"ts": payload.get("egress_ts")},
        "elapsed_seconds": float(payload.get("elapsed_seconds", 0.0)),
        "window_minutes": float(payload.get("window_minutes", 0.0)),
    }


def _slow_chain_explainer(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Break down an ``ioa.slow_chain`` finding: the distinct advanced kill-chain
    stages a machine touched across the long horizon, each with its own window.
    """
    stages = payload.get("stages")
    if not isinstance(stages, list) or not stages:
        return None
    cards: list[dict[str, Any]] = []
    for st in stages:
        if not isinstance(st, dict):
            continue
        cards.append(
            {
                "stage": str(st.get("stage", "")),
                "first_seen": st.get("first_seen"),
                "last_seen": st.get("last_seen"),
                "count": int(st.get("count", 0) or 0),
                "example_signal": str(st.get("example_signal", "")),
                "attack_url": attack_url_for_signal(str(st.get("example_signal", ""))),
            }
        )
    if not cards:
        return None
    return {
        "kind": "slow_chain",
        "distinct_count": int(payload.get("distinct_count", len(cards)) or 0),
        "min_distinct": int(payload.get("min_distinct", 0) or 0),
        "span_hours": float(payload.get("span_hours", 0.0) or 0.0),
        "lookback_days": float(payload.get("lookback_days", 0.0) or 0.0),
        "stages": cards,
    }


def _ai_trigger_explainer(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Break down ``ioa.ai_trigger_escalation``: the AI-origin TRIGGER (a finding
    rule_id, not a catalog signal) linked to the endpoint ESCALATION on the same
    machine — the cause→effect a classic EDR cannot draw."""
    trigger_rule = payload.get("trigger_rule")
    escalation_signal = payload.get("escalation_signal")
    if not trigger_rule or not escalation_signal:
        return None
    return {
        "kind": "ai_trigger_escalation",
        "trigger_rule": str(trigger_rule),
        "trigger_at": payload.get("trigger_at"),
        # escalation_signal may be a catalog signal (attack_url resolves) OR an
        # ioa.* rule_id (no catalog technique → attack_url None, shown as-is).
        "escalation": _signal_card(str(escalation_signal))
        | {"stage": payload.get("escalation_stage"), "ts": payload.get("escalation_at")},
        "gap_hours": float(payload.get("gap_hours", 0.0) or 0.0),
        "window_hours": float(payload.get("window_hours", 0.0) or 0.0),
        "narrative": str(payload.get("narrative", "")),
    }


def _explainer_for(rule_id: str, payload_json: str) -> dict[str, Any] | None:
    if rule_id not in (
        RISK_RULE_ID,
        SEQUENCE_RULE_ID,
        SLOW_CHAIN_RULE_ID,
        AI_TRIGGER_RULE_ID,
        "ioa.fleet_campaign",
    ):
        return None
    if not payload_json:
        return None
    try:
        payload = json.loads(payload_json)
    except (ValueError, TypeError):
        return None
    if not isinstance(payload, dict):
        return None
    if rule_id == RISK_RULE_ID:
        return _risk_explainer(payload)
    if rule_id == SEQUENCE_RULE_ID:
        return _sequence_explainer(payload)
    if rule_id == AI_TRIGGER_RULE_ID:
        return _ai_trigger_explainer(payload)
    if rule_id == "ioa.fleet_campaign":
        return _fleet_campaign_explainer(payload)
    return _slow_chain_explainer(payload)


def _fleet_campaign_explainer(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Break down ``ioa.fleet_campaign``: one compromised component (MCP/skill/
    hook/agent) seen across N machines — the org-wide supply-chain campaign a
    per-endpoint EDR structurally cannot aggregate."""
    identity = payload.get("identity")
    machines = payload.get("machines")
    if not identity or not isinstance(machines, list):
        return None
    return {
        "kind": "fleet_campaign",
        "identity": identity,
        "family": payload.get("family", ""),
        "machine_count": payload.get("machine_count", len(machines)),
        "machines": machines,
        "spread_hours": payload.get("spread_hours"),
        "window_hours": payload.get("window_hours"),
        "narrative": payload.get("narrative", ""),
    }


def _passthrough_payload(payload_json: str) -> dict[str, Any]:
    """Best-effort decode of Finding.model_dump_json() stored in payload_json.

    The agent's check.py emits Finding(rule_id/severity/title/description/...);
    inventory.py serialises that with ``model_dump_json()``. For findings the
    UI doesn't render via a dedicated explainer (e.g. ``hooks.unknown``) we
    still want description/source/recommendation visible — otherwise the user
    sees a bare ``WARN hooks.unknown`` chip with no actionable context.
    """
    if not payload_json:
        return {}
    try:
        d = json.loads(payload_json)
    except (ValueError, TypeError):
        return {}
    if not isinstance(d, dict):
        return {}
    return {
        "title": d.get("title"),
        "description": d.get("description"),
        "source": d.get("source"),
        "recommendation": d.get("recommendation"),
        "matched_value": d.get("matched_value"),
    }


def build_explainable_findings(findings: Iterable[Any]) -> list[dict[str, Any]]:
    """Enrich finding rows with parsed payloads for the template.

    Each row exposes ``rule_id``, ``severity``, ``discovered_at`` and an
    optional ``explainer`` dict (None for findings the engine doesn't know how
    to break down — anomaly findings, etc).

    Findings without an explainer still carry a ``details`` dict with the
    raw description/source/recommendation copied from the stored
    ``payload_json`` so the template can render a useful card instead of
    just severity + rule_id (см. fix/inventory-findings-ux).
    """
    out: list[dict[str, Any]] = []
    for f in findings:
        payload_json = f.payload_json or ""
        explainer = _explainer_for(f.rule_id, payload_json)
        row: dict[str, Any] = {
            "id": getattr(f, "id", None),
            "rule_id": f.rule_id,
            "severity": f.severity,
            "discovered_at": f.discovered_at,
            "explainer": explainer,
        }
        if explainer is None:
            row["details"] = _passthrough_payload(payload_json)
        out.append(row)
    return out
