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

_SIGNAL_TO_TECHNIQUE: dict[str, str] = {s.id: s.attack_technique for s in CATALOG}


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


def _explainer_for(rule_id: str, payload_json: str) -> dict[str, Any] | None:
    if rule_id not in (RISK_RULE_ID, SEQUENCE_RULE_ID):
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
    return _sequence_explainer(payload)


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
            "rule_id": f.rule_id,
            "severity": f.severity,
            "discovered_at": f.discovered_at,
            "explainer": explainer,
        }
        if explainer is None:
            row["details"] = _passthrough_payload(payload_json)
        out.append(row)
    return out
