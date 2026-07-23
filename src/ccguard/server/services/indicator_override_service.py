"""Serve active ThreatIndicators to the agent as live catalog overrides.

The 90-row ``threatindicator`` store was seeded (ТЗ-05) to feed the coverage map,
but nothing ever *matched* on it — the detection engines kept their hardcoded
lists, so "add an indicator" did nothing at runtime. This closes that gap for the
one indicator type that is a genuine command SIGNATURE: ``dangerous_command``.

Active + enabled ``dangerous_command`` indicators are converted into signal
``overrides`` — the SAME wire the approved-``ProposedSignal`` path already uses
(:mod:`ccguard.server.api.policy` serves them; the agent's
:func:`ccguard.agent.signals.extractor.extract_signals` merges them into its
catalog). So an indicator added via the seed / admin UI / Path-2 auto-collection
becomes a live agent signal on the next policy sync — no redeploy.

Scope (deliberately narrow, honest): ONLY ``dangerous_command`` is served. The
``sensitive_path`` / ``suspicious_host`` indicators duplicate detection that is
still hardcoded (``signals/catalog.py`` paths, policy ``suspicious_host_rules``),
so serving them as extra signals would double-tag; consolidating those onto the
store is a separate, larger change. ``safe_path`` is an ALLOWLIST and must never
become a detection signal.
"""
from __future__ import annotations

import fnmatch
import re

from sqlmodel import Session, select

from ccguard.server.db.models import ThreatIndicator

# Only this indicator type is a command signature suitable for a text-regex signal.
_SERVED_TYPE = "dangerous_command"
# Signal-id namespace so an indicator override can never collide with (and thus
# silently REPLACE) a baked catalog signal or a ProposedSignal override.
_ID_PREFIX = "indicator."


def _to_pattern(value: str, value_kind: str) -> str | None:
    """Turn an indicator ``(value, value_kind)`` into a regex, or None if unusable.

    ``dangerous_command`` indicators are authored as ``regex`` already; the other
    kinds are converted defensively so the function stays correct if a
    non-regex dangerous_command is ever added.
    """
    value = (value or "").strip()
    if not value:
        return None
    kind = (value_kind or "exact").lower()
    if kind == "regex":
        pattern = value
    elif kind == "glob":
        # fnmatch.translate anchors with \Z and adds a (?s:...) wrapper; we want a
        # substring match against the normalized command text, so strip anchors.
        pattern = fnmatch.translate(value).replace(r"(?s:", "(?:").rstrip(r"\Z").rstrip(")")
        pattern = f"(?:{pattern})"
    elif kind == "prefix":
        pattern = re.escape(value)
    else:  # exact — match the literal token anywhere in the text
        pattern = re.escape(value)
    try:
        re.compile(pattern, re.IGNORECASE)
    except re.error:
        return None
    return pattern


def load_indicator_overrides(session: Session) -> list[dict[str, object]]:
    """Active + enabled ``dangerous_command`` indicators as signal overrides.

    Each override is ``{id, attack_technique, pattern, description}`` — the shape
    the agent extractor requires (all four non-empty strings, else it drops the
    entry). Rows with an uncompilable pattern are skipped. Sorted by id for a
    deterministic ETag.
    """
    stmt = (
        select(ThreatIndicator)
        .where(ThreatIndicator.indicator_type == _SERVED_TYPE)
        .where(ThreatIndicator.status == "active")
        .where(ThreatIndicator.enabled == True)  # noqa: E712 — SQL boolean, not `is`
    )
    out: list[dict[str, object]] = []
    for ind in session.exec(stmt):
        if ind.id is None or not ind.platform_relevant:
            continue
        pattern = _to_pattern(ind.value, ind.value_kind)
        if pattern is None:
            continue
        # All four fields MUST be non-empty strings or the agent drops the override.
        technique = ind.technique or ind.tactic or "n/a"
        description = ind.description or ind.value
        out.append(
            {
                "id": f"{_ID_PREFIX}{ind.id}",
                "attack_technique": technique,
                "pattern": pattern,
                "description": description,
            }
        )
    out.sort(key=lambda x: str(x.get("id", "")))
    return out
