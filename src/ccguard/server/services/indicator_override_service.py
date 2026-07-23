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

Two indicator types are served, each on the mechanism that fits it:

* ``dangerous_command`` → agent signal ``overrides`` (:func:`load_indicator_overrides`),
  the text-regex catalog wire.
* ``suspicious_host`` → :class:`SuspiciousHostRule` dicts merged into the served
  policy's ``suspicious_host_rules`` (:func:`load_suspicious_host_rules`), the
  URL-aware host mechanism, deduped against the hardcoded rules and emitted at
  ``warn`` (tag, don't block) to stay false-positive-safe.

``sensitive_path`` stays coverage-only (it duplicates the hardcoded
``signals/catalog.py`` path signals; serving it would double-tag reads — a larger
consolidation). ``safe_path`` is an ALLOWLIST and must never become a signal.
Indicators mirrored from an approved ProposedSignal (source ``llm-proposed``) are
excluded from serving here — that pattern is already on the wire via the
ProposedSignal's ``catalog.override.<id>``.
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
# Indicators mirrored from an approved ProposedSignal carry this source. They are
# ALREADY served on the wire via that ProposedSignal's ``catalog.override.<id>``,
# so serving them again here would double-tag the same pattern — exclude them
# from indicator serving (they still populate the store for the unified catalog).
MIRROR_SOURCE = "llm-proposed"


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


def _host_pattern(value: str, value_kind: str) -> tuple[str, str] | None:
    """Turn a suspicious_host indicator into a (pattern, rule_type) for a
    SuspiciousHostRule, or None if unusable. rule_type is ``glob`` or ``regex``.
    """
    value = (value or "").strip()
    if not value:
        return None
    kind = (value_kind or "exact").lower()
    if kind == "regex":
        try:
            re.compile(value, re.IGNORECASE)
        except re.error:
            return None
        return value, "regex"
    if kind == "prefix":
        return f"{value}*", "glob"     # prefix → glob wildcard suffix
    # exact / glob → a glob pattern (an exact host is a literal glob)
    return value, "glob"


def load_suspicious_host_rules(session: Session) -> list[dict[str, object]]:
    """Active ``suspicious_host`` indicators as SuspiciousHostRule dicts.

    Served by merging into the policy's ``suspicious_host_rules`` (deduped) — the
    PROPER host-detection mechanism (URL-aware PreToolUse match), so no double-tag
    with the signal catalog. Emitted at **warn** on purpose: a freshly-added /
    auto-collected host indicator TAGS, it does not block — an operator promotes it
    to block after review (anti-false-positive default). The hardcoded block-tier
    host rules are untouched and win the dedup.
    """
    stmt = (
        select(ThreatIndicator)
        .where(ThreatIndicator.indicator_type == "suspicious_host")
        .where(ThreatIndicator.status == "active")
        .where(ThreatIndicator.enabled == True)  # noqa: E712
    )
    out: list[dict[str, object]] = []
    for ind in session.exec(stmt):
        if ind.id is None or not ind.platform_relevant:
            continue
        pat = _host_pattern(ind.value, ind.value_kind)
        if pat is None:
            continue
        pattern, rule_type = pat
        title = (ind.description or f"Подозрительный хост: {ind.value}")[:256]
        out.append(
            {
                "id": f"indicator/{ind.id}",
                "pattern": pattern,
                "type": rule_type,
                "severity": "warn",
                "title": title,
                "reason": (ind.description or "Индикатор из threat-store (suspicious_host).")[:512],
                "remediation": "Проверь адресата. Если легитимен — добавь в network.allowlist_hosts; "
                "иначе повысь до block.",
            }
        )
    out.sort(key=lambda x: str(x.get("id", "")))
    return out


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
        .where(ThreatIndicator.source != MIRROR_SOURCE)  # served via ProposedSignal already
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
