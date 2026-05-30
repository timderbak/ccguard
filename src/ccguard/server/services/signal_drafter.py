"""LLM signal drafter (Rule Discovery Agent · E2).

Takes a threat-intel text snippet and asks an LLM to draft one catalog
``Signal`` as JSON. Validates shape via
:mod:`ccguard.server.services.proposed_signal_service` before persisting a
``ProposedSignal`` for human review.

Decoupling:

* The LLM call is hidden behind the :class:`SignalDrafterProtocol`. The
  production implementation (:class:`AnthropicSignalDrafter`) wraps the sync
  Anthropic SDK so this module avoids the async dance ScanService does. Tests
  pass a tiny fake (see ``tests/integration/test_signal_drafter.py``) so the
  unit/integration suite never makes a network call.

* Budget gating shares ``daily_call_budget`` + ``LLMCallLog`` with the
  scanner so a single tunable controls all LLM cost on the box.

* Markdown fence recovery: LLMs frequently wrap their JSON in ```` ```json````
  fences even when instructed not to. We strip the outer fence and re-parse
  once before giving up.
"""
from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime
from typing import Any, Protocol

from sqlalchemy import func
from sqlmodel import Session, select

from ccguard.agent.signals.catalog import CATALOG
from ccguard.server.db.models import LLMCallLog, ProposedSignal
from ccguard.server.services import proposed_signal_service
from ccguard.server.services.settings_service import get_setting, parse_budget

log = logging.getLogger(__name__)

_RATIONALE_MAX = 800
_MODEL_TAG = "signal-drafter/claude-sonnet-4-6"


class DrafterError(ValueError):
    """LLM returned an unparseable or invalid draft."""


class BudgetExhausted(RuntimeError):
    """Daily LLM call budget exhausted."""


class SignalDrafterProtocol(Protocol):
    """Sync LLM client surface. ``draft`` returns the raw response text."""

    def draft(self, threat_text: str) -> str: ...


def _utc_day_start(now: datetime) -> datetime:
    return now.replace(hour=0, minute=0, second=0, microsecond=0)


def _check_budget(session: Session, now: datetime) -> None:
    budget = parse_budget(get_setting(session, "daily_call_budget"))
    if budget <= 0:
        raise BudgetExhausted("daily_call_budget is 0 — no LLM calls allowed")
    day_start = _utc_day_start(now)
    used = session.exec(
        select(func.count())  # type: ignore[arg-type]
        .select_from(LLMCallLog)
        .where(LLMCallLog.ts >= day_start)
    ).one()
    used = used[0] if isinstance(used, tuple) else used
    if used >= budget:
        raise BudgetExhausted(
            f"daily LLM budget {budget} exhausted (used={used})"
        )


def _strip_markdown_fence(raw: str) -> str:
    """Recover JSON from ``` ```json ... ``` ``` wrapper if present."""
    s = raw.strip()
    if s.startswith("```"):
        # Drop opening fence (with or without language tag) and trailing fence.
        s = re.sub(r"^```[a-zA-Z0-9_-]*\s*", "", s)
        s = re.sub(r"\s*```$", "", s)
    return s.strip()


def _parse_response(raw: str) -> dict[str, Any]:
    for attempt in (raw, _strip_markdown_fence(raw)):
        try:
            parsed = json.loads(attempt)
        except (ValueError, TypeError):
            continue
        if isinstance(parsed, dict):
            return parsed
    raise DrafterError("LLM response is not a JSON object")


def draft_signal_from_text(
    session: Session,
    *,
    drafter: SignalDrafterProtocol,
    threat_text: str,
    source_kind: str,
    source_url: str | None = None,
    source_title: str | None = None,
) -> ProposedSignal:
    """End-to-end: budget → LLM call → parse → propose. Returns the new row.

    Raises :class:`BudgetExhausted` if today's budget is gone, or
    :class:`DrafterError` if the LLM output cannot be turned into a valid
    draft. On a DrafterError the LLMCallLog entry is still written — the
    operator should see exhausted budget if the LLM keeps misbehaving.
    """
    now = datetime.now(UTC)
    _check_budget(session, now)

    raw = drafter.draft(threat_text)

    # Log the call before parsing so a malformed response still costs against
    # the budget — otherwise a broken drafter could DoS the budget gate.
    session.add(
        LLMCallLog(
            ts=now,
            file_hash="signal-drafter",  # not a file; reuse the field as a label
            model=_MODEL_TAG,
            input_tokens=0,
            output_tokens=0,
            cost_estimate_cents=0,
        )
    )
    session.commit()

    try:
        draft = _parse_response(raw)
    except DrafterError:
        raise

    # Strip "alternates" — they're a separate review surface, not the primary.
    draft.pop("alternates", None)

    rationale = (
        f"LLM drafted from {len(threat_text)} chars of source text. "
        f"Excerpt: {threat_text[:200]}…"
    )[:_RATIONALE_MAX]

    try:
        return proposed_signal_service.propose(
            session,
            draft=draft,
            source_kind=source_kind,
            source_url=source_url,
            source_title=source_title,
            llm_rationale=rationale,
        )
    except proposed_signal_service.InvalidDraft as e:
        raise DrafterError(f"LLM draft failed validation: {e}") from e


# --- Production Anthropic implementation (no test imports here) -----------

_SYSTEM_PROMPT = """You extend ccguard's behavioral-detection signal catalog \
for AI-agent endpoints. Each signal is a regex matched against the lowercased \
combination of a tool's command + file_path. Match the schema EXACTLY: \
{id, attack_technique, pattern, description}. \
- id is kebab-namespaced (e.g. "cred.read.aws"). \
- attack_technique is a MITRE ATT&CK id like "T1552.001" or an ATLAS ref. \
- pattern is a Python re-compile-able regex (matched IGNORECASE). \
- description is one short English line. \
Output STRICT JSON. No prose, no markdown fences. One signal per call — the \
highest-value detection for the given threat."""


def _few_shot_examples() -> str:
    """Pick 4 diverse catalog entries as in-context examples."""
    picks = [s for s in CATALOG if s.id in (
        "cred.read.aws", "egress.network_tool", "persist.cron", "exec.pipe_to_shell"
    )]
    items = [
        {
            "id": s.id,
            "attack_technique": s.attack_technique,
            "pattern": s.pattern.pattern,
            "description": s.description,
        }
        for s in picks
    ]
    return "Examples:\n" + "\n".join(json.dumps(it, ensure_ascii=False) for it in items)


class AnthropicSignalDrafter:
    """Sync wrapper around the Anthropic SDK for E2.

    Kept separate from :class:`ccguard.server.services.llm_client.LLMClient`
    so that the scanner's async + locking semantics don't bleed into the
    much lighter drafter path (one user-initiated POST = one call).
    """

    def __init__(
        self,
        api_key: str,
        model: str = "claude-sonnet-4-6",
        max_tokens: int = 600,
        timeout: float = 30.0,
    ) -> None:
        import anthropic

        self._client = anthropic.Anthropic(api_key=api_key, timeout=timeout)
        self._model = model
        self._max_tokens = max_tokens

    def draft(self, threat_text: str) -> str:
        user_msg = (
            f"{_few_shot_examples()}\n\n"
            f"Draft ONE signal as strict JSON for this threat-intel text:\n"
            f'"""\n{threat_text}\n"""'
        )
        resp = self._client.messages.create(
            model=self._model,
            max_tokens=self._max_tokens,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_msg}],
        )
        # `content` is a list of blocks; first text block carries the JSON.
        for block in resp.content:
            if getattr(block, "type", None) == "text":
                return block.text  # type: ignore[no-any-return]
        return ""
