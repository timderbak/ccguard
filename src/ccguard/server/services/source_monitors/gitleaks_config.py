"""gitleaks config monitor — secret-detection regexes as behavioral signals.

``github.com/gitleaks/gitleaks`` ships ``config/gitleaks.toml``: ~180
``[[rules]]`` each with a regex that matches a secret VALUE (AWS key, GitHub
token, Stripe key, ...). Each rule is a candidate ``cred.value.*`` behavioral
signal — the endpoint EDR's current cred catalog keys off secret *paths*
(``~/.aws/credentials``); this adds detection of a live secret *value* appearing
in a command/output.

gitleaks is MIT-licensed, so the derived regex can be redistributed (attribution
kept in ``source_url``). One HTTP GET per sweep; per-rule dedup via a
``…gitleaks.toml#<id>`` fragment URL so each rule is drafted exactly once.
Tests inject ``fetch_config`` to stay offline.
"""
from __future__ import annotations

import tomllib
from collections.abc import Callable
from datetime import UTC, datetime
from urllib import request as urlreq

from ccguard.server.services.source_monitors.base import SourceItem

_CONFIG_URL = "https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml"
# Bound per sweep so one monitor can't flood the daily LLM budget; already-drafted
# rules are cheaply skipped by the discovery dedup on the next sweep.
_MAX_RULES = 200


def _http_get_text(url: str, timeout: float = 15.0) -> str:
    with urlreq.urlopen(url, timeout=timeout) as resp:  # noqa: S310 — trusted host
        return resp.read().decode("utf-8", errors="replace")


class GitleaksConfigMonitor:
    name: str = "gitleaks"

    def __init__(self, fetch_config: Callable[[], str] | None = None) -> None:
        self._fetch_config = fetch_config or (lambda: _http_get_text(_CONFIG_URL))

    def poll(self, since: datetime) -> list[SourceItem]:
        # ``since`` is unused: the gitleaks.toml carries no per-rule timestamps,
        # so re-emitting the full ruleset each sweep is correct — the discovery
        # dedup (SourceFetchLog on the #<id> fragment) guarantees each rule is
        # drafted exactly once, and new upstream rule ids surface as new items.
        try:
            raw = self._fetch_config()
        except Exception:  # noqa: BLE001 — a fetch failure yields nothing, never raises
            return []
        try:
            data = tomllib.loads(raw)
        except (tomllib.TOMLDecodeError, ValueError, TypeError):
            return []
        rules = data.get("rules")
        if not isinstance(rules, list):
            return []
        now = datetime.now(UTC)
        items: list[SourceItem] = []
        for rule in rules[:_MAX_RULES]:
            if not isinstance(rule, dict):
                continue
            rid = rule.get("id")
            regex = rule.get("regex")
            if not (isinstance(rid, str) and rid and isinstance(regex, str) and regex):
                continue
            desc = rule.get("description") if isinstance(rule.get("description"), str) else rid
            kws = rule.get("keywords")
            kw_str = ", ".join(str(k) for k in kws) if isinstance(kws, list) else ""
            text = (
                "Secret-detection rule from gitleaks (MIT-licensed).\n"
                f"id: {rid}\n"
                f"description: {desc}\n"
                f"matches a live credential/secret VALUE via regex: {regex}\n"
                f"keywords: {kw_str}\n\n"
                "Draft a `cred.value.*` behavioral signal (MITRE ATT&CK T1552 "
                "Unsecured Credentials): fires when an AI agent reads, prints, or "
                "transmits a secret of this kind in a tool invocation."
            )
            items.append(
                SourceItem(
                    url=f"{_CONFIG_URL}#{rid}",
                    title=f"gitleaks · {rid}",
                    text=text[:8000],
                    published_at=now,
                )
            )
        return items
