"""IOC host-feed auto-collection (Path-2 · abuse.ch).

The norm-EDR "blocklist auto-updates" channel: fetch known-bad host **IOCs**
(indicators of compromise — a host/IP an attacker uses) from authoritative,
freely-redistributable feeds and INSERT them into the ``ThreatIndicator`` store
as ``suspicious_host`` rows with ``status="pending"`` — never auto-live. An admin
approves (pending → active), after which
:func:`ccguard.server.services.indicator_override_service.load_suspicious_host_rules`
serves them to the served policy as **warn**-tier host rules on the next sync
(no redeploy). "Add a feed → the block-list grows itself."

Deterministic by design — **no LLM**. A host IOC is an exact string; there is
nothing to synthesise, so this path works fully on-prem with the optional LLM
scanner off (unlike the ``source_monitors`` → drafter → ProposedSignal path,
which needs an LLM to turn prose into a regex). A feed that is unreachable or
malformed yields zero inserts and never raises — the existing store stays
intact, which is the correct graceful degradation for an air-gapped install.

Feeds (freely redistributable; attribution kept in ``source_ref``):

* **abuse.ch Feodo Tracker** — botnet C2 IP block-list (Dridex / Emotet /
  QakBot / … command-and-control servers). Exact-IP indicators, so a match is a
  connection to a *known* C2 host — effectively zero false positives.

Idempotent: the ``ThreatIndicator`` composite-unique ``(indicator_type, value,
source)`` means re-fetching the same IP from the same feed is a no-op (checked
before insert, so a re-fetch is counted as ``deduped`` rather than raising an
IntegrityError). Bounded per sweep so one feed can never flood the store.
"""
from __future__ import annotations

import ipaddress
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from urllib import request as urlreq

from sqlmodel import Session, select

from ccguard.server.db.models import ThreatIndicator
from ccguard.server.services._utc import aware_utc
from ccguard.server.services.settings_service import get_setting, set_setting

log = logging.getLogger(__name__)

_LAST_RUN_KEY = "ioc_feed.last_run_at"
# Bound per feed per sweep so a feed that suddenly balloons can't flood the store
# / the admin review queue in one go; the rest arrive on subsequent sweeps.
_MAX_PER_FEED = 500

_FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"


@dataclass(frozen=True)
class HostIOC:
    """One known-bad host indicator emitted by a feed.

    ``value`` is the host/IP (exact match). The rest classify it for the store
    and the coverage map; ``source`` is the feed id and is part of the store's
    composite-unique key (so the same IP from two feeds cross-corroborates).
    """

    value: str
    source: str
    source_ref: str | None
    technique: str
    tactic: str
    weight: float
    description: str


class HostFeed(Protocol):
    """A source of host IOCs. ``name`` is a short kebab-id used in logs."""

    name: str

    def poll(self) -> list[HostIOC]: ...


def _http_get_text(url: str, timeout: float = 15.0) -> str:
    with urlreq.urlopen(url, timeout=timeout) as resp:  # noqa: S310 — trusted host
        return resp.read().decode("utf-8", errors="replace")


class FeodoTrackerFeed:
    """abuse.ch Feodo Tracker botnet-C2 IP block-list.

    The CSV has ``#``-prefixed comment/header lines then rows of
    ``first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware``. We keep the
    IP and the malware family (for the description); everything else is ignored.
    Tests inject ``fetch`` to stay offline.
    """

    name: str = "abuse.ch-feodo"

    def __init__(self, fetch: Callable[[], str] | None = None) -> None:
        self._fetch = fetch or (lambda: _http_get_text(_FEODO_URL))

    def poll(self) -> list[HostIOC]:
        try:
            raw = self._fetch()
        except Exception:  # noqa: BLE001 — a fetch failure yields nothing, never raises
            return []
        out: list[HostIOC] = []
        seen: set[str] = set()
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(",")
            if len(parts) < 2:
                continue
            ip = parts[1].strip().strip('"')
            if not _is_ip(ip) or ip in seen:
                continue
            seen.add(ip)
            malware = parts[5].strip().strip('"') if len(parts) > 5 else ""
            family = malware or "unknown"
            out.append(
                HostIOC(
                    value=ip,
                    source=self.name,
                    source_ref="feodotracker/ipblocklist",
                    technique="T1071.001",
                    tactic="command-and-control",
                    weight=4.0,
                    description=f"abuse.ch Feodo Tracker — {family} botnet C2 IP",
                )
            )
        return out


def _is_ip(value: str) -> bool:
    """True for a syntactically valid IPv4/IPv6 address.

    Feeds are external + untrusted; validating keeps a corrupt line (or an
    injected hostname with odd characters) from ever reaching the store as a
    bogus indicator.
    """
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def default_feeds() -> list[HostFeed]:
    """The production set of host-IOC feeds. Single source of truth shared by the
    scheduled sweep and the manual "run IOC feeds now" admin trigger."""
    return [FeodoTrackerFeed()]


def should_run(session: Session, *, now: datetime, min_interval_hours: float = 23.0) -> bool:
    """True if the daily IOC sweep hasn't run in ``min_interval_hours``.

    Mirrors :func:`discovery_service.should_run` — 23h (not 24) absorbs cron
    drift; a missing / unparseable timestamp means "go".
    """
    raw = get_setting(session, _LAST_RUN_KEY)
    if not raw:
        return True
    try:
        last = datetime.fromisoformat(raw)
    except ValueError:
        return True
    return (now - aware_utc(last)) >= timedelta(hours=min_interval_hours)


def _exists(session: Session, indicator_type: str, value: str, source: str) -> bool:
    stmt = (
        select(ThreatIndicator.id)
        .where(ThreatIndicator.indicator_type == indicator_type)
        .where(ThreatIndicator.value == value)
        .where(ThreatIndicator.source == source)
        .limit(1)
    )
    return session.exec(stmt).first() is not None


def run_ioc_feeds(
    session: Session,
    *,
    feeds: list[HostFeed] | None = None,
    max_per_feed: int = _MAX_PER_FEED,
    now: datetime | None = None,
) -> dict[str, Any]:
    """One IOC sweep: poll each feed, insert new host IOCs as pending indicators.

    Returns a summary dict. Isolation-safe: a feed that raises is caught and
    reported in ``feed_errors``; the rest still run. Idempotent across sweeps via
    the ``(indicator_type, value, source)`` existence check — a re-seen IP counts
    as ``deduped``, not an insert. Rows land ``status="pending"`` so nothing goes
    live until an admin approves it (:mod:`ccguard.server.services.indicator_review_service`).
    """
    feeds = default_feeds() if feeds is None else feeds
    inserted = 0
    deduped = 0
    invalid = 0
    feed_errors: dict[str, str] = {}

    for feed in feeds:
        try:
            iocs = feed.poll()
        except Exception as exc:  # noqa: BLE001 — boundary isolation by design
            feed_errors[feed.name] = str(exc)
            log.warning("ioc_feed: feed %s failed: %s", feed.name, exc)
            continue

        feed_new = 0
        for ioc in iocs:
            if feed_new >= max_per_feed:
                break
            value = (ioc.value or "").strip()
            if not value or " " in value:
                invalid += 1
                continue
            if _exists(session, "suspicious_host", value, ioc.source):
                deduped += 1
                continue
            session.add(
                ThreatIndicator(
                    indicator_type="suspicious_host",
                    value=value,
                    value_kind="exact",
                    source=ioc.source,
                    source_ref=ioc.source_ref,
                    technique=ioc.technique,
                    tactic=ioc.tactic,
                    weight=ioc.weight,
                    platform_relevant=True,
                    status="pending",  # human-gated: never auto-live
                    enabled=True,
                    description=ioc.description,
                )
            )
            inserted += 1
            feed_new += 1
        session.commit()

    set_setting(session, _LAST_RUN_KEY, (now or datetime.now(UTC)).isoformat())

    return {
        "inserted": inserted,
        "deduped": deduped,
        "invalid": invalid,
        "feed_errors": feed_errors,
    }
