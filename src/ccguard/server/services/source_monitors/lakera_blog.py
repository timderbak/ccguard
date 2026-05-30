"""Lakera blog monitor — AI-attack post-mortems (RSS).

Lakera publishes incident write-ups and threat research that's often more
actionable than generic ATT&CK additions — concrete commands, paths,
real exploitation chains. We parse the RSS feed with stdlib only (no
feedparser dep).

Stdlib XML parsing has security considerations; we use the
``defusedxml`` lightweight pattern (parse with strict options) — but to
avoid a new dep, fall back to ``xml.etree`` and refuse to follow entity
references implicitly (resolve_entities=False isn't a thing in stdlib;
mitigation: cap body length, never eval).
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Callable
from urllib import request as urlreq
from xml.etree import ElementTree as ET

from ccguard.server.services.source_monitors.base import SourceItem

_RSS_URL = "https://www.lakera.ai/rss.xml"


def _fetch_default() -> str:
    with urlreq.urlopen(_RSS_URL, timeout=15.0) as resp:  # noqa: S310 — trusted host
        return resp.read().decode("utf-8", errors="replace")


class LakeraBlogMonitor:
    name: str = "lakera-blog"

    def __init__(self, fetch_rss: Callable[[], str] | None = None) -> None:
        self._fetch_rss = fetch_rss or _fetch_default

    def poll(self, since: datetime) -> list[SourceItem]:
        try:
            xml = self._fetch_rss()
        except Exception:  # noqa: BLE001 — discovery service catches at monitor boundary
            return []
        try:
            root = ET.fromstring(xml)
        except ET.ParseError:
            return []
        items: list[SourceItem] = []
        # Standard RSS 2.0 layout: <channel><item><title/><link/><description/><pubDate/>
        for item_el in root.iter("item"):
            title = (item_el.findtext("title") or "").strip()
            link = (item_el.findtext("link") or "").strip()
            desc = (item_el.findtext("description") or "").strip()
            pub_raw = (item_el.findtext("pubDate") or "").strip()
            if not (title and link):
                continue
            published_dt = _parse_rfc822(pub_raw) or datetime.now(UTC)
            if published_dt <= since:
                continue
            items.append(
                SourceItem(
                    url=link,
                    title=f"Lakera: {title}",
                    text=desc[:8000],
                    published_at=published_dt,
                )
            )
        return items


def _parse_rfc822(s: str) -> datetime | None:
    """RSS pubDate is RFC-822: ``Tue, 27 May 2026 14:00:00 +0000``."""
    if not s:
        return None
    try:
        from email.utils import parsedate_to_datetime

        dt = parsedate_to_datetime(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt
    except (TypeError, ValueError, IndexError):
        return None
