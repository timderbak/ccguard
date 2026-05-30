"""MITRE ATT&CK monitor — latest releases of mitre/cti.

The mitre/cti repository ships STIX JSON for the entire ATT&CK matrix. Each
release adds / updates techniques. We list the most recent 2 releases and
emit one SourceItem per release (a single item containing the release notes
text — the drafter is good enough to pick out one Signal from a list).
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Callable
from urllib import request as urlreq

from ccguard.server.services.source_monitors.base import SourceItem

_RELEASES_URL = "https://api.github.com/repos/mitre/cti/releases?per_page=2"


def _fetch_default() -> object:
    req = urlreq.Request(_RELEASES_URL, headers={"Accept": "application/vnd.github+json"})
    with urlreq.urlopen(req, timeout=15.0) as resp:  # noqa: S310 — trusted host
        return json.loads(resp.read().decode("utf-8"))


class MitreAttackMonitor:
    name: str = "mitre-attack"

    def __init__(self, fetch_releases: Callable[[], object] | None = None) -> None:
        self._fetch_releases = fetch_releases or _fetch_default

    def poll(self, since: datetime) -> list[SourceItem]:
        releases = self._fetch_releases()
        if not isinstance(releases, list):
            return []
        items: list[SourceItem] = []
        for rel in releases:
            if not isinstance(rel, dict):
                continue
            published = rel.get("published_at")
            tag = rel.get("tag_name")
            html_url = rel.get("html_url")
            body = rel.get("body") or ""
            if not (isinstance(published, str) and isinstance(tag, str) and isinstance(html_url, str)):
                continue
            try:
                published_dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
            except ValueError:
                continue
            if published_dt <= since:
                continue
            items.append(
                SourceItem(
                    url=html_url,
                    title=f"MITRE ATT&CK {tag}",
                    text=body[:8000],
                    published_at=published_dt,
                )
            )
        return items
