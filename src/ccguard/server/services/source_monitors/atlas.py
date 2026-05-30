"""MITRE ATLAS monitor — AI-specific ATT&CK techniques.

ATLAS is MITRE's adversarial-threat catalog for ML/AI systems. Newer and
smaller than the main ATT&CK matrix but more relevant to ccguard's
threat model. Releases live on github.com/mitre-atlas/atlas-data.

Same shape as MitreAttackMonitor — pull the latest 2 releases, emit one
SourceItem per release. The drafter picks one signal out of the body.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Callable
from urllib import request as urlreq

from ccguard.server.services.source_monitors.base import SourceItem

_RELEASES_URL = "https://api.github.com/repos/mitre-atlas/atlas-data/releases?per_page=2"


def _fetch_default() -> object:
    req = urlreq.Request(_RELEASES_URL, headers={"Accept": "application/vnd.github+json"})
    with urlreq.urlopen(req, timeout=15.0) as resp:  # noqa: S310 — trusted host
        return json.loads(resp.read().decode("utf-8"))


class AtlasMonitor:
    name: str = "atlas"

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
                    title=f"MITRE ATLAS {tag}",
                    text=body[:8000],
                    published_at=published_dt,
                )
            )
        return items
