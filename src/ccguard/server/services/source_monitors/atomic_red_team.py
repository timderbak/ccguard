"""Atomic Red Team monitor — atomic-tests structured by ATT&CK technique.

Atomic Red Team publishes one markdown per ATT&CK technique under
``atomics/T####/T####.md`` in github.com/redcanaryco/atomic-red-team. Each
release ships the changeset. We pull the latest 3 releases on each sweep,
extract the changed atomic markdown files, and emit one SourceItem per file.

Network calls are stdlib-only (urllib) so no new dep. Tests inject a mock
``_fetch_releases`` to stay offline.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Callable
from urllib import request as urlreq

from ccguard.server.services.source_monitors.base import SourceItem

_RELEASES_URL = "https://api.github.com/repos/redcanaryco/atomic-red-team/releases?per_page=3"
_RAW_FILE_FMT = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/{tag}/atomics/{tech}/{tech}.md"


def _http_get_json(url: str, timeout: float = 15.0) -> object:
    req = urlreq.Request(url, headers={"Accept": "application/vnd.github+json"})
    with urlreq.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — trusted host
        return json.loads(resp.read().decode("utf-8"))


def _http_get_text(url: str, timeout: float = 15.0) -> str:
    with urlreq.urlopen(url, timeout=timeout) as resp:  # noqa: S310 — trusted host
        return resp.read().decode("utf-8", errors="replace")


class AtomicRedTeamMonitor:
    name: str = "atomic-red-team"

    def __init__(
        self,
        fetch_releases: Callable[[], object] | None = None,
        fetch_file: Callable[[str], str] | None = None,
    ) -> None:
        self._fetch_releases = fetch_releases or (lambda: _http_get_json(_RELEASES_URL))
        self._fetch_file = fetch_file or _http_get_text

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
            if not (isinstance(published, str) and isinstance(tag, str)):
                continue
            try:
                published_dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
            except ValueError:
                continue
            if published_dt <= since:
                continue
            # GitHub's release body lists changed techniques — best-effort parse.
            body = rel.get("body") or ""
            techs = sorted({t for t in _extract_technique_ids(body)})
            for tech in techs:
                url = _RAW_FILE_FMT.format(tag=tag, tech=tech)
                try:
                    text = self._fetch_file(url)
                except Exception:  # noqa: BLE001 — single file fails, others survive
                    continue
                items.append(
                    SourceItem(
                        url=url,
                        title=f"Atomic Red Team {tag} — {tech}",
                        text=text[:8000],  # cap LLM input
                        published_at=published_dt,
                    )
                )
        return items


def _extract_technique_ids(body: str) -> list[str]:
    import re
    return re.findall(r"\bT\d{4}(?:\.\d{3})?\b", body)
