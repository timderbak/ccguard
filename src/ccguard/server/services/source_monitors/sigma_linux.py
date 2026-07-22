"""Sigma (SigmaHQ) linux rules monitor — behavioral detection rules.

``github.com/SigmaHQ/sigma`` ships detection rules as YAML under
``rules/linux/**`` — each with a ``logsource`` + ``detection`` + ATT&CK tags.
This is the richest external feed for the endpoint EDR's *weakest* catalog:
per-event behavioral signals (``cred.read.*`` / ``exec.*`` / ``persist.*`` /
``impact.*``), already tagged with the technique.

We poll commits touching ``rules/linux`` and emit one SourceItem per changed
``.yml`` rule (the raw_url carries the commit sha, so a rule that changes
re-drafts and an unchanged rule dedups). DRL-1.1 licensed (detection logic;
attribution is kept in ``source_url``). stdlib ``urllib`` only.

Two injectable fetchers keep tests offline: ``fetch_changed_files`` (the
GitHub commits→files dance) and ``fetch_file`` (raw rule text).
"""
from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from urllib import request as urlreq

from ccguard.server.services.source_monitors.base import SourceItem

_COMMITS_URL = "https://api.github.com/repos/SigmaHQ/sigma/commits?path=rules/linux&per_page=15"
_COMMIT_FMT = "https://api.github.com/repos/SigmaHQ/sigma/commits/{sha}"
_MAX_COMMITS = 15
_MAX_FILES = 60  # per-sweep cap so one monitor can't flood the daily LLM budget


def _http_get_json(url: str, timeout: float = 15.0) -> object:
    req = urlreq.Request(url, headers={"Accept": "application/vnd.github+json"})
    with urlreq.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — trusted host
        return json.loads(resp.read().decode("utf-8"))


def _http_get_text(url: str, timeout: float = 15.0) -> str:
    with urlreq.urlopen(url, timeout=timeout) as resp:  # noqa: S310 — trusted host
        return resp.read().decode("utf-8", errors="replace")


def _default_fetch_changed_files() -> list[dict]:
    """Production impl of the commits→files dance: list recent commits touching
    rules/linux, then pull each commit's changed ``.yml`` rule files."""
    commits = _http_get_json(_COMMITS_URL)
    if not isinstance(commits, list):
        return []
    out: list[dict] = []
    for c in commits[:_MAX_COMMITS]:
        if not isinstance(c, dict):
            continue
        sha = c.get("sha")
        date = ((c.get("commit") or {}).get("author") or {}).get("date")
        if not isinstance(sha, str):
            continue
        try:
            detail = _http_get_json(_COMMIT_FMT.format(sha=sha))
        except Exception:  # noqa: BLE001 — one commit fails, others survive
            continue
        files = detail.get("files") if isinstance(detail, dict) else None
        if not isinstance(files, list):
            continue
        for f in files:
            if not isinstance(f, dict):
                continue
            fn = f.get("filename")
            raw = f.get("raw_url")
            if (
                isinstance(fn, str)
                and fn.startswith("rules/linux/")
                and fn.endswith(".yml")
                and isinstance(raw, str)
            ):
                out.append({"filename": fn, "raw_url": raw, "date": date})
    return out


class SigmaLinuxMonitor:
    name: str = "sigma-linux"

    def __init__(
        self,
        fetch_changed_files: Callable[[], list[dict]] | None = None,
        fetch_file: Callable[[str], str] | None = None,
    ) -> None:
        self._fetch_changed_files = fetch_changed_files or _default_fetch_changed_files
        self._fetch_file = fetch_file or _http_get_text

    def poll(self, since: datetime) -> list[SourceItem]:
        try:
            changed = self._fetch_changed_files()
        except Exception:  # noqa: BLE001 — never raise out of a monitor
            return []
        if not isinstance(changed, list):
            return []
        items: list[SourceItem] = []
        for ch in changed[:_MAX_FILES]:
            if not isinstance(ch, dict):
                continue
            raw = ch.get("raw_url")
            fn = ch.get("filename")
            if not (isinstance(raw, str) and isinstance(fn, str)):
                continue
            date = ch.get("date")
            try:
                pub = (
                    datetime.fromisoformat(date.replace("Z", "+00:00"))
                    if isinstance(date, str)
                    else datetime.now(UTC)
                )
            except ValueError:
                pub = datetime.now(UTC)
            if pub <= since:
                continue
            try:
                text = self._fetch_file(raw)
            except Exception:  # noqa: BLE001 — single file fails, others survive
                continue
            items.append(
                SourceItem(
                    url=raw,
                    title=f"Sigma linux · {fn.rsplit('/', 1)[-1]}",
                    text=(
                        "Sigma detection rule (SigmaHQ, DRL-1.1). Draft an "
                        "endpoint behavioral signal (cred/exec/persist/impact) "
                        "with its ATT&CK technique from this rule:\n\n" + text
                    )[:8000],
                    published_at=pub,
                )
            )
        return items
