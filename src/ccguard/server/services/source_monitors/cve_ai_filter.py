"""NVD CVE feed filtered to AI/agent-relevant keywords.

NVD provides a JSON 2.0 API. We pull recent CVEs (default 7 days), filter
descriptions by a curated keyword list, and emit one SourceItem per match.
Network injection point mirrors the Atomic Red Team monitor for testability.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Callable
from urllib import parse as urlparse
from urllib import request as urlreq

from ccguard.server.services.source_monitors.base import SourceItem

_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_KEYWORDS = (
    "ai agent", "llm", "mcp", "model context protocol",
    "prompt injection", "claude", "openai", "anthropic",
    "supply chain", "ai assistant", "code assistant",
)


def _fetch_default(since: datetime, until: datetime) -> object:
    params = {
        "pubStartDate": since.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": until.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": "200",
    }
    url = f"{_NVD_BASE}?{urlparse.urlencode(params)}"
    req = urlreq.Request(url, headers={"Accept": "application/json"})
    with urlreq.urlopen(req, timeout=20.0) as resp:  # noqa: S310 — trusted host
        return json.loads(resp.read().decode("utf-8"))


class CVEAIFilterMonitor:
    name: str = "cve"

    def __init__(
        self,
        fetch: Callable[[datetime, datetime], object] | None = None,
        keywords: tuple[str, ...] = _KEYWORDS,
    ) -> None:
        self._fetch = fetch or _fetch_default
        self._keywords = tuple(k.lower() for k in keywords)

    def poll(self, since: datetime) -> list[SourceItem]:
        now = datetime.now(UTC)
        # NVD caps date-range to 120 days; clamp.
        lower = max(since, now - timedelta(days=120))
        try:
            payload = self._fetch(lower, now)
        except Exception:  # noqa: BLE001 — discovery service catches at monitor boundary
            return []
        if not isinstance(payload, dict):
            return []
        vulns = payload.get("vulnerabilities") or []
        if not isinstance(vulns, list):
            return []
        items: list[SourceItem] = []
        for v in vulns:
            cve = (v or {}).get("cve") if isinstance(v, dict) else None
            if not isinstance(cve, dict):
                continue
            cve_id = cve.get("id")
            descriptions = cve.get("descriptions") or []
            en_desc = next(
                (d.get("value", "") for d in descriptions if isinstance(d, dict) and d.get("lang") == "en"),
                "",
            )
            if not isinstance(cve_id, str) or not isinstance(en_desc, str):
                continue
            lowered = en_desc.lower()
            if not any(k in lowered for k in self._keywords):
                continue
            published = cve.get("published") or now.isoformat()
            try:
                published_dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                published_dt = now
            items.append(
                SourceItem(
                    url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    title=cve_id,
                    text=en_desc[:8000],
                    published_at=published_dt,
                )
            )
        return items
