"""Source monitors: parsing + filtering with injected fetchers (no network)."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ccguard.server.services.source_monitors.atomic_red_team import (
    AtomicRedTeamMonitor,
)
from ccguard.server.services.source_monitors.cve_ai_filter import CVEAIFilterMonitor
from ccguard.server.services.source_monitors.mitre_attack import MitreAttackMonitor


def test_atomic_red_team_emits_one_item_per_technique_in_release():
    releases = [
        {
            "tag_name": "v2026.05.30",
            "published_at": "2026-05-30T00:00:00Z",
            "body": "New atomic tests for T1555.003 and T1539. Also tweaks to T1041.",
        }
    ]
    files: dict[str, str] = {
        "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/v2026.05.30/atomics/T1555.003/T1555.003.md":
            "## Atomic Test — Chrome Login Data\nrun: cat ~/.../Login\\ Data",
        "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/v2026.05.30/atomics/T1539/T1539.md":
            "## Atomic Test — Cookies binarycookies",
        "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/v2026.05.30/atomics/T1041/T1041.md":
            "## Atomic Test — Exfil over C2",
    }
    m = AtomicRedTeamMonitor(
        fetch_releases=lambda: releases,
        fetch_file=lambda url: files.get(url, ""),
    )
    items = m.poll(since=datetime(2026, 1, 1, tzinfo=UTC))
    assert len(items) == 3
    titles = sorted(i.title for i in items)
    assert "T1041" in titles[0]
    assert "T1539" in titles[1]
    assert "T1555.003" in titles[2]
    assert all(i.text.startswith("## Atomic Test") for i in items)


def test_atomic_red_team_skips_releases_older_than_since():
    releases = [
        {"tag_name": "v1", "published_at": "2024-01-01T00:00:00Z", "body": "T1041"},
    ]
    m = AtomicRedTeamMonitor(
        fetch_releases=lambda: releases,
        fetch_file=lambda url: "x",
    )
    assert m.poll(since=datetime(2025, 1, 1, tzinfo=UTC)) == []


def test_cve_ai_filter_keeps_ai_keywords_only():
    payload = {
        "vulnerabilities": [
            {"cve": {"id": "CVE-2025-1", "published": "2026-05-29T00:00:00",
                     "descriptions": [{"lang": "en", "value": "Prompt injection in foo-mcp leads to RCE."}]}},
            {"cve": {"id": "CVE-2025-2", "published": "2026-05-29T00:00:00",
                     "descriptions": [{"lang": "en", "value": "Buffer overflow in libfoo."}]}},
            {"cve": {"id": "CVE-2025-3", "published": "2026-05-29T00:00:00",
                     "descriptions": [{"lang": "en", "value": "Anthropic SDK leaks API key on error."}]}},
        ]
    }
    m = CVEAIFilterMonitor(fetch=lambda lo, hi: payload)
    items = m.poll(since=datetime.now(UTC) - timedelta(days=7))
    ids = sorted(i.title for i in items)
    assert ids == ["CVE-2025-1", "CVE-2025-3"]


def test_cve_handles_malformed_payload_safely():
    m = CVEAIFilterMonitor(fetch=lambda lo, hi: "garbage")
    assert m.poll(since=datetime.now(UTC) - timedelta(days=7)) == []


def test_mitre_attack_emits_one_per_release():
    releases = [
        {"tag_name": "ATT&CK-v15.1", "published_at": "2026-05-15T00:00:00Z",
         "html_url": "https://github.com/mitre/cti/releases/tag/ATT&CK-v15.1",
         "body": "Adds T1659, updates T1041."},
    ]
    m = MitreAttackMonitor(fetch_releases=lambda: releases)
    items = m.poll(since=datetime(2026, 1, 1, tzinfo=UTC))
    assert len(items) == 1
    assert "v15.1" in items[0].title
    assert "T1659" in items[0].text


def test_mitre_attack_respects_since():
    releases = [
        {"tag_name": "v0", "published_at": "2020-01-01T00:00:00Z",
         "html_url": "x", "body": "y"},
    ]
    m = MitreAttackMonitor(fetch_releases=lambda: releases)
    assert m.poll(since=datetime(2026, 1, 1, tzinfo=UTC)) == []
