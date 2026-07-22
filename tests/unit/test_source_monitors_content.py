"""Content-catalog source monitors (gitleaks, Sigma) — parse with injected
fetchers, no network."""
from __future__ import annotations

from datetime import UTC, datetime

from ccguard.server.services.source_monitors import default_monitors, sigma_linux
from ccguard.server.services.source_monitors.gitleaks_config import GitleaksConfigMonitor
from ccguard.server.services.source_monitors.sigma_linux import SigmaLinuxMonitor

_GITLEAKS_TOML = """
title = "gitleaks config"

[[rules]]
id = "aws-access-token"
description = "AWS Access Token"
regex = '''AKIA[0-9A-Z]{16}'''
keywords = ["AKIA"]

[[rules]]
id = "github-pat"
description = "GitHub Personal Access Token"
regex = '''ghp_[0-9a-zA-Z]{36}'''
"""


def test_gitleaks_emits_one_item_per_rule_with_fragment_url():
    m = GitleaksConfigMonitor(fetch_config=lambda: _GITLEAKS_TOML)
    items = m.poll(since=datetime(2020, 1, 1, tzinfo=UTC))
    assert len(items) == 2
    urls = {i.url for i in items}
    assert any(u.endswith("#aws-access-token") for u in urls)
    assert any(u.endswith("#github-pat") for u in urls)
    # the drafter prompt steers toward a cred.value.* signal + the right technique
    body = items[0].text
    assert "cred.value" in body
    assert "T1552" in body
    assert "AKIA[0-9A-Z]{16}" in items[0].text or "AKIA[0-9A-Z]{16}" in items[1].text


def test_gitleaks_malformed_toml_yields_nothing():
    m = GitleaksConfigMonitor(fetch_config=lambda: "this is : not = toml [[[")
    assert m.poll(since=datetime(2020, 1, 1, tzinfo=UTC)) == []


def test_gitleaks_fetch_failure_never_raises():
    def _boom() -> str:
        raise OSError("network down")

    m = GitleaksConfigMonitor(fetch_config=_boom)
    assert m.poll(since=datetime(2020, 1, 1, tzinfo=UTC)) == []


def test_sigma_emits_item_per_changed_rule_and_respects_since():
    changed = [
        {
            "filename": "rules/linux/auditd/lnx_auditd_susp_exfil.yml",
            "raw_url": "https://raw.githubusercontent.com/SigmaHQ/sigma/abc123/rules/linux/auditd/lnx_auditd_susp_exfil.yml",
            "date": "2026-06-01T00:00:00Z",
        },
        {
            "filename": "rules/linux/process_creation/lnx_old.yml",
            "raw_url": "https://raw.githubusercontent.com/SigmaHQ/sigma/old000/rules/linux/process_creation/lnx_old.yml",
            "date": "2024-01-01T00:00:00Z",  # older than `since` → filtered out
        },
    ]
    files = {
        changed[0]["raw_url"]: "title: Suspicious Exfil\nlogsource:\n  category: auditd\ntags:\n  - attack.exfiltration",
    }
    m = SigmaLinuxMonitor(
        fetch_changed_files=lambda: changed,
        fetch_file=lambda url: files.get(url, ""),
    )
    items = m.poll(since=datetime(2026, 1, 1, tzinfo=UTC))
    assert len(items) == 1
    assert items[0].url == changed[0]["raw_url"]
    assert "lnx_auditd_susp_exfil.yml" in items[0].title
    assert "Suspicious Exfil" in items[0].text
    assert "Sigma detection rule" in items[0].text  # drafter framing prepended


def test_sigma_default_fetch_filters_to_linux_yml(monkeypatch):
    """The production commits→files dance keeps only rules/linux/*.yml files."""
    commits = [{"sha": "s1", "commit": {"author": {"date": "2026-06-01T00:00:00Z"}}}]
    detail = {
        "files": [
            {"filename": "rules/linux/auditd/a.yml", "raw_url": "https://raw/x/rules/linux/auditd/a.yml"},
            {"filename": "rules/windows/b.yml", "raw_url": "https://raw/x/rules/windows/b.yml"},
            {"filename": "rules/linux/README.md", "raw_url": "https://raw/x/rules/linux/README.md"},
        ]
    }

    def fake_json(url: str, timeout: float = 15.0) -> object:
        return commits if "commits?path" in url else detail

    monkeypatch.setattr(sigma_linux, "_http_get_json", fake_json)
    out = sigma_linux._default_fetch_changed_files()
    assert len(out) == 1
    assert out[0]["filename"] == "rules/linux/auditd/a.yml"


def test_new_content_monitors_registered_in_defaults():
    names = {m.name for m in default_monitors()}
    assert "gitleaks" in names
    assert "sigma-linux" in names
