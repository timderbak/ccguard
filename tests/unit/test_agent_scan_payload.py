"""Unit tests for the agent-side content scanner pipeline (Plan 03-04 Task 2).

Covers:
1. mask_content redacts JWT + sk-ant + AKIA + ghp + glpat
2. mask_content is idempotent
3. collect_scannable_files walks agents/*.md + skills/*/SKILL.md only
4. collect_scannable_files masks BEFORE base64-encoding (no raw secret bytes
   survive the trip even if decoded back from b64)
5. send_scan_batch short-circuits when /scanner-config returns enabled=false
6. send_scan_batch on POST 500 logs the error but does not raise
"""

from __future__ import annotations

import base64
import logging
from pathlib import Path

import httpx
import pytest

from ccguard.agent.inventory_scan import (
    collect_scannable_files,
    send_scan_batch,
)
from ccguard.agent.masking import mask_content


# -----------------------------------------------------------------------------
# mask_content coverage
# -----------------------------------------------------------------------------


def test_mask_content_redacts_jwt() -> None:
    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    out = mask_content(f"prefix {jwt} suffix")
    assert "eyJh" not in out
    assert "***MASKED***" in out


def test_mask_content_redacts_anthropic_key() -> None:
    out = mask_content("api=sk-ant-abc_def_ghi_jkl_mno_pqr_stu")
    assert "sk-ant-" not in out


def test_mask_content_redacts_aws_key() -> None:
    out = mask_content("AKIAIOSFODNN7EXAMPLE in the middle of a line")
    assert "AKIA" not in out


def test_mask_content_redacts_github_pat() -> None:
    out = mask_content("ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa is a token")
    assert "ghp_" not in out


def test_mask_content_redacts_gitlab_pat() -> None:
    out = mask_content("token=glpat-abcdefghijklmnopqrst something")
    assert "glpat-" not in out


def test_mask_content_idempotent() -> None:
    text = "key=sk-1234567890abcdefghijabcd and AKIAIOSFODNN7EXAMPLE"
    once = mask_content(text)
    twice = mask_content(once)
    assert once == twice


def test_mask_content_does_not_truncate() -> None:
    """Unlike mask_secrets, mask_content preserves the full document."""
    text = "X" * 5000
    out = mask_content(text)
    assert len(out) == 5000


# -----------------------------------------------------------------------------
# collect_scannable_files
# -----------------------------------------------------------------------------


def test_collect_finds_agents_and_skills(tmp_path: Path) -> None:
    home = tmp_path / ".claude"
    (home / "agents").mkdir(parents=True)
    (home / "skills" / "code-review").mkdir(parents=True)
    (home / "skills" / "deploy").mkdir(parents=True)
    (home / "agents" / "researcher.md").write_text("researcher body")
    (home / "agents" / "writer.md").write_text("writer body")
    (home / "skills" / "code-review" / "SKILL.md").write_text("review skill")
    (home / "skills" / "deploy" / "SKILL.md").write_text("deploy skill")
    # Unrelated files MUST be skipped.
    (home / "agents" / "ignore.txt").write_text("not md")
    (home / "skills" / "code-review" / "notes.md").write_text("not SKILL.md")
    (home / "settings.json").write_text("{}")

    items = collect_scannable_files(home)

    paths = sorted(it.file_path for it in items)
    assert len(items) == 4
    assert all(it.scope in ("agent", "skill") for it in items)
    assert any(p.endswith("researcher.md") for p in paths)
    assert any(p.endswith("writer.md") for p in paths)
    assert any(p.endswith("SKILL.md") for p in paths)
    # No txt or unrelated md.
    assert not any("ignore.txt" in p for p in paths)
    assert not any("notes.md" in p for p in paths)


def test_collect_masks_before_base64(tmp_path: Path) -> None:
    """A raw secret in an agent .md must NOT survive the round-trip back from b64."""
    home = tmp_path / ".claude"
    agents = home / "agents"
    agents.mkdir(parents=True)
    secret = "AKIAIOSFODNN7EXAMPLE"
    (agents / "leaky.md").write_text(f"hello {secret} world")

    items = collect_scannable_files(home)
    assert len(items) == 1
    decoded = base64.b64decode(items[0].content_b64).decode("utf-8")
    assert secret not in decoded, "raw AWS key leaked through the masking step"
    assert "***MASKED***" in decoded


def test_collect_handles_missing_dirs(tmp_path: Path) -> None:
    home = tmp_path / ".claude"
    home.mkdir()
    # No agents/ or skills/ — should not raise.
    items = collect_scannable_files(home)
    assert items == []


def test_collect_handles_nonexistent_home(tmp_path: Path) -> None:
    home = tmp_path / "does-not-exist"
    # Returns empty list, never raises.
    items = collect_scannable_files(home)
    assert items == []


# -----------------------------------------------------------------------------
# send_scan_batch
# -----------------------------------------------------------------------------


def _mk_transport(*, enabled: bool, post_status: int = 200, post_body: dict | None = None):
    """Build an httpx MockTransport that responds to /scanner-config and /scan-content."""

    posts: list[httpx.Request] = []
    gets: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/scanner-config":
            gets.append(request)
            return httpx.Response(200, json={"enabled": enabled, "max_file_bytes": 1_048_576, "schema_version": 1})
        if request.url.path == "/api/v1/scan-content":
            posts.append(request)
            return httpx.Response(post_status, json=post_body or {"schema_version": 1, "items": []})
        return httpx.Response(404)

    return httpx.MockTransport(handler), posts, gets


def test_send_scan_batch_short_circuits_when_disabled(tmp_path: Path) -> None:
    from ccguard.schemas.scan import ScanRequestItem

    transport, posts, gets = _mk_transport(enabled=False)
    items = [ScanRequestItem(file_path="a.md", scope="agent", content_b64=base64.b64encode(b"x").decode())]
    result = send_scan_batch(
        server_url="http://server.local",
        token="tok",
        items=items,
        transport=transport,
    )
    assert result == {"skipped": "scanner_disabled"}
    assert len(gets) == 1
    assert len(posts) == 0  # CRITICAL: no /scan-content POST when disabled


def test_send_scan_batch_posts_when_enabled(tmp_path: Path) -> None:
    from ccguard.schemas.scan import ScanRequestItem

    transport, posts, gets = _mk_transport(
        enabled=True,
        post_status=200,
        post_body={
            "schema_version": 1,
            "items": [
                {
                    "file_path": "a.md",
                    "file_hash": "abc" * 16 + "1234",
                    "risk_score": 10,
                    "category": "benign",
                    "severity": "info",
                    "cached": False,
                    "truncated": False,
                    "error": None,
                }
            ],
        },
    )
    items = [ScanRequestItem(file_path="a.md", scope="agent", content_b64=base64.b64encode(b"x").decode())]
    result = send_scan_batch(
        server_url="http://server.local",
        token="tok",
        items=items,
        transport=transport,
    )
    assert len(gets) == 1
    assert len(posts) == 1
    assert posts[0].headers.get("X-CCGuard-Token") == "tok"
    assert "items" in result
    assert len(result["items"]) == 1


def test_send_scan_batch_does_not_raise_on_500(caplog: pytest.LogCaptureFixture) -> None:
    from ccguard.schemas.scan import ScanRequestItem

    transport, _posts, _gets = _mk_transport(enabled=True, post_status=500)
    items = [ScanRequestItem(file_path="a.md", scope="agent", content_b64=base64.b64encode(b"x").decode())]
    with caplog.at_level(logging.ERROR, logger="ccguard.agent.inventory_scan"):
        result = send_scan_batch(
            server_url="http://server.local",
            token="tok",
            items=items,
            transport=transport,
        )
    # Returns an error sentinel, does NOT raise.
    assert "error" in result
    # Logged at ERROR level.
    assert any("scan-content" in r.getMessage().lower() or "500" in r.getMessage() for r in caplog.records)


def test_send_scan_batch_skips_empty_items() -> None:
    """No items → no HTTP call at all."""
    transport, posts, gets = _mk_transport(enabled=True)
    result = send_scan_batch(
        server_url="http://server.local",
        token="tok",
        items=[],
        transport=transport,
    )
    assert result == {"skipped": "no_items"}
    assert len(gets) == 0
    assert len(posts) == 0
