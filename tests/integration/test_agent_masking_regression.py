"""Masking regression tests (Plan 03-06 Task 2).

Locks two invariants:

1. The v0.1 inventory MCP-args masking path produces byte-for-byte identical
   output before and after the Plan 04 refactor that consolidated regex sources
   into ``ccguard.agent.masking``. The expected output is hard-coded as a
   string constant inside the test.
2. ``mask_content`` (the LLM-scanner pre-send mask) strips all 6 secret pattern
   families. After running ``collect_scannable_files`` over a tmp directory the
   base64-decoded items contain NONE of the raw secret bytes.
3. Masking is idempotent — re-running ``mask_content`` on already-masked text
   is a no-op.
"""

from __future__ import annotations

import base64
from pathlib import Path

from ccguard.agent.masking import mask_content, mask_secrets


# Sample inventory-style input mirroring v0.1 MCP-args masking. The expected
# output is the literal byte string the v0.1 code produced; any drift in the
# regex set or replacement token will trip this test.
_V01_INPUT = "ANTHROPIC_API_KEY=sk-ant-abcdefghijklmnop1234"
_V01_EXPECTED_MASKED = "ANTHROPIC_API_KEY=***MASKED***"


def test_v01_inventory_masking_unchanged() -> None:
    """v0.1 inventory mask_secrets path returns byte-for-byte expected output
    after the Plan 04 refactor that moved regexes into agent/masking.py."""
    out = mask_secrets(_V01_INPUT)
    assert out == _V01_EXPECTED_MASKED


def test_masking_idempotent_across_layers() -> None:
    """Applying mask_content twice yields the same result (no chained
    over-masking, no regex collisions with ``***MASKED***`` itself)."""
    text = "secret sk-ant-abcdefghijklmnop1234 and AKIAIOSFODNN7EXAMPLE end"
    once = mask_content(text)
    twice = mask_content(once)
    assert once == twice
    assert "sk-ant-" not in once
    assert "AKIA" not in once

    # Same for the short-form mask_secrets path.
    once_s = mask_secrets(text) or ""
    twice_s = mask_secrets(once_s) or ""
    assert once_s == twice_s


def test_content_scan_masks_before_send(tmp_path: Path) -> None:
    """End-to-end: synthesize a file with 6 secret families, run
    collect_scannable_files, base64-decode each item, assert no raw secret
    bytes remain. Proves T-03-10 mitigation holds through the pre-send
    pipeline."""
    from ccguard.agent.inventory_scan import collect_scannable_files

    secrets_block = "\n".join(
        [
            "OPENAI=sk-abcdef0123456789ABCDEF01",
            "ANTHROPIC=sk-ant-abcdefghijklmnop1234",
            "GITHUB=ghp_abcdefghijklmnopqrstuv12",
            "AWS=AKIAIOSFODNN7EXAMPLE",
            "GOOGLE=AIzaSyAbcDefGhiJklMnoPqrStuVwxYz_-12345",
            "JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        ]
    )
    home = tmp_path / "claude_home"
    agents = home / "agents"
    agents.mkdir(parents=True)
    (agents / "leaky.md").write_text(secrets_block + "\nharmless trailing")

    items = collect_scannable_files(home)
    assert len(items) == 1
    decoded = base64.b64decode(items[0].content_b64)

    for needle in (b"sk-abcdef", b"sk-ant-", b"ghp_abc", b"AKIA", b"AIzaSy", b"eyJh"):
        assert needle not in decoded, f"unmasked secret leaked: {needle!r}"

    # Harmless content survives unmasked.
    assert b"harmless trailing" in decoded
    # Mask token actually appeared.
    assert b"***MASKED***" in decoded
