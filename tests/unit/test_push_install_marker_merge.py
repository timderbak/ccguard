"""Marker-merge tests for ccguard.agent.push_install._merge_claude_md_blocks."""

from __future__ import annotations

import re

from ccguard.agent.push_install import _merge_claude_md_blocks


def _block(id_: str, content: str) -> dict:
    return {"id": id_, "content": content}


def test_empty_input_single_block() -> None:
    out = _merge_claude_md_blocks("", [_block("security-rules", "Rule body")])
    assert (
        "<!-- ccguard:managed start security-rules -->\nRule body\n"
        "<!-- ccguard:managed end security-rules -->" in out
    )
    assert out.endswith("\n")


def test_preserves_user_content_around_existing_block() -> None:
    existing = (
        "# User Top\nUser line A\n\n"
        "<!-- ccguard:managed start security-rules -->\nOLD\n"
        "<!-- ccguard:managed end security-rules -->\n\n"
        "## User Bottom\nUser line B\n"
    )
    out = _merge_claude_md_blocks(existing, [_block("security-rules", "NEW")])
    assert "# User Top\nUser line A" in out
    assert "## User Bottom\nUser line B" in out
    assert "OLD" not in out
    assert "NEW" in out
    # User bytes verbatim outside the markers:
    assert out.startswith("# User Top\nUser line A\n\n<!-- ccguard:managed start security-rules -->\n")


def test_orphan_block_preserved_d3_no_deletion() -> None:
    """D-3: blocks present in file but absent from policy must remain."""
    existing = (
        "<!-- ccguard:managed start alpha -->\nA-old\n"
        "<!-- ccguard:managed end alpha -->\n\n"
        "<!-- ccguard:managed start beta -->\nB-old\n"
        "<!-- ccguard:managed end beta -->\n"
    )
    out = _merge_claude_md_blocks(existing, [_block("alpha", "A-new")])
    # Updated:
    assert "A-new" in out
    assert "A-old" not in out
    # Orphan still there:
    assert "<!-- ccguard:managed start beta -->" in out
    assert "B-old" in out


def test_appends_new_block_when_none_existed() -> None:
    existing = "# User content\nLine\n"
    out = _merge_claude_md_blocks(existing, [_block("security-rules", "Body")])
    assert out.startswith("# User content\nLine\n")
    assert "<!-- ccguard:managed start security-rules -->\nBody\n<!-- ccguard:managed end security-rules -->" in out
    # Exactly one blank-line separator between user content and new marker
    assert "\n\n<!-- ccguard:managed start security-rules -->" in out


def test_backref_prevents_cross_id_match() -> None:
    """Regex backref on id: end marker MUST match same id as start marker."""
    # Malformed input: start `alpha` end `beta` — should NOT be matched as alpha block.
    existing = (
        "<!-- ccguard:managed start alpha -->\nBAD\n"
        "<!-- ccguard:managed end beta -->\n"
    )
    out = _merge_claude_md_blocks(existing, [_block("alpha", "GOOD")])
    # alpha block was not found → appended; the malformed lines stay as-is
    assert "BAD" in out
    assert "<!-- ccguard:managed end beta -->" in out
    # Plus a new properly-bracketed alpha block:
    assert re.search(
        r"<!-- ccguard:managed start alpha -->\nGOOD\n<!-- ccguard:managed end alpha -->",
        out,
    )


def test_multiple_blocks_in_one_call() -> None:
    out = _merge_claude_md_blocks(
        "",
        [_block("a", "AA"), _block("b", "BB")],
    )
    assert "<!-- ccguard:managed start a -->\nAA\n<!-- ccguard:managed end a -->" in out
    assert "<!-- ccguard:managed start b -->\nBB\n<!-- ccguard:managed end b -->" in out
