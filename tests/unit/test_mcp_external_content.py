"""P4: MCP tool results are tagged as untrusted external content.

A tool named mcp__<server>__<tool> is a third-party MCP server call whose result
is the indirect-prompt-injection delivery vector — it must reach the
initial-access stage via content.read.external.
"""
from __future__ import annotations

import pytest

from ccguard.agent.signals.extractor import extract_signals


@pytest.mark.parametrize(
    "tool",
    [
        "mcp__untrusted__fetch",
        "mcp__github__get_issue",
        "mcp__memory__create_entities",
    ],
)
def test_mcp_tool_emits_external_content(tool):
    assert "content.read.external" in set(extract_signals(tool, {"query": "x"}))


def test_mcp_with_empty_input_still_tags():
    # tool-gated on the name, not the payload shape
    assert "content.read.external" in set(extract_signals("mcp__x__y", {}))


def test_non_mcp_tools_not_tagged():
    # a plain Bash/Read of project source must not get external-content
    assert "content.read.external" not in set(
        extract_signals("Bash", {"command": "ls -la"})
    )
    assert "content.read.external" not in set(
        extract_signals("Read", {"file_path": "/proj/src/app.py"})
    )


def test_mcp_does_not_swallow_other_signals():
    # an MCP tool whose args happen to touch creds still emits both
    fired = set(extract_signals("mcp__x__run", {"command": "cat ~/.aws/credentials"}))
    assert "content.read.external" in fired
    assert "cred.read.aws" in fired
