"""Live smoke test for the LLM scanner against the REAL Anthropic API.

Guards the known strict-schema 400 regression: the ``report_risk`` tool must NOT
use ``strict`` mode, or the live API rejects the request with a 400 (see the
NOTE at ``llm_client.REPORT_RISK_TOOL``). Every other LLM test mocks the SDK and
therefore CANNOT catch this — a mock accepts any schema. This test exercises the
real client end-to-end so the regression surfaces in CI instead of resting on an
unverifiable code comment.

Skips unless ``ANTHROPIC_API_KEY`` is set (CI with a key, or a manual run). It
makes one real, cheap API call.
"""
from __future__ import annotations

import asyncio
import os

import pytest

from ccguard.server.services.llm_client import LLMClient, ScanOutcome


@pytest.mark.skipif(
    not os.environ.get("ANTHROPIC_API_KEY"),
    reason="live LLM smoke — set ANTHROPIC_API_KEY to run",
)
def test_llm_scan_content_live_no_strict_schema_400() -> None:
    client = LLMClient(api_key=os.environ["ANTHROPIC_API_KEY"])
    # A benign file: we don't assert a specific verdict (model output varies) —
    # only that the call SUCCEEDS. If the report_risk tool schema regressed to
    # strict mode, the live API 400s and scan_content raises LLMClientError,
    # failing this test.
    outcome = asyncio.run(
        client.scan_content(
            "This is an ordinary project README describing how to install the CLI.",
            "README.md",
            "read_file",
        )
    )
    assert isinstance(outcome, ScanOutcome)
    assert 0 <= outcome.risk_score <= 100
