"""LLM signal drafter: budget gating, JSON parsing, defensive validation."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from ccguard.server.db.models import LLMCallLog, ProposedSignal
from ccguard.server.services import signal_drafter
from ccguard.server.services.settings_service import set_setting


@dataclass
class FakeDrafter:
    """Captures the last threat_text and returns a canned LLM response."""

    response: str
    calls: int = 0
    last_input: str = ""

    def draft(self, threat_text: str) -> str:
        self.calls += 1
        self.last_input = threat_text
        return self.response


_VALID_DRAFT = {
    "id": "cred.read.session_cookie",
    "attack_technique": "T1539",
    "pattern": r"(cookies\.binarycookies|sessiongopher)",
    "description": "Browser session cookie theft",
}


def test_drafts_signal_from_text_creates_pending_row(client: TestClient) -> None:
    fake = FakeDrafter(response=json.dumps(_VALID_DRAFT))
    with Session(client.app.state.engine) as s:
        set_setting(s, "daily_call_budget", "100")
        row = signal_drafter.draft_signal_from_text(
            s,
            drafter=fake,
            threat_text="T1539 web session cookie theft from ~/Library/Cookies/Cookies.binarycookies",
            source_kind="manual-llm",
            source_url="https://attack.mitre.org/techniques/T1539/",
            source_title="MITRE T1539",
        )
        assert row.status == "pending"
        assert json.loads(row.draft_json)["id"] == "cred.read.session_cookie"
        assert row.source_kind == "manual-llm"
        assert row.llm_rationale is not None  # text snippet captured

    assert fake.calls == 1
    assert "T1539" in fake.last_input


def test_llm_call_is_logged_for_budget(client: TestClient) -> None:
    fake = FakeDrafter(response=json.dumps(_VALID_DRAFT))
    with Session(client.app.state.engine) as s:
        set_setting(s, "daily_call_budget", "100")
        signal_drafter.draft_signal_from_text(
            s, drafter=fake, threat_text="x", source_kind="manual-llm"
        )
        rows = list(s.exec(select(LLMCallLog)))
        assert len(rows) == 1
        assert rows[0].model.startswith("signal-drafter")


def test_budget_exhausted_raises(client: TestClient) -> None:
    fake = FakeDrafter(response=json.dumps(_VALID_DRAFT))
    with Session(client.app.state.engine) as s:
        set_setting(s, "daily_call_budget", "1")
        signal_drafter.draft_signal_from_text(
            s, drafter=fake, threat_text="a", source_kind="manual-llm"
        )
        with pytest.raises(signal_drafter.BudgetExhausted):
            signal_drafter.draft_signal_from_text(
                s, drafter=fake, threat_text="b", source_kind="manual-llm"
            )


def test_zero_budget_blocks_first_call(client: TestClient) -> None:
    fake = FakeDrafter(response=json.dumps(_VALID_DRAFT))
    with Session(client.app.state.engine) as s:
        set_setting(s, "daily_call_budget", "0")
        with pytest.raises(signal_drafter.BudgetExhausted):
            signal_drafter.draft_signal_from_text(
                s, drafter=fake, threat_text="a", source_kind="manual-llm"
            )
        assert fake.calls == 0


def test_invalid_json_response_raises_drafter_error(client: TestClient) -> None:
    fake = FakeDrafter(response="this is not json at all")
    with Session(client.app.state.engine) as s:
        set_setting(s, "daily_call_budget", "100")
        with pytest.raises(signal_drafter.DrafterError):
            signal_drafter.draft_signal_from_text(
                s, drafter=fake, threat_text="x", source_kind="manual-llm"
            )


def test_invalid_shape_raises_drafter_error(client: TestClient) -> None:
    # LLM returned valid JSON but missing required keys.
    fake = FakeDrafter(response=json.dumps({"id": "x.y"}))
    with Session(client.app.state.engine) as s:
        set_setting(s, "daily_call_budget", "100")
        with pytest.raises(signal_drafter.DrafterError):
            signal_drafter.draft_signal_from_text(
                s, drafter=fake, threat_text="x", source_kind="manual-llm"
            )


def test_response_wrapped_in_markdown_fence_is_recovered(client: TestClient) -> None:
    """LLMs often wrap JSON in ```json fences despite instruction not to."""
    wrapped = "```json\n" + json.dumps(_VALID_DRAFT) + "\n```"
    fake = FakeDrafter(response=wrapped)
    with Session(client.app.state.engine) as s:
        set_setting(s, "daily_call_budget", "100")
        row = signal_drafter.draft_signal_from_text(
            s, drafter=fake, threat_text="x", source_kind="manual-llm"
        )
        assert json.loads(row.draft_json)["id"] == "cred.read.session_cookie"
