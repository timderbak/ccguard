"""ProposedSignal with kind='pi_pattern' — PI Rule Discovery foundation."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session

from ccguard.server.db.models import ProposedSignal, SettingsRecord
from ccguard.server.services import proposed_signal_service as svc


def _pi_draft(category: str = "tool_hijack_dans") -> dict:
    return {
        "category": category,
        "pattern": r"do anything now\s*\(",
        "description": "DANs tool-hijack variant",
    }


def test_propose_pi_pattern_creates_pending_row(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:
        row = svc.propose(
            s, draft=_pi_draft(), source_kind="manual-pi", kind="pi_pattern"
        )
        assert row.kind == "pi_pattern"
        assert row.status == "pending"
        assert json.loads(row.draft_json)["category"] == "tool_hijack_dans"


def test_pi_shape_validation_rejects_signal_shape(client: TestClient) -> None:
    """Submitting signal-shape draft with kind=pi_pattern fails fast."""
    bad = {
        "id": "cred.read.aws",
        "attack_technique": "T1552.001",
        "pattern": ".",
        "description": "x",
    }
    with Session(client.app.state.engine) as s:
        with pytest.raises(svc.InvalidDraft):
            svc.propose(s, draft=bad, source_kind="manual-pi", kind="pi_pattern")


def test_pi_category_must_be_snake_case(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:
        with pytest.raises(svc.InvalidDraft):
            svc.propose(
                s,
                draft={"category": "Bad-Category!", "pattern": ".", "description": "x"},
                source_kind="manual-pi",
                kind="pi_pattern",
            )


def test_approve_pi_pattern_writes_pi_override_key(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:
        row = svc.propose(
            s, draft=_pi_draft(), source_kind="manual-pi", kind="pi_pattern"
        )
        svc.approve(s, row.id, reviewed_by="admin")  # type: ignore[arg-type]
        # PI-specific prefix — not the signal catalog one.
        assert s.get(SettingsRecord, "pi.override.tool_hijack_dans") is not None
        assert s.get(SettingsRecord, "catalog.override.tool_hijack_dans") is None


def test_signal_default_kind_unchanged(client: TestClient) -> None:
    """Legacy callers without kind= keep working (default 'signal')."""
    with Session(client.app.state.engine) as s:
        row = svc.propose(
            s,
            draft={
                "id": "cred.read.foo",
                "attack_technique": "T1552.001",
                "pattern": ".foo",
                "description": "x",
            },
            source_kind="manual",
        )
        assert row.kind == "signal"


def test_approve_pi_refuses_invalid_regex(client: TestClient) -> None:
    bad = {"category": "broken_test", "pattern": "(unclosed", "description": "x"}
    with Session(client.app.state.engine) as s:
        row = svc.propose(s, draft=bad, source_kind="manual-pi", kind="pi_pattern")
        with pytest.raises(svc.InvalidDraft):
            svc.approve(s, row.id, reviewed_by="admin")  # type: ignore[arg-type]
