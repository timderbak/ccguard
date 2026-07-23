"""ProposedSignal storage + approve/reject lifecycle + dynamic-catalog write."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, select

from ccguard.server.db.models import ProposedSignal, SettingsRecord
from ccguard.server.services import proposed_signal_service as svc


def _draft(sig_id: str = "cred.read.browser", pattern: str = r"login\s+data") -> dict:
    return {
        "id": sig_id,
        "attack_technique": "T1555.003",
        "pattern": pattern,
        "description": "Access to browser credential stores",
    }


def test_propose_creates_pending_row(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:
        row = svc.propose(
            s,
            draft=_draft(),
            source_kind="manual",
            source_url=None,
            source_title="manual paste",
            llm_rationale=None,
        )
        assert row.id is not None
        assert row.status == "pending"
        assert row.reviewed_at is None
        assert json.loads(row.draft_json)["id"] == "cred.read.browser"


def test_propose_rejects_invalid_draft_shape(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:
        with pytest.raises(svc.InvalidDraft):
            svc.propose(s, draft={"id": "x"}, source_kind="manual")  # missing keys
        with pytest.raises(svc.InvalidDraft):
            svc.propose(
                s,
                draft={"id": "BAD ID", "attack_technique": "T1", "pattern": ".", "description": "x"},
                source_kind="manual",
            )


def test_approve_validates_regex_and_writes_setting_override(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:
        row = svc.propose(s, draft=_draft(), source_kind="manual")
        approved = svc.approve(s, row.id, reviewed_by="admin")  # type: ignore[arg-type]
        assert approved.status == "approved"
        assert approved.reviewed_by == "admin"
        assert approved.reviewed_at is not None

        override = s.get(SettingsRecord, f"catalog.override.{approved.id_in_draft()}")
        assert override is not None
        payload = json.loads(override.value)
        assert payload["pattern"] == r"login\s+data"


def test_approve_mirrors_into_indicator_store(client: TestClient) -> None:
    """Discovery → store loop: approving a command-signal populates the unified
    ThreatIndicator store, but the mirror is NOT double-served (it's already on
    the wire via the catalog.override the approval wrote)."""
    from ccguard.server.db.models import ThreatIndicator
    from ccguard.server.services.indicator_override_service import (
        MIRROR_SOURCE,
        load_indicator_overrides,
    )

    with Session(client.app.state.engine) as s:
        row = svc.propose(s, draft=_draft(pattern=r"aws_secret_access_key"), source_kind="manual")
        svc.approve(s, row.id, reviewed_by="admin")  # type: ignore[arg-type]

        mirror = s.exec(
            select(ThreatIndicator)
            .where(ThreatIndicator.source == MIRROR_SOURCE)
            .where(ThreatIndicator.value == r"aws_secret_access_key")
        ).first()
        assert mirror is not None
        assert mirror.indicator_type == "dangerous_command"
        assert mirror.status == "active" and mirror.enabled is True

        # NOT double-served: the mirror source is excluded from indicator serving.
        served_ids = {o["id"] for o in load_indicator_overrides(s)}
        assert f"indicator.{mirror.id}" not in served_ids


def test_revert_disables_mirror_and_reapprove_reactivates(client: TestClient) -> None:
    from ccguard.server.db.models import ThreatIndicator
    from ccguard.server.services.indicator_override_service import MIRROR_SOURCE

    def _mirror(s):
        return s.exec(
            select(ThreatIndicator)
            .where(ThreatIndicator.source == MIRROR_SOURCE)
            .where(ThreatIndicator.value == r"login\s+data")
        ).first()

    with Session(client.app.state.engine) as s:
        row = svc.propose(s, draft=_draft(), source_kind="manual")
        svc.approve(s, row.id, reviewed_by="admin")  # type: ignore[arg-type]
        assert _mirror(s).status == "active"

        svc.revert(s, row.id, reviewed_by="admin", reason="noisy")  # type: ignore[arg-type]
        m = _mirror(s)
        assert m.status == "disabled" and m.enabled is False

        # Re-approve after revert reactivates the same mirror row (idempotent).
        row2 = svc.propose(s, draft=_draft(), source_kind="manual")
        svc.approve(s, row2.id, reviewed_by="admin")  # type: ignore[arg-type]
        m2 = _mirror(s)
        assert m2.status == "active" and m2.enabled is True


def test_pi_pattern_approve_does_not_mirror(client: TestClient) -> None:
    """A pi_pattern draft is a PI category, not a dangerous_command — no mirror."""
    from ccguard.server.db.models import ThreatIndicator
    from ccguard.server.services.indicator_override_service import MIRROR_SOURCE

    with Session(client.app.state.engine) as s:
        row = svc.propose(
            s,
            draft={"category": "exfil_url", "pattern": r"evil\.test", "description": "x"},
            source_kind="manual", kind="pi_pattern",
        )
        svc.approve(s, row.id, reviewed_by="admin")  # type: ignore[arg-type]
        mirrors = s.exec(
            select(ThreatIndicator).where(ThreatIndicator.source == MIRROR_SOURCE)
        ).all()
    assert mirrors == []


def test_approve_refuses_invalid_regex(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:
        row = svc.propose(s, draft=_draft(pattern=r"(unclosed"), source_kind="manual")
        with pytest.raises(svc.InvalidDraft):
            svc.approve(s, row.id, reviewed_by="admin")  # type: ignore[arg-type]
        # Row stays pending so admin can edit, not silently flipped to rejected.
        s.refresh(row)
        assert row.status == "pending"


def test_reject_records_reason(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:
        row = svc.propose(s, draft=_draft(), source_kind="manual")
        rejected = svc.reject(s, row.id, reviewed_by="admin", reason="too noisy")  # type: ignore[arg-type]
        assert rejected.status == "rejected"
        assert rejected.rejection_reason == "too noisy"
        # No SettingsRecord override written.
        assert s.get(SettingsRecord, f"catalog.override.cred.read.browser") is None


def test_list_pending_returns_only_pending(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:
        r1 = svc.propose(s, draft=_draft("a.b"), source_kind="manual")
        r2 = svc.propose(s, draft=_draft("c.d"), source_kind="manual")
        svc.reject(s, r2.id, reviewed_by="admin", reason="dup")  # type: ignore[arg-type]
        pending = svc.list_pending(s)
        assert [p.id for p in pending] == [r1.id]


def test_double_approve_is_a_noop(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:
        row = svc.propose(s, draft=_draft(), source_kind="manual")
        svc.approve(s, row.id, reviewed_by="admin")  # type: ignore[arg-type]
        with pytest.raises(svc.NotPending):
            svc.approve(s, row.id, reviewed_by="admin")  # type: ignore[arg-type]


def test_revert_deletes_override_and_marks_reverted(client: TestClient) -> None:
    # P3.3-7 rollback: un-ship a shipped signal that turned out noisy. Deletes
    # the catalog.override.<id> so agents drop it next sync, marks row reverted.
    with Session(client.app.state.engine) as s:
        row = svc.propose(s, draft=_draft(), source_kind="manual")
        svc.approve(s, row.id, reviewed_by="admin")  # type: ignore[arg-type]
        key = f"catalog.override.{row.id_in_draft()}"
        assert s.get(SettingsRecord, key) is not None
        reverted = svc.revert(s, row.id, reviewed_by="admin2", reason="too noisy")  # type: ignore[arg-type]
        assert reverted.status == "reverted"
        assert reverted.reviewed_by == "admin2"
        assert reverted.rejection_reason == "too noisy"
        assert s.get(SettingsRecord, key) is None  # override removed


def test_revert_of_pi_pattern_deletes_pi_override(client: TestClient) -> None:
    pi_draft = {"category": "tool_hijack_v2", "pattern": r"do anything now", "description": "x"}
    with Session(client.app.state.engine) as s:
        row = svc.propose(s, draft=pi_draft, source_kind="manual-pi", kind="pi_pattern")
        svc.approve(s, row.id, reviewed_by="admin")  # type: ignore[arg-type]
        key = "pi.override.tool_hijack_v2"
        assert s.get(SettingsRecord, key) is not None
        svc.revert(s, row.id, reviewed_by="admin", reason="rollback")  # type: ignore[arg-type]
        assert s.get(SettingsRecord, key) is None


def test_revert_requires_approved(client: TestClient) -> None:
    with Session(client.app.state.engine) as s:
        row = svc.propose(s, draft=_draft(), source_kind="manual")
        with pytest.raises(svc.NotApproved):
            svc.revert(s, row.id, reviewed_by="admin")  # type: ignore[arg-type]  # still pending
