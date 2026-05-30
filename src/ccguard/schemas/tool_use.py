"""Tool-use audit schemas (TUA-01, TUA-02) — shared between agent flusher and server router.

Privacy contract (T-01-07): this module deliberately defines NO field for the raw
``tool_input`` payload. Only a 16-hex ``fingerprint`` derived by
:func:`ccguard.agent.audit_hook.fingerprint.compute_fingerprint` ever crosses the
agent→server trust boundary. If you find yourself adding a `tool_input` field
here, STOP — that is a privacy regression.

``SCHEMA_VERSION_AUDIT`` is the single source of truth for the audit-batch wire
format version. Both the agent (`ccguard.agent.audit_hook.flusher`) and the
server (`/api/v1/audit` router) import this constant; the agent stamps it into
every outgoing batch and the server echoes its own value back in
:class:`AuditBatchOut` so clients can detect protocol drift.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Final, Literal

from pydantic import Field, field_validator

from ccguard.schemas._base import SchemaBase

SCHEMA_VERSION_AUDIT: Final[str] = "0.2"


class ToolUseEventIn(SchemaBase):
    """One tool invocation as the agent records it post-hook.

    The ``fingerprint`` is a 16-char lowercase hex digest (see
    :func:`ccguard.agent.audit_hook.fingerprint.compute_fingerprint`); the raw
    tool input that produced it is never carried in this schema.
    """

    ts: datetime
    tool_name: str = Field(min_length=1, max_length=128)
    fingerprint: str = Field(pattern=r"^[0-9a-f]{16}$")
    decision: Literal["allow", "deny", "error"]
    result_status: Literal["success", "error", "blocked"]
    # Per-event behavioral signal IDs (see ccguard.agent.signals.catalog).
    # Defaulted so v0.1 agents (which never send this) validate unchanged.
    # These are short ASCII IDs — never raw tool_input — preserving the
    # module's privacy contract. Both the list and each element are bounded
    # to prevent untrusted agents from smuggling large blobs (DoS hardening).
    signals: list[Annotated[str, Field(max_length=64)]] = Field(
        default_factory=list, max_length=64
    )
    # Per-User Attribution: shell user the tool call ran under (USER env or
    # os.getlogin). Optional — v0.1/v0.2 agents don't send this, in which
    # case events are attributed to the machine only.
    actor_user: str | None = Field(default=None, max_length=64)

    @field_validator("ts", mode="after")
    @classmethod
    def _enforce_utc(cls, v: datetime) -> datetime:
        """Reject naive datetimes; normalize tz-aware values to UTC.

        WR-05: ``server.services.tool_use_service.timeline_buckets`` groups by
        ``strftime('%Y-%m-%d %H', ts)`` and treats the stored ISO string as
        UTC-anchored. A future agent shipping ``+03:00`` (or naive local
        time) would silently mis-bucket events. Enforce the UTC contract at
        ingest by rejecting naive datetimes and converting any non-UTC
        offset to UTC before persistence.
        """
        if v.tzinfo is None:
            raise ValueError("ts must be timezone-aware (UTC)")
        if v.utcoffset() != UTC.utcoffset(v):
            return v.astimezone(UTC)
        return v


class AuditBatchIn(SchemaBase):
    """A batch of audit events POSTed by the agent flusher to ``/api/v1/audit``."""

    schema_version: str
    # max_length=128 bounds untrusted input — derive_machine_id emits a 16-hex
    # digest so 128 is generous; cap prevents a misbehaving or malicious agent
    # holding a valid token from POSTing arbitrarily large strings repeated
    # across events (WR-03).
    machine_id: str = Field(min_length=1, max_length=128)
    events: list[ToolUseEventIn] = Field(min_length=1, max_length=200)


class AuditBatchOut(SchemaBase):
    """Server response to :class:`AuditBatchIn`."""

    accepted: bool
    stored: int
    rejected: int
    server_schema_version: str
