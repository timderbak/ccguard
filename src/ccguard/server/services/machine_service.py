"""Machine compliance status + fleet queries."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Literal

ComplianceStatus = Literal["compliant", "policy-old", "stale", "blocking"]

_STALE_THRESHOLD = timedelta(days=7)


def compliance_status(
    *,
    last_seen: datetime,
    agent_policy_revision: int | None,
    current_published_revision: int,
    block_findings_count: int,
) -> ComplianceStatus:
    if block_findings_count > 0:
        return "blocking"
    # Make `last_seen` UTC-aware if naive (SQLite strips tz on roundtrip).
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=UTC)
    age = datetime.now(UTC) - last_seen
    if age > _STALE_THRESHOLD:
        return "stale"
    if agent_policy_revision is None or agent_policy_revision < current_published_revision:
        return "policy-old"
    return "compliant"
