"""Surface the enforce-block stream for the console.

The agent ships every ``deny`` and ``fail_open`` enforcement decision to the
server as an :class:`AuditRecord` (rule_id + reason + fail_open). Until now no
page rendered it, so anti-tamper ``hard.*`` blocks were invisible — "we block
AND you'll see it" was only half true. This service is the read side for the
machine-detail "Заблокированные действия" section.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlmodel import Session, select

from ccguard.server.db.models import AuditRecord


def list_recent_blocks(
    session: Session,
    machine_id: str,
    *,
    days: int = 7,
    limit: int = 50,
) -> list[AuditRecord]:
    """Recent enforcement events (deny + fail_open) for a machine, newest first.

    ``fail_open`` rows are kept: they mean the enforce hook could NOT evaluate
    (policy unavailable) and let the command through — a real coverage gap the
    operator should see, rendered distinctly from an actual block.
    """
    if limit <= 0:
        return []
    since = datetime.now(UTC) - timedelta(days=days)
    return list(
        session.exec(
            select(AuditRecord)
            .where(AuditRecord.machine_id == machine_id)
            .where(AuditRecord.received_at >= since)
            .order_by(AuditRecord.received_at.desc())  # type: ignore[attr-defined]
            .limit(limit)
        )
    )
