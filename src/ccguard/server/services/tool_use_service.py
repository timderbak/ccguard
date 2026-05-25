"""Query layer for :class:`ToolUseEvent` (TUA-02).

Two functions, both consumed by PLAN 04 (audit list page) and PLAN 05 (timeline
chart):

* :func:`list_events` — filtered, time-bounded, ordered, limited row fetch +
  total-matched count.
* :func:`timeline_buckets` — dense hourly histogram for chart rendering.

All raw SQL uses bind parameters (T-01-14: SQL-injection mitigation). The
``hour_label`` format ``"HH:MM DD.MM"`` is mandated by ``01-UI-SPEC.md`` and
must stay aligned with the chart axis renderer in PLAN 05.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Literal, TypedDict

from sqlalchemy import func
from sqlalchemy import text as _sql_text
from sqlmodel import Session, select

from ccguard.server.db.models import ToolUseEvent

_TIMEFRAMES: dict[str, int] = {"1h": 1, "24h": 24, "7d": 168}

Timeframe = Literal["1h", "24h", "7d"]


class BucketDict(TypedDict):
    bucket_iso: str
    hour_label: str
    count: int


def _apply_common_filters(
    stmt,
    *,
    machine_id_like: str | None,
    tool_name: str | None,
    decision: str | None,
):
    if machine_id_like:
        stmt = stmt.where(ToolUseEvent.machine_id.like(f"%{machine_id_like}%"))  # type: ignore[union-attr]
    if tool_name:
        stmt = stmt.where(ToolUseEvent.tool_name == tool_name)
    if decision:
        stmt = stmt.where(ToolUseEvent.decision == decision)
    return stmt


def list_events(
    session: Session,
    *,
    machine_id_like: str | None = None,
    tool_name: str | None = None,
    decision: str | None = None,
    timeframe: Timeframe = "24h",
    limit: int = 200,
) -> tuple[list[ToolUseEvent], int]:
    """Filtered ToolUseEvent rows + pre-limit total count.

    ``timeframe`` enforces a ``ts >= now - N hours`` lower bound. ``limit``
    caps the returned row count but the total reflects the full filter match.
    Rows are returned newest-first (``ts DESC``).
    """
    window_hours = _TIMEFRAMES[timeframe]
    cutoff = datetime.now(UTC) - timedelta(hours=window_hours)

    base = select(ToolUseEvent).where(ToolUseEvent.ts >= cutoff)
    base = _apply_common_filters(
        base,
        machine_id_like=machine_id_like,
        tool_name=tool_name,
        decision=decision,
    )

    count_stmt = select(func.count()).select_from(base.subquery())
    total = int(session.exec(count_stmt).one())

    rows_stmt = base.order_by(ToolUseEvent.ts.desc()).limit(limit)  # type: ignore[union-attr]
    rows = list(session.exec(rows_stmt).all())
    return rows, total


def timeline_buckets(
    session: Session,
    *,
    hours: int = 24,
    machine_id_like: str | None = None,
    tool_name: str | None = None,
    decision: str | None = None,
) -> list[BucketDict]:
    """Hourly histogram over the last ``hours`` hours, oldest-first.

    The returned list always has exactly ``hours`` entries — empty hours get
    ``count=0`` so the chart can render without client-side gap-filling.

    SQL uses ``strftime('%Y-%m-%d %H', ts)`` to group by hour. SQLite stores
    timezone-aware datetimes as ISO strings; ``strftime`` operates on the
    string lexicographically which is correct for UTC-anchored ISO values.
    """
    now = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
    start = now - timedelta(hours=hours - 1)

    # Build the parameterized WHERE clause dynamically.
    where_parts = ["ts >= :cutoff"]
    params: dict[str, object] = {"cutoff": start.isoformat()}
    if machine_id_like:
        where_parts.append("machine_id LIKE :mid")
        params["mid"] = f"%{machine_id_like}%"
    if tool_name:
        where_parts.append("tool_name = :tname")
        params["tname"] = tool_name
    if decision:
        where_parts.append("decision = :dec")
        params["dec"] = decision

    sql = (
        "SELECT strftime('%Y-%m-%d %H', ts) AS bucket, COUNT(*) AS cnt "
        "FROM tooluseevent "
        f"WHERE {' AND '.join(where_parts)} "
        "GROUP BY bucket"
    )

    raw = session.exec(_sql_text(sql).bindparams(**params)).all()  # type: ignore[arg-type]
    # Row shape varies between SQLAlchemy/SQLModel — be permissive.
    counts: dict[str, int] = {}
    for row in raw:
        if isinstance(row, tuple):
            bucket_key, cnt = row[0], row[1]
        else:
            bucket_key = row.bucket  # type: ignore[attr-defined]
            cnt = row.cnt  # type: ignore[attr-defined]
        counts[str(bucket_key)] = int(cnt)

    out: list[BucketDict] = []
    for i in range(hours):
        b = start + timedelta(hours=i)
        key = b.strftime("%Y-%m-%d %H")
        out.append(
            BucketDict(
                bucket_iso=b.isoformat(),
                hour_label=b.strftime("%H:%M %d.%m"),
                count=counts.get(key, 0),
            )
        )
    return out
