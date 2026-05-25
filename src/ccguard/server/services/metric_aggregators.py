"""Phase 2 metric aggregators (Plan 02-02).

Four pure-function series builders that produce the 14-day daily time series
consumed by both the matrix-page sparklines (UI plan 02-05) and the
baseline-statistics computation (``baseline_service``).

All four functions share the same signature:

    fn(session: Session, machine_id: str, anchor_date: date | None = None)
        -> list[tuple[date, int]]

They return exactly 14 ``(date, count)`` tuples, oldest first, anchor last. Days
with no activity are zero-padded so the UI can render without client-side gap
filling, and so :func:`baseline_service.compute_baseline` can treat the series
as a fixed-length window.

Implementation notes:

* ``bash_calls_per_day_series`` issues a single grouped SQL query against
  ``tooluseevent`` — cheapest path.
* The three inventory-diff aggregators load each machine's
  ``InventorySnapshot`` rows once, parse ``payload_json``, then apply the
  rolling-week logic in pure Python. This keeps total cost ``O(snapshots)``
  rather than ``O(14 × snapshots)``.

Rolling-week semantics (locked in plan 02-CONTEXT.md):

For each of the 14 daily anchor dates ``d``:

1. ``window``  = snapshots whose ``received_at.date()`` is in ``(d - 7, d]``.
2. ``baseline`` = snapshots whose ``received_at.date()`` is in
   ``(d - 14, d - 7]`` (strictly older than the window).
3. ``new = items_at(latest_in_window) - items_anywhere_in(baseline)``.
4. If ``baseline`` is empty, count is 0 (no baseline → no signal, prevents
   initial-population from being flagged as anomalous).

The skill-dir-hash variant compares (name, dir_hash) instead of presence-only,
and counts skills whose dir_hash differs between the latest baseline snapshot
and the latest window snapshot.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import text as _sql
from sqlmodel import Session

from .anomaly_constants import (
    AGENT_HASH_FIELD,
    AGENT_NAME_FIELD,
    MCP_NAME_FIELD,
    SKILL_HASH_FIELD,
    SKILL_NAME_FIELD,
)

log = logging.getLogger(__name__)

WINDOW_DAYS: int = 14
ROLLING_WEEK_DAYS: int = 7


def _anchor_dates(anchor_date: date) -> list[date]:
    """Return the 14 anchor dates in ascending order, ending at ``anchor_date``."""
    return [anchor_date - timedelta(days=WINDOW_DAYS - 1 - i) for i in range(WINDOW_DAYS)]


def _default_anchor() -> date:
    return datetime.now(UTC).date()


# ---------------------------------------------------------------------------
# bash_calls_per_day_series
# ---------------------------------------------------------------------------


def bash_calls_per_day_series(
    session: Session,
    machine_id: str,
    anchor_date: date | None = None,
) -> list[tuple[date, int]]:
    """Daily count of ``ToolUseEvent`` rows with ``tool_name='Bash'``.

    SQLite stores timezone-aware datetimes as ISO-8601 strings whose first 10
    characters are the UTC date (because Phase 1 ``ToolUseEventIn._enforce_utc``
    normalizes all incoming timestamps to UTC at ingest). We bucket on
    ``substr(ts, 1, 10)`` which is lexicographically equivalent to ``date(ts)``
    for UTC ISO strings and avoids ``date()``'s edge-case behavior with the
    trailing ``+00:00`` offset.
    """
    anchor = anchor_date or _default_anchor()
    days = _anchor_dates(anchor)

    # Compare on the date prefix (``substr(ts, 1, 10)`` == ``"YYYY-MM-DD"``)
    # directly against ``date.isoformat()`` strings. This is independent of how
    # SQLAlchemy/SQLite serializes the rest of the timestamp (space vs ``T``
    # separator, with or without trailing ``+00:00`` offset) — what matters is
    # only the first 10 characters, which are the UTC date for any tz-aware
    # datetime normalized to UTC (Phase 1 ``ToolUseEventIn._enforce_utc``
    # guarantees this). Lexicographic comparison on ``YYYY-MM-DD`` strings
    # matches calendrical ordering, so the range filter is exact.
    sql = _sql(
        "SELECT substr(ts, 1, 10) AS day, COUNT(*) AS cnt "
        "FROM tooluseevent "
        "WHERE machine_id = :mid "
        "  AND tool_name = 'Bash' "
        "  AND substr(ts, 1, 10) >= :start_day "
        "  AND substr(ts, 1, 10) <= :end_day "
        "GROUP BY day"
    ).bindparams(
        mid=machine_id,
        start_day=days[0].isoformat(),
        end_day=anchor.isoformat(),
    )

    counts: dict[str, int] = {}
    for row in session.exec(sql).all():  # type: ignore[arg-type]
        if isinstance(row, tuple):
            day_key, cnt = row[0], row[1]
        else:
            day_key = row.day  # type: ignore[attr-defined]
            cnt = row.cnt  # type: ignore[attr-defined]
        counts[str(day_key)] = int(cnt)

    return [(d, counts.get(d.isoformat(), 0)) for d in days]


# ---------------------------------------------------------------------------
# Inventory-diff aggregators (shared loader)
# ---------------------------------------------------------------------------


def _load_snapshots(
    session: Session,
    machine_id: str,
) -> list[tuple[date, dict]]:
    """Return ``[(received_date, parsed_payload), ...]`` ordered by date asc.

    Loaded once per aggregator call; reused across all 14 anchor evaluations.
    """
    sql = _sql(
        "SELECT received_at, payload_json FROM inventorysnapshot "
        "WHERE machine_id = :mid "
        "ORDER BY received_at ASC"
    ).bindparams(mid=machine_id)

    out: list[tuple[date, dict]] = []
    for row in session.exec(sql).all():  # type: ignore[arg-type]
        if isinstance(row, tuple):
            received_at, payload_json = row[0], row[1]
        else:
            received_at = row.received_at  # type: ignore[attr-defined]
            payload_json = row.payload_json  # type: ignore[attr-defined]
        # received_at may come back as ISO string or datetime depending on driver.
        if isinstance(received_at, str):
            # Strip any tz suffix for date parsing.
            dt = datetime.fromisoformat(received_at.replace("Z", "+00:00"))
            day = dt.date()
        elif isinstance(received_at, datetime):
            day = received_at.date()
        else:
            day = date.fromisoformat(str(received_at)[:10])
        try:
            payload = json.loads(payload_json) if isinstance(payload_json, str) else {}
        except (ValueError, TypeError) as exc:
            # WR-08: silently masking a malformed inventory payload hides data
            # corruption from AppSec users — the per-snapshot result becomes
            # "no items" which renders as "no anomalies" instead of an alert.
            # Log a warning so the corruption is at least visible in server
            # logs; we still fall back to {} to keep the aggregator running
            # against the remaining (valid) snapshots.
            log.warning(
                "malformed inventorysnapshot.payload_json for machine_id=%s: %s",
                machine_id,
                exc,
            )
            payload = {}
        out.append((day, payload))
    return out


def _rolling_window_diff_series(
    snapshots: list[tuple[date, dict]],
    payload_key: str,
    identity_fn,
    anchor_date: date,
) -> list[tuple[date, int]]:
    """Generic "new in last 7 days vs. older baseline" series builder.

    ``identity_fn(item) -> hashable`` builds the identity tuple used for set
    membership (e.g. ``item["name"]`` for MCP, ``(item["name"], item["file_hash"])``
    for agents).

    Returns 0 for anchors with empty baseline (no signal without prior data).
    """
    days = _anchor_dates(anchor_date)
    out: list[tuple[date, int]] = []

    for d in days:
        window_lo = d - timedelta(days=ROLLING_WEEK_DAYS)  # exclusive lower
        baseline_lo = d - timedelta(days=WINDOW_DAYS)  # exclusive lower for baseline
        # window: (window_lo, d]
        # baseline: (baseline_lo, window_lo]
        baseline_items: set = set()
        baseline_seen = False
        latest_window_payload: dict | None = None

        for snap_day, payload in snapshots:
            if window_lo < snap_day <= d:
                # in rolling-week window — track latest
                latest_window_payload = payload
            elif baseline_lo < snap_day <= window_lo:
                baseline_seen = True
                for it in payload.get(payload_key, []) or []:
                    try:
                        baseline_items.add(identity_fn(it))
                    except (KeyError, TypeError):
                        continue

        if not baseline_seen or latest_window_payload is None:
            out.append((d, 0))
            continue

        new_count = 0
        for it in latest_window_payload.get(payload_key, []) or []:
            try:
                ident = identity_fn(it)
            except (KeyError, TypeError):
                continue
            if ident not in baseline_items:
                new_count += 1
        out.append((d, new_count))

    return out


def new_mcp_per_week_series(
    session: Session,
    machine_id: str,
    anchor_date: date | None = None,
) -> list[tuple[date, int]]:
    """Rolling-week count of MCP servers whose ``name`` is new vs. the prior 7d.

    Identity = ``McpServerEntry.name`` (see ``anomaly_constants.MCP_NAME_FIELD``).
    """
    anchor = anchor_date or _default_anchor()
    snapshots = _load_snapshots(session, machine_id)
    return _rolling_window_diff_series(
        snapshots,
        payload_key="mcp_servers",
        identity_fn=lambda it: it[MCP_NAME_FIELD],
        anchor_date=anchor,
    )


def new_agents_per_week_series(
    session: Session,
    machine_id: str,
    anchor_date: date | None = None,
) -> list[tuple[date, int]]:
    """Rolling-week count of agents whose ``(name, file_hash)`` is new vs. prior 7d.

    A renamed agent with a fresh ``file_hash`` counts; an unchanged agent does not.
    """
    anchor = anchor_date or _default_anchor()
    snapshots = _load_snapshots(session, machine_id)
    return _rolling_window_diff_series(
        snapshots,
        payload_key="agents",
        identity_fn=lambda it: (it[AGENT_NAME_FIELD], it[AGENT_HASH_FIELD]),
        anchor_date=anchor,
    )


def skill_dir_hash_changes_per_week_series(
    session: Session,
    machine_id: str,
    anchor_date: date | None = None,
) -> list[tuple[date, int]]:
    """Rolling-week count of skills whose ``dir_hash`` differs from the prior 7d.

    Implementation: an item is "changed" if its ``(name, dir_hash)`` tuple is
    new in the latest window snapshot vs. the baseline window — i.e. same name
    but different hash. This reuses the generic diff helper; a skill that
    appears with a new hash naturally registers as a new ``(name, hash)``
    identity not present in the baseline set.
    """
    anchor = anchor_date or _default_anchor()
    snapshots = _load_snapshots(session, machine_id)
    return _rolling_window_diff_series(
        snapshots,
        payload_key="skills",
        identity_fn=lambda it: (it[SKILL_NAME_FIELD], it[SKILL_HASH_FIELD]),
        anchor_date=anchor,
    )
