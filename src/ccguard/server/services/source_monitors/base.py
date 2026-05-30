"""Shared types for source monitors.

A monitor is a tiny adapter: ``poll(since)`` returns the items new since the
last sweep. The discovery service handles dedup, the LLM call, and persistence
so each monitor stays narrow (just HTTP + parse).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol


@dataclass(frozen=True)
class SourceItem:
    """One item discovered by a monitor.

    ``url`` is the stable identifier used for dedup — two items with the same
    URL are considered the same item even across monitors.
    ``text`` is the threat-intel content handed to the LLM drafter.
    ``published_at`` is whatever timestamp the source gives (for ordering /
    cutoff decisions; never trusted for security).
    """

    url: str
    title: str
    text: str
    published_at: datetime


class SourceMonitor(Protocol):
    """One source of threat intelligence.

    ``name`` is a short kebab-id used in ``SourceFetchLog.monitor_name``.
    """

    name: str

    def poll(self, since: datetime) -> list[SourceItem]: ...
