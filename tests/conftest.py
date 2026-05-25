"""Общие фикстуры pytest для всех тестов ccguard."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from ccguard.schemas import (
    HookEntry,
    InventoryReport,
    McpServerEntry,
    PermissionsSnapshot,
    Policy,
    PolicyMeta,
    SettingsSource,
)


@pytest.fixture
def sample_policy() -> Policy:
    """Минимальная валидная policy для тестов."""
    return Policy(
        meta=PolicyMeta(
            revision=1,
            updated_at=datetime.now(UTC),
        ),
    )


@pytest.fixture
def sample_inventory() -> InventoryReport:
    """Минимальный валидный inventory для тестов."""
    return InventoryReport(
        machine_id="testmachine12345",
        timestamp=datetime.now(UTC),
        agent_version="0.1.0",
        os="linux",
        settings_sources=[
            SettingsSource(
                path="/home/test/.claude/settings.json",
                scope="user",
                exists=True,
            ),
        ],
        mcp_servers=[
            McpServerEntry(
                name="filesystem",
                transport="stdio",
                command="npx",
                args=["-y", "@modelcontextprotocol/server-filesystem"],
                env_keys=["FS_ROOT"],
                source="/home/test/.claude/settings.json",
            ),
        ],
        hooks=[
            HookEntry(
                event="PreToolUse",
                matcher="Bash",
                type="command",
                command="/usr/bin/lint",
                source="/home/test/.claude/settings.json",
            ),
        ],
        permissions=PermissionsSnapshot(
            allow=["Bash(git *)"],
            deny=[],
            ask=[],
        ),
    )


# --- audit_hook buffer fixtures (Phase 01 / Plan 01-01) ---------------------


@pytest.fixture
def audit_buffer_path(tmp_path: Path) -> Path:
    """Per-test path for a ToolBufferDB sqlite file."""
    return tmp_path / "audit_buffer.db"


def multiprocessing_buffer_worker(path_str: str, n_inserts: int) -> int:
    """Worker target for multiprocessing-based concurrency tests.

    Module-level (not a closure) so it is picklable under `spawn` start method.
    Opens its own ToolBufferDB at the given path and performs ``n_inserts``
    independent INSERTs. Returns the number of successful inserts.
    """
    from pathlib import Path as _P

    from ccguard.agent.audit_hook.buffer import ToolBufferDB

    ok = 0
    with ToolBufferDB(_P(path_str)) as buf:
        for i in range(n_inserts):
            buf.insert(
                ts=f"2026-05-25T00:00:{i:02d}Z",
                tool_name="Bash",
                fingerprint="0123456789abcdef",
                decision="allow",
                result_status="success",
            )
            ok += 1
    return ok
