"""Общие фикстуры pytest для всех тестов ccguard."""

from __future__ import annotations

from datetime import UTC, datetime

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
