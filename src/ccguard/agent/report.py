"""report: сводка по последнему scan + check для человека."""

from __future__ import annotations

from ccguard.schemas import Finding, InventoryReport


def build_text_report(inventory: InventoryReport, findings: list[Finding]) -> str:
    """Текстовый отчёт для терминала."""
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append(f"ccguard report — machine {inventory.machine_id}")
    if inventory.machine_label:
        lines.append(f"label: {inventory.machine_label}")
    lines.append(f"os: {inventory.os}, agent: {inventory.agent_version}")
    lines.append(f"timestamp: {inventory.timestamp.isoformat()}")
    lines.append("")

    lines.append("== Inventory ==")
    lines.append(f"  settings sources : {len(inventory.settings_sources)}")
    lines.append(f"  MCP servers      : {len(inventory.mcp_servers)}")
    lines.append(f"  skills           : {len(inventory.skills)}")
    lines.append(f"  hooks            : {len(inventory.hooks)}")
    lines.append(f"  plugins          : {len(inventory.plugins)}")
    lines.append(f"  permissions.allow: {len(inventory.permissions.allow)}")
    lines.append(f"  permissions.deny : {len(inventory.permissions.deny)}")
    lines.append(f"  dangerously-skip : {inventory.permissions.dangerously_skip_detected}")
    lines.append("")

    by_sev = {"info": 0, "warn": 0, "block": 0}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    lines.append("== Findings ==")
    lines.append(
        f"  total: {len(findings)} | block: {by_sev['block']} "
        f"| warn: {by_sev['warn']} | info: {by_sev['info']}"
    )
    lines.append("")
    if findings:
        for f in findings:
            lines.append(f"  [{f.severity.upper():5}] {f.rule_id}: {f.title}")
            lines.append(f"    source: {f.source}")
            lines.append(f"    fix:    {f.recommendation}")
            lines.append("")
    else:
        lines.append("  ✓ no findings")
        lines.append("")

    lines.append("=" * 60)
    return "\n".join(lines)
