"""CLI агента ccguard. Точка входа `ccguard`."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer
import yaml

from ccguard.agent import install as install_module
from ccguard.agent.check import check_inventory, exit_code_for_findings
from ccguard.agent.config import default_config_dir, load_or_create
from ccguard.agent.enforce import main_cli as enforce_main_cli
from ccguard.agent.machine_id import derive_machine_id
from ccguard.agent.report import build_text_report
from ccguard.agent.scan import run_scan
from ccguard.agent.sync import perform_sync
from ccguard.schemas import Finding, InventoryReport, Policy

app = typer.Typer(
    name="ccguard",
    help="Endpoint-агент контроля конфигурации Claude Code.",
    no_args_is_help=True,
    add_completion=False,
)


def _claude_home() -> Path:
    import os
    return Path(os.environ.get("CLAUDE_HOME") or os.path.expanduser("~/.claude"))


def _do_scan() -> InventoryReport:
    cfg, _ = load_or_create()
    mid = derive_machine_id(cfg.install_salt)
    return run_scan(
        claude_home=_claude_home(),
        project_dir=Path.cwd(),
        machine_id=mid,
        machine_label=cfg.machine_label,
    )


def _load_policy_or_die() -> Policy:
    cfg, _ = load_or_create()
    cache = cfg.resolved_cache_path()
    if not cache.exists():
        typer.echo(f"policy cache not found at {cache}; run `ccguard sync` first", err=True)
        raise typer.Exit(code=3)
    data = yaml.safe_load(cache.read_text()) or {}
    return Policy.model_validate(data)


@app.command()
def scan(
    fmt: str = typer.Option("text", "--format", "-f", help="text | json"),
) -> None:
    """Инвентаризировать конфигурацию Claude Code на машине."""
    inv = _do_scan()
    if fmt == "json":
        typer.echo(inv.model_dump_json(indent=2))
    else:
        typer.echo(
            f"scan ok: machine_id={inv.machine_id}, mcp={len(inv.mcp_servers)}, "
            f"hooks={len(inv.hooks)}, skills={len(inv.skills)}, plugins={len(inv.plugins)}"
        )


@app.command()
def check(
    fmt: str = typer.Option("text", "--format", "-f", help="text | json"),
) -> None:
    """Проверить inventory против локальной политики. Exit 0/1/2 по severity."""
    inv = _do_scan()
    policy = _load_policy_or_die()
    findings = check_inventory(inv, policy)
    if fmt == "json":
        typer.echo(json.dumps([f.model_dump(mode="json") for f in findings], indent=2))
    else:
        typer.echo(build_text_report(inv, findings))
    raise typer.Exit(code=exit_code_for_findings(findings))


@app.command()
def install(
    scope: str = typer.Option("user", "--scope", help="user | project | managed"),
) -> None:
    """Установить PreToolUse-хук ccguard в settings.json Claude Code."""
    project_dir = Path.cwd() if scope == "project" else None
    res = install_module.install_hook(scope=scope, project_dir=project_dir)  # type: ignore[arg-type]
    typer.echo(json.dumps(res, indent=2))


@app.command()
def uninstall(
    scope: str = typer.Option("user", "--scope", help="user | project | managed"),
) -> None:
    """Удалить ccguard-хук из settings.json Claude Code."""
    project_dir = Path.cwd() if scope == "project" else None
    res = install_module.uninstall_hook(scope=scope, project_dir=project_dir)  # type: ignore[arg-type]
    typer.echo(json.dumps(res, indent=2))


@app.command()
def enforce() -> None:
    """Точка входа хука (Claude Code вызывает с stdin). НЕ для ручного использования."""
    sys.exit(enforce_main_cli())


@app.command()
def sync() -> None:
    """Отправить inventory на сервер, обновить локальную policy.

    Plan 03-04: after the inventory POST succeeds we additionally run the
    LLM content-scan cycle (collect agents/skills, mask, send to
    ``/api/v1/scan-content``). The scanner is gated server-side via
    ``/api/v1/scanner-config`` so an old/disabled server is a no-op.
    Scan failures are logged and swallowed — they must never fail the
    inventory cycle (the scanner is best-effort tertiary signal).
    """
    cfg, _ = load_or_create()
    inv = _do_scan()

    # Получаем findings на основе текущего (возможно устаревшего) кэша policy,
    # но если кэша нет — пустой список. Сервер всё равно решит, что показывать.
    cache = cfg.resolved_cache_path()
    findings: list[Finding] = []
    if cache.exists():
        try:
            data = yaml.safe_load(cache.read_text()) or {}
            policy = Policy.model_validate(data)
            findings = check_inventory(inv, policy)
        except Exception:
            pass

    audit_path = default_config_dir() / "audit.log"
    audit_cursor_path = default_config_dir() / "audit.cursor"

    result = perform_sync(
        config=cfg,
        inventory=inv,
        findings=findings,
        audit_path=audit_path,
        audit_cursor_path=audit_cursor_path,
        policy_cache_path=cache,
    )
    # Plan 03-04: trigger LLM content scan AFTER the inventory cycle. The
    # scanner is gated server-side; agent v0.1 servers without /scanner-config
    # will simply 404 and we treat that as "skipped". Never raises — the scan
    # is purely informational.
    scan_summary: dict[str, object] = {"skipped": "inventory_failed"}
    if result.inventory_posted and not result.error:
        try:
            from ccguard.agent.inventory_scan import run_scan_cycle
            scan_summary = run_scan_cycle(
                claude_home=_claude_home(),
                server_url=cfg.server.url,
                token=cfg.server.token,
            )
        except Exception as exc:  # noqa: BLE001 — never fail sync because of scan
            scan_summary = {"error": f"scan_unexpected: {exc.__class__.__name__}"}

    typer.echo(
        json.dumps(
            {
                "inventory_posted": result.inventory_posted,
                "policy_updated": result.policy_updated,
                "new_policy_revision": result.new_policy_revision,
                "error": result.error,
                "scan": scan_summary,
            },
            indent=2,
        )
    )
    if result.error:
        raise typer.Exit(code=1)


@app.command()
def report(
    fmt: str = typer.Option("text", "--format", "-f", help="text | json"),
) -> None:
    """Сводный отчёт по последнему scan + check."""
    inv = _do_scan()
    cache = (load_or_create()[0]).resolved_cache_path()
    findings: list[Finding] = []
    if cache.exists():
        try:
            policy = Policy.model_validate(yaml.safe_load(cache.read_text()) or {})
            findings = check_inventory(inv, policy)
        except Exception:
            pass
    if fmt == "json":
        typer.echo(
            json.dumps(
                {
                    "inventory": inv.model_dump(mode="json"),
                    "findings": [f.model_dump(mode="json") for f in findings],
                },
                indent=2,
            )
        )
    else:
        typer.echo(build_text_report(inv, findings))


if __name__ == "__main__":
    app()
