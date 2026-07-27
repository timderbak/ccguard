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
from ccguard.agent.sync import _apply_and_report, perform_sync, sync_cursor_inventory
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


def _cursor_home() -> Path:
    import os
    return Path(os.environ.get("CCGUARD_CURSOR_HOME") or os.path.expanduser("~/.cursor"))


def _apply_and_report_safe(
    policy: dict,
    *,
    server_url: str,
    token: str,
    machine_id: str,
) -> None:
    """Thin pass-through to sync._apply_and_report — overridable by tests."""
    _apply_and_report(
        policy,
        server_url=server_url,
        token=token,
        machine_id=machine_id,
    )


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
def harden(
    apply: bool = typer.Option(
        False, "--apply", help="run the hardening now (requires root/sudo)"
    ),
) -> None:
    """Hardened tier (privilege boundary): pin the ccguard hooks in Claude Code's
    root-owned managed-settings.json and make the shim/policy root-owned +
    immutable, so a same-user agent can't remove the hook or swap the shim.

    Prints a reviewable bash script — run it with root on the endpoint
    (``ccguard harden | sudo bash``). ``--apply`` runs it now (needs root)."""
    import subprocess
    import sys as _sys

    from ccguard.agent import harden as harden_module

    plat = _sys.platform
    if harden_module.managed_settings_path(plat) is None:
        typer.echo(f"hardened tier not supported on platform {plat!r}", err=True)
        raise typer.Exit(code=2)
    plan = harden_module.harden_plan(
        platform=plat,
        enforce_shim=install_module.shim_path(),
        audit_shim=install_module.audit_shim_path(),
        policy_path=default_config_dir() / "policy.yaml",
    )
    script = harden_module.render_script(plan)
    if not apply:
        typer.echo(script)
        return
    proc = subprocess.run(["bash", "-c", script])  # noqa: S603 — operator-invoked
    raise typer.Exit(code=proc.returncode)


@app.command()
def enforce() -> None:
    """Точка входа хука (Claude Code вызывает с stdin). НЕ для ручного использования."""
    sys.exit(enforce_main_cli())


@app.command()
def selftest() -> None:
    """Прогнать батарею canned-атак через enforce (evil→deny, benign→allow).

    Быстрая проверка горячего пути enforce БЕЗ сервера и живого Claude Code:
    always-on hard-ярус режет всё «никогда-не-легитимное» даже без политики
    (свойство anti-tamper A1), а обычные dev-команды проходят (FP-safety).
    Exit 0 если все вердикты сошлись, иначе 1.
    """
    from ccguard.agent.selftest import run_selftest

    results, ok = run_selftest()
    typer.echo("ccguard enforce self-test\n")
    for r in results:
        mark = "ok  " if r.ok else "FAIL"
        rule = f"  [{r.rule_id}]" if r.rule_id else ""
        typer.echo(f"  {mark}  expect={r.case.expect:<5s} got={r.permission:<5s}  {r.case.name}{rule}")
    passed = sum(1 for r in results if r.ok)
    typer.echo(f"\n{passed}/{len(results)} passed")
    raise typer.Exit(0 if ok else 1)


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
    # Plan 04-04: push_install — apply mandatory policy sections and report
    # outcome to /api/v1/audit. Best-effort: any failure here MUST NOT
    # raise into the CLI. _apply_and_report_safe wraps the inner helper in
    # a final try/except as belt-and-suspenders.
    if result.inventory_posted:
        try:
            policy_dict: dict = {}
            if cache.exists():
                try:
                    policy_dict = yaml.safe_load(cache.read_text()) or {}
                except Exception:  # noqa: BLE001
                    policy_dict = {}
            mid = derive_machine_id(cfg.install_salt)
            _apply_and_report_safe(
                policy_dict,
                server_url=cfg.server.url,
                token=cfg.server.token,
                machine_id=mid,
            )
        except Exception as exc:  # noqa: BLE001 — belt-and-suspenders
            typer.echo(
                f"warning: policy apply step failed: {type(exc).__name__}: {exc}",
                err=True,
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

    # Мультиагентность: если на машине есть Cursor — отправить его инвентарь
    # отдельным machine_id. Best-effort: сбой (или отсутствие Cursor) не влияет
    # на код возврата основного sync.
    cursor_summary: dict[str, object] = {"detected": False}
    try:
        cursor_result = sync_cursor_inventory(
            config=cfg, cursor_home=_cursor_home(), project_dir=Path.cwd()
        )
        if cursor_result is not None:
            cursor_summary = {
                "detected": True,
                "inventory_posted": cursor_result.inventory_posted,
                "error": cursor_result.error,
            }
    except Exception as exc:  # noqa: BLE001 — never fail sync because of cursor
        cursor_summary = {"detected": True, "error": f"cursor_unexpected: {exc.__class__.__name__}"}

    typer.echo(
        json.dumps(
            {
                "inventory_posted": result.inventory_posted,
                "policy_updated": result.policy_updated,
                "new_policy_revision": result.new_policy_revision,
                "error": result.error,
                "scan": scan_summary,
                "cursor": cursor_summary,
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


@app.command("seed-demo")
def seed_demo(
    server_url: str = typer.Option(
        "http://localhost:8000",
        "--server-url",
        envvar="CCGUARD_SERVER_URL",
        help="URL сервера ccguard.",
    ),
    token: str = typer.Option(
        "",
        "--token",
        envvar="CCGUARD_AGENT_TOKEN",
        help="Agent-токен (создай на /settings).",
    ),
    scenario: str = typer.Option(
        "kill_chain",
        "--scenario",
        help="Имя сценария из scripts/attack_simulator.py (например, kill_chain, recon, mix).",
    ),
    machine: str = typer.Option(
        "m-demo-laptop",
        "--machine",
        help="machine_id для demo-машины (получит суффикс (demo) в label на сервере).",
    ),
) -> None:
    """Создать демо-данные для пустого инстанса. Только для разработки.

    Запускает scripts/attack_simulator.py с дефолтным сценарием, чтобы пустой
    UI наполнился реалистично выглядящими событиями + одной demo-машиной.
    Команда явно opt-in и НЕ зовётся автоматически ни откуда.
    """
    import importlib.util
    import os
    import sys as _sys
    from pathlib import Path as _Path

    if not token:
        typer.echo(
            "Нужен --token или env CCGUARD_AGENT_TOKEN (создай на /settings).",
            err=True,
        )
        raise typer.Exit(code=2)

    # Найти scripts/attack_simulator.py относительно установленного пакета.
    # TODO: при packaged-релизе перенести scenarios внутрь пакета,
    #       а CLI оставить как тонкую обёртку.
    repo_root = _Path(__file__).resolve().parents[3]
    sim_path = repo_root / "scripts" / "attack_simulator.py"
    if not sim_path.exists():
        typer.echo(
            f"attack_simulator.py не найден: {sim_path}. "
            "Запускай seed-demo из репозитория (pip install -e .).",
            err=True,
        )
        raise typer.Exit(code=2)

    typer.echo(f"[seed-demo] scenario={scenario} machine={machine} → {server_url}")

    # Сначала регистрируем машину, и только потом шлём события.
    #
    # Приём событий машину в реестр НЕ заводит: это разные потоки — аудит
    # принимает поток действий, инвентарь регистрирует саму машину. Без
    # регистрации демо-события ложатся на машину, которой для сервера не
    # существует: страница /machines пуста, карточка машины отдаёт 404, и вся
    # защитная логика (диагноз состояния, разбор эпизодов) эту машину не
    # видит, потому что перебирает реестр. То есть демо показывало бы меньше
    # половины продукта, обещая на выходе обратное.
    _seed_demo_register_machine(server_url=server_url, token=token, machine=machine)

    # Загружаем модуль и зовём его main() с подменёнными argv — это явно,
    # без curl-зависимостей и без shell.
    spec = importlib.util.spec_from_file_location("_ccguard_attack_sim", sim_path)
    assert spec and spec.loader  # for type checker
    mod = importlib.util.module_from_spec(spec)
    saved_argv = _sys.argv
    saved_env = dict(os.environ)
    try:
        os.environ["CCGUARD_SERVER_URL"] = server_url
        os.environ["CCGUARD_AGENT_TOKEN"] = token
        # Флаг адреса у симулятора называется --server (не --server-url):
        # несовпадение имён роняло команду разбором аргументов.
        _sys.argv = [
            str(sim_path),
            "--scenario", scenario,
            "--machine", machine,
            "--server", server_url,
            "--token", token,
        ]
        # Модуль обязан лежать в sys.modules ДО выполнения: симулятор
        # использует отложенные аннотации (``from __future__ import
        # annotations``), а @dataclass разбирает их через
        # ``sys.modules[cls.__module__]``. Незарегистрированный модуль даёт
        # там None и падение с невнятным «NoneType has no attribute __dict__»
        # ещё на импорте — то есть команда не работала вовсе.
        _sys.modules[spec.name] = mod
        spec.loader.exec_module(mod)
        rc = mod.main()
    finally:
        _sys.modules.pop(spec.name, None)
        _sys.argv = saved_argv
        os.environ.clear()
        os.environ.update(saved_env)

    if rc:
        raise typer.Exit(code=int(rc))
    typer.echo(
        "[seed-demo] готово. Открой /machines, /audit и карточку машины "
        f"/machines/{machine}."
    )


def _seed_demo_register_machine(*, server_url: str, token: str, machine: str) -> None:
    """Завести демо-машину в реестре и подать сигнал «я жива».

    Только для ``seed-demo``. Инвентарь намеренно минимальный: цель — не
    изобразить правдоподобный парк установленных расширений, а сделать машину
    видимой, чтобы на демо-данных работали страницы и защитная логика.
    Сигнал отправляется следом, иначе диагноз состояния честно скажет
    «машина ни разу не присылала сигнал» — что для демонстрации бесполезно.

    Сеть здесь может отказать (сервер не поднят, другой адрес), и это НЕ повод
    ронять команду: события всё равно отправятся, а причина будет названа.
    """
    import json as _json
    from datetime import UTC as _UTC
    from datetime import datetime as _dt
    from urllib import error as _urlerr
    from urllib import request as _urlreq

    base = server_url.rstrip("/")
    now = _dt.now(_UTC).isoformat()

    def _post(path: str, body: dict) -> tuple[int, str]:
        req = _urlreq.Request(
            f"{base}{path}",
            data=_json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-CCGuard-Token": token},
            method="POST",
        )
        try:
            with _urlreq.urlopen(req, timeout=10) as resp:  # noqa: S310 — свой сервер
                return resp.status, resp.read().decode("utf-8", "replace")[:200]
        except _urlerr.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")[:200]
        except OSError as e:
            return 0, str(e)

    status, body = _post("/api/v1/inventory", {
        "inventory": {
            "schema_version": 1,
            "machine_id": machine,
            "machine_label": f"{machine} (demo)",
            "timestamp": now,
            "agent_version": "demo",
            "os": "linux",
        },
    })
    if status != 200:
        typer.echo(
            f"[seed-demo] машину зарегистрировать не удалось ({status}): {body}. "
            "События всё равно отправим, но страница машины будет пустой.",
            err=True,
        )
        return
    typer.echo(f"[seed-demo] машина {machine} зарегистрирована")

    hb_status, hb_body = _post("/api/v1/heartbeat", {
        "machine_id": machine,
        "agent_version": "demo",
        "hooks_intact": True,
        "expected_interval_sec": 900,
    })
    if hb_status != 200:
        typer.echo(
            f"[seed-demo] сигнал не принят ({hb_status}): {hb_body}. "
            "Карточка машины покажет «нет данных» вместо «защита работает».",
            err=True,
        )


if __name__ == "__main__":
    app()
