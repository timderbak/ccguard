"""sync: отправить inventory + findings + audit на сервер, забрать актуальную policy.

Plan 04-04 adds :func:`_apply_and_report`: after the agent fetches a fresh
policy, it invokes :func:`ccguard.agent.push_install.apply` and forwards the
outcome (success or rollback) to POST /api/v1/audit with
``event_source=policy_apply``. The function is best-effort: it MUST NOT raise
into the CLI caller — every failure path (apply exception, audit POST
network error, server 5xx) is swallowed and logged at WARNING.

Empty no-op applies (``applied_count == 0`` and ``result == "success"``) do
NOT POST to /api/v1/audit, to avoid logging noise from agents talking to a
v0.1 server that never publishes mandatory sections.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import yaml
from pydantic import ValidationError

from ccguard.agent.audit import read_audit_entries
from ccguard.agent.config import AgentConfig
# Re-exported under an alias so tests can monkeypatch the call site without
# touching the original module-level binding in push_install.
from ccguard.agent.push_install import apply as push_install_apply
from ccguard.schemas import AuditEntry, Finding, InventoryReport, Policy, SyncPayload

_log = logging.getLogger(__name__)


@dataclass
class SyncResult:
    inventory_posted: bool
    policy_updated: bool
    new_policy_revision: int | None
    server_response: dict | None
    error: str | None = None


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content)
    tmp.replace(path)


def _load_cached_etag(cache_path: Path) -> str | None:
    etag_file = cache_path.with_suffix(cache_path.suffix + ".etag")
    if etag_file.exists():
        return etag_file.read_text().strip() or None
    return None


def _save_etag(cache_path: Path, etag: str) -> None:
    etag_file = cache_path.with_suffix(cache_path.suffix + ".etag")
    etag_file.write_text(etag)


def _filter_audit_for_sync(entries: list[AuditEntry]) -> list[AuditEntry]:
    """На сервер шлём только deny + fail_open. См. BRAINSTORM §6."""
    return [e for e in entries if e.decision == "deny" or e.fail_open]


def _read_cursor(cursor_path: Path) -> int:
    if not cursor_path.exists():
        return 0
    try:
        return int(cursor_path.read_text().strip())
    except (ValueError, OSError):
        return 0


def _write_cursor(cursor_path: Path, value: int) -> None:
    _atomic_write(cursor_path, str(value))


def perform_sync(
    config: AgentConfig,
    inventory: InventoryReport,
    findings: list[Finding],
    audit_path: Path,
    audit_cursor_path: Path,
    policy_cache_path: Path,
    timeout_sec: float = 5.0,
) -> SyncResult:
    """Одношаговый sync. Не бросает: ошибки записывает в SyncResult.error."""
    server_url = config.server.url.rstrip("/")
    token = config.server.token
    headers = {"X-CCGuard-Token": token}

    # Собираем audit для отправки: всё что после cursor + only deny/fail_open.
    audit_all = read_audit_entries(audit_path)
    cursor = _read_cursor(audit_cursor_path)
    new_entries_total = len(audit_all)
    new_audit = audit_all[cursor:]
    audit_to_send = _filter_audit_for_sync(new_audit)

    payload = SyncPayload(inventory=inventory, findings=findings, audit_events=audit_to_send)

    try:
        with httpx.Client(timeout=timeout_sec) as client:
            r = client.post(
                f"{server_url}/api/v1/inventory",
                content=payload.model_dump_json(),
                headers={**headers, "Content-Type": "application/json"},
            )
            r.raise_for_status()
            response_body = r.json()
    except httpx.HTTPError as e:
        return SyncResult(
            inventory_posted=False,
            policy_updated=False,
            new_policy_revision=None,
            server_response=None,
            error=f"inventory post failed: {e}",
        )

    # Двигаем cursor только после успешной отправки.
    _write_cursor(audit_cursor_path, new_entries_total)

    # 2. GET /policy с If-None-Match.
    etag = _load_cached_etag(policy_cache_path)
    policy_updated = False
    new_revision: int | None = None
    try:
        with httpx.Client(timeout=timeout_sec) as client:
            req_headers = dict(headers)
            if etag:
                req_headers["If-None-Match"] = etag
            r = client.get(f"{server_url}/api/v1/policy", headers=req_headers)
            if r.status_code == 304:
                # Кэш актуален.
                pass
            else:
                r.raise_for_status()
                # Валидируем то, что пришло.
                new_policy = Policy.model_validate(r.json())
                cached_revision = _read_cached_revision(policy_cache_path)
                if cached_revision is not None and new_policy.meta.revision < cached_revision:
                    # Защита от отката: не применяем более старую policy.
                    return SyncResult(
                        inventory_posted=True,
                        policy_updated=False,
                        new_policy_revision=cached_revision,
                        server_response=response_body,
                        error=f"server returned older policy (rev {new_policy.meta.revision} < {cached_revision})",
                    )
                _atomic_write(
                    policy_cache_path,
                    yaml.safe_dump(new_policy.model_dump(mode="json"), sort_keys=False),
                )
                new_etag = r.headers.get("ETag")
                if new_etag:
                    _save_etag(policy_cache_path, new_etag)
                policy_updated = True
                new_revision = new_policy.meta.revision
    except httpx.HTTPError as e:
        return SyncResult(
            inventory_posted=True,
            policy_updated=False,
            new_policy_revision=_read_cached_revision(policy_cache_path),
            server_response=response_body,
            error=f"policy fetch failed: {e}",
        )

    return SyncResult(
        inventory_posted=True,
        policy_updated=policy_updated,
        new_policy_revision=new_revision or _read_cached_revision(policy_cache_path),
        server_response=response_body,
    )


def _read_cached_revision(cache_path: Path) -> int | None:
    if not cache_path.exists():
        return None
    try:
        data = yaml.safe_load(cache_path.read_text()) or {}
        return int(data.get("meta", {}).get("revision"))
    except (ValueError, KeyError, TypeError, OSError):
        return None


# ---------------------------------------------------------------------------
# Plan 04-04: push_install integration hook
# ---------------------------------------------------------------------------


def _policy_revision_from(policy: dict) -> int:
    """Extract revision from a policy dict; fall back to 0 if absent/malformed."""
    try:
        rev = policy.get("meta", {}).get("revision")
        return int(rev) if rev is not None else 0
    except (AttributeError, TypeError, ValueError):
        return 0


def _post_policy_apply_event(
    *,
    server_url: str,
    token: str,
    machine_id: str,
    apply_result: dict[str, Any],
    policy_revision: int,
    timeout_sec: float = 5.0,
) -> None:
    """POST a single PolicyApplyEvent to /api/v1/audit. Best-effort: never raises."""
    body = {
        "event_source": "policy_apply",
        "events": [
            {
                "machine_id": machine_id,
                "ts": datetime.now(UTC).isoformat(),
                "result": apply_result.get("result", "rollback"),
                "applied_count": int(apply_result.get("applied_count") or 0),
                "snapshot_id": apply_result.get("snapshot_id"),
                "reason": apply_result.get("reason"),
                "failed_file": apply_result.get("failed_file"),
                "policy_revision": policy_revision,
            }
        ],
    }
    url = f"{server_url.rstrip('/')}/api/v1/audit"
    try:
        with httpx.Client(timeout=timeout_sec) as client:
            r = client.post(
                url,
                content=json.dumps(body),
                headers={
                    "X-CCGuard-Token": token,
                    "Content-Type": "application/json",
                },
            )
            if r.status_code >= 400:
                _log.warning(
                    "policy_apply audit POST returned %s: %s",
                    r.status_code, r.text[:200],
                )
    except Exception as exc:  # noqa: BLE001 — best-effort, never raise
        _log.warning("policy_apply audit POST failed: %s: %s", type(exc).__name__, exc)


def _apply_and_report(
    policy: dict,
    *,
    server_url: str,
    token: str,
    machine_id: str,
    home: Path | None = None,
) -> None:
    """Apply mandatory policy sections and report outcome to /api/v1/audit.

    Plan 04-04 best-effort guarantee: this function NEVER raises into the
    CLI caller. Any exception from ``push_install.apply`` or the audit POST
    is caught and logged at WARNING.

    Empty no-op apply (success with applied_count==0) is intentionally NOT
    posted to /api/v1/audit to avoid noise from agents talking to v0.1
    servers that publish no mandatory sections.
    """
    # WR-03: re-validate the cached policy dict through Policy before apply.
    # The validation done at sync time proves the *server response* was valid;
    # it does NOT prove that the on-disk cache is still valid at apply time.
    # Local tamper of ~/.config/ccguard/policy.yaml (same UID, common on dev
    # workstations) is the threat. Combined with CR-01's path-traversal
    # validator on RequiredSkill/RequiredAgent name, this forecloses arbitrary
    # writes via cache tamper.
    try:
        Policy.model_validate(policy)
    except ValidationError as exc:
        _log.warning(
            "policy cache failed re-validation; skipping apply: %s", exc
        )
        return
    except Exception as exc:  # noqa: BLE001 — defense in depth
        _log.warning(
            "policy cache re-validation raised unexpectedly: %s: %s",
            type(exc).__name__, exc,
        )
        return

    try:
        apply_result = push_install_apply(policy, home=home)
    except Exception as exc:  # noqa: BLE001 — defense in depth
        _log.warning(
            "push_install.apply unexpectedly raised: %s: %s",
            type(exc).__name__, exc,
        )
        return

    result = apply_result.get("result")
    applied_count = int(apply_result.get("applied_count") or 0)

    # Skip no-op (success with nothing applied). Always report rollbacks.
    if result == "success" and applied_count == 0:
        return

    _post_policy_apply_event(
        server_url=server_url,
        token=token,
        machine_id=machine_id,
        apply_result=apply_result,
        policy_revision=_policy_revision_from(policy),
    )
