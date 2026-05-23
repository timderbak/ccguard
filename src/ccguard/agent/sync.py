"""sync: отправить inventory + findings + audit на сервер, забрать актуальную policy."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import httpx
import yaml

from ccguard.agent.audit import read_audit_entries
from ccguard.agent.config import AgentConfig
from ccguard.schemas import AuditEntry, Finding, InventoryReport, Policy, SyncPayload


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
