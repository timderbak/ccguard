"""Agent-side LLM content scanner pipeline (Plan 03-04 Task 2).

Three functions:

* :func:`collect_scannable_files` — walk ``~/.claude/agents/*.md`` and
  ``~/.claude/skills/*/SKILL.md``, mask secrets, base64-encode, return
  :class:`ScanRequestItem` list. Files larger than the server's hard cap are
  still included; the server will reject them with ``content_too_large``.
* :func:`send_scan_batch` — gate on ``GET /api/v1/scanner-config`` (skip if
  ``enabled=false``), then ``POST /api/v1/scan-content`` with the batch. Never
  raises — scan failures must not fail the inventory cycle.
* :func:`run_scan_cycle` — convenience entry point combining the two; used
  from the CLI ``sync`` hook.

Privacy / threat-model invariants:

- T-03-10: every file is run through :func:`mask_content` BEFORE base64
  encoding so secrets never leave the machine.
- T-03-12: every request carries the ``X-CCGuard-Token`` header (agent auth
  reused from Phase 1).
- Server contract guarantees that raw content is never persisted or logged;
  this module relies on that and itself logs only ``file_path`` summaries.
"""

from __future__ import annotations

import base64
import logging
from pathlib import Path
from typing import Any

import httpx

from ccguard.agent import read_scan_spool
from ccguard.agent.masking import mask_content
from ccguard.schemas.scan import ScanBatchResponse, ScannerConfig, ScanRequest, ScanRequestItem

logger = logging.getLogger("ccguard.agent.inventory_scan")

DEFAULT_TIMEOUT_SEC = 30.0

# ScanRequest caps a batch at 50 items (schema-level). Config artifacts take
# priority; read-scan backstop items fill whatever budget remains.
_MAX_BATCH_ITEMS = 50


def _scrub_path(path: Path, claude_home: Path) -> str:
    """Return a server-safe, PII-free representation of ``path``.

    WR-05: absolute file paths leak the developer's OS username
    (``/Users/<x>/.claude/...`` on macOS, ``C:\\Users\\<x>\\.claude\\...``
    on Windows). The path is metadata, not load-bearing for classification,
    so we scrub the leading home segment to ``~/.claude/<rel>`` before
    sending it to the server (where it lands in logs + Anthropic user
    messages).
    """
    try:
        rel = path.resolve().relative_to(claude_home.resolve())
    except (ValueError, OSError):
        # Fallback: best-effort tail (last 2 segments) so the LLM still has
        # filename context but no full filesystem path is leaked.
        parts = path.parts[-2:]
        return "~/.claude/" + "/".join(parts)
    return "~/.claude/" + rel.as_posix()


def collect_scannable_files(claude_home: Path) -> list[ScanRequestItem]:
    """Walk a Claude home directory and return scannable items.

    Targets:
    - ``<home>/agents/*.md`` (top-level only, scope="agent")
    - ``<home>/skills/<name>/SKILL.md`` (one per skill, scope="skill")

    Each item:
    1. is read as bytes,
    2. decoded utf-8 with ``errors="replace"`` (binary garbage → ``\\ufffd``),
    3. masked via :func:`mask_content` BEFORE encoding (T-03-10),
    4. base64-encoded for HTTP transport.

    Returns ``[]`` if ``claude_home`` or its subdirectories are missing —
    never raises. Files that fail to read are skipped (logged at WARNING).
    """
    items: list[ScanRequestItem] = []
    if not claude_home.exists() or not claude_home.is_dir():
        return items

    # agents/*.md
    agents_dir = claude_home / "agents"
    if agents_dir.is_dir():
        for path in sorted(agents_dir.glob("*.md")):
            item = _read_and_pack(path, scope="agent", claude_home=claude_home)
            if item is not None:
                items.append(item)

    # skills/<name>/SKILL.md
    skills_dir = claude_home / "skills"
    if skills_dir.is_dir():
        for skill_dir in sorted(p for p in skills_dir.iterdir() if p.is_dir()):
            skill_file = skill_dir / "SKILL.md"
            if skill_file.is_file():
                item = _read_and_pack(skill_file, scope="skill", claude_home=claude_home)
                if item is not None:
                    items.append(item)

    return items


def _read_and_pack(
    path: Path, *, scope: str, claude_home: Path
) -> ScanRequestItem | None:
    """Read one file, mask, base64-encode. Returns None on read failure.

    WR-05: ``file_path`` is scrubbed to a home-relative form
    (``~/.claude/...``) before being attached to the request, so the
    server's logs and the Anthropic user message never carry the OS
    username.
    """
    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        logger.warning("inventory_scan: failed to read %s: %s", path, exc)
        return None
    text = raw_bytes.decode("utf-8", errors="replace")
    masked = mask_content(text)
    b64 = base64.b64encode(masked.encode("utf-8")).decode("ascii")
    scrubbed = _scrub_path(path, claude_home)
    return ScanRequestItem(file_path=scrubbed, scope=scope, content_b64=b64)  # type: ignore[arg-type]


def collect_read_scan_items(
    max_items: int = _MAX_BATCH_ITEMS,
) -> tuple[list[ScanRequestItem], list[Path]]:
    """Drain the read-scan spool (P5) into ``scope="read_file"`` scan items.

    Returns ``(items, spool_paths)``. The spool already masked + username-
    scrubbed the content at write time, so here we only base64-encode for
    transport. The caller deletes ``spool_paths`` after a successful POST so a
    failed sync re-ships next cycle. Never raises.
    """
    if max_items <= 0:
        return [], []
    try:
        drained = read_scan_spool.drain(max_items=max_items)
    except Exception:  # noqa: BLE001 — spool drain must not fail the cycle
        return [], []
    items: list[ScanRequestItem] = []
    paths: list[Path] = []
    for file_path, content, path in drained:
        b64 = base64.b64encode(content.encode("utf-8")).decode("ascii")
        items.append(
            ScanRequestItem(
                file_path=file_path or "~/read-content",
                scope="read_file",  # type: ignore[arg-type]
                content_b64=b64,
            )
        )
        paths.append(path)
    return items, paths


def send_scan_batch(
    *,
    server_url: str,
    token: str,
    items: list[ScanRequestItem],
    transport: httpx.BaseTransport | None = None,
    timeout_sec: float = DEFAULT_TIMEOUT_SEC,
) -> dict[str, Any]:
    """Send a scan batch IF the server has the scanner enabled.

    Flow:
    1. GET /api/v1/scanner-config; if ``enabled=false`` return without POST.
    2. POST /api/v1/scan-content with the batch.
    3. Log per-item result summary (path + risk_score + cached) at INFO.
       NEVER log content bytes.

    Never raises:
    - Network/timeout/5xx → returns ``{"error": "<reason>"}``, logs at ERROR.
    - ``items`` empty → returns ``{"skipped": "no_items"}`` without HTTP I/O.
    - Scanner disabled server-side → returns ``{"skipped": "scanner_disabled"}``.

    ``transport`` is for testing with :class:`httpx.MockTransport`; production
    callers omit it and get the default transport.
    """
    if not items:
        return {"skipped": "no_items"}

    base = server_url.rstrip("/")
    headers = {"X-CCGuard-Token": token}

    client_kwargs: dict[str, Any] = {"timeout": timeout_sec, "headers": headers}
    if transport is not None:
        client_kwargs["transport"] = transport

    try:
        with httpx.Client(**client_kwargs) as client:
            # --- 1. Probe enabled flag ---
            try:
                r_cfg = client.get(f"{base}/api/v1/scanner-config")
            except httpx.HTTPError as exc:
                logger.error("inventory_scan: /scanner-config request failed: %s", exc)
                return {"error": f"config_unreachable: {exc.__class__.__name__}"}

            if r_cfg.status_code != 200:
                logger.warning(
                    "inventory_scan: /scanner-config returned %d; skipping scan",
                    r_cfg.status_code,
                )
                return {"skipped": f"config_status_{r_cfg.status_code}"}

            try:
                cfg = ScannerConfig.model_validate(r_cfg.json())
            except Exception as exc:  # noqa: BLE001 — server returned junk; skip
                logger.warning("inventory_scan: /scanner-config returned invalid JSON: %s", exc)
                return {"error": "config_invalid"}

            if not cfg.enabled:
                logger.info("inventory_scan: scanner disabled server-side; skipping")
                return {"skipped": "scanner_disabled"}

            # --- 2. POST batch ---
            req = ScanRequest(items=items)
            try:
                r_scan = client.post(
                    f"{base}/api/v1/scan-content",
                    json=req.model_dump(mode="json"),
                )
            except httpx.HTTPError as exc:
                logger.error("inventory_scan: /scan-content request failed: %s", exc)
                return {"error": f"scan_unreachable: {exc.__class__.__name__}"}

            if r_scan.status_code != 200:
                logger.error(
                    "inventory_scan: /scan-content returned status=%d body_size=%d",
                    r_scan.status_code,
                    len(r_scan.content or b""),
                )
                return {"error": f"scan_status_{r_scan.status_code}"}

            try:
                resp = ScanBatchResponse.model_validate(r_scan.json())
            except Exception as exc:  # noqa: BLE001 — malformed; surface but don't crash
                logger.error("inventory_scan: /scan-content returned invalid JSON: %s", exc)
                return {"error": "scan_response_invalid"}

            # --- 3. Privacy-safe summary log (NO content, NO base64) ---
            for ri in resp.items:
                logger.info(
                    "scan result: file_path=%s risk_score=%s cached=%s truncated=%s error=%s",
                    ri.file_path,
                    ri.risk_score,
                    ri.cached,
                    ri.truncated,
                    ri.error,
                )

            return resp.model_dump(mode="json")

    except Exception as exc:  # noqa: BLE001 — last-resort safety net
        logger.error("inventory_scan: unexpected error: %s", exc, exc_info=True)
        return {"error": "unexpected"}


def run_scan_cycle(
    *,
    claude_home: Path,
    server_url: str,
    token: str,
) -> dict[str, Any]:
    """One-shot collect + send. Called from the CLI ``sync`` after inventory
    POST succeeds. Never raises (scan must not fail the inventory cycle).

    Ships two streams in one batch: config artifacts (agents/skills) and the
    P5 read-scan backstop spool (scope=read_file). Config artifacts take
    priority for the 50-item batch cap; read-scan items fill the remainder and
    are deleted from the spool only once the server has processed the batch
    (response carries ``items``), so a failed/skipped sync re-ships next cycle.
    """
    config_items = collect_scannable_files(claude_home)
    read_budget = max(0, _MAX_BATCH_ITEMS - len(config_items))
    read_items, spool_paths = collect_read_scan_items(max_items=read_budget)
    items = config_items + read_items

    result = send_scan_batch(server_url=server_url, token=token, items=items)

    # Delete spooled entries only if the server actually processed the batch
    # (a successful POST returns an ``items`` list). Skipped/errored results
    # leave the spool intact for the next cycle (bounded by the spool cap).
    if spool_paths and isinstance(result, dict) and "items" in result:
        try:
            read_scan_spool.delete(spool_paths)
        except Exception:  # noqa: BLE001
            pass
    return result
