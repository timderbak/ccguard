"""push_install — apply mandatory policy sections to the local Claude config.

PUSH-02 / PUSH-03 / PUSH-04. Best-effort: NEVER raises into the CLI caller —
on any exception the most-recent snapshot is restored byte-for-byte and an
`ApplyResult` dict with `result="rollback"` is returned.

Locked decisions (see plan 04-03 / 04-CONTEXT.md):
- D-2: snapshot scope is strictly the targeted files (no whole-tree backup).
- D-3: orphan deletion SKIPPED in v0.2 — no managed-manifest.json.
- D-4: only `~/CLAUDE.md` (user-home) is touched; project-scope deferred.
- D-5: `required_skills[].content` is the full file (frontmatter + body).
- D-7: managed MCP entries identified by `_managed_by: "ccguard"` field
  (NOT by key prefix — safer when a user names a server `ccguard-...`).

Stdlib only.
"""

from __future__ import annotations

import json
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

from ccguard.agent.atomic_io import atomic_write_bytes

__all__ = ["apply"]


def _assert_inside(path: Path, base: Path) -> None:
    """Defense-in-depth (CR-01): reject any computed target outside `base`.

    The Pydantic ``_SAFE_NAME_RE`` validator on ``RequiredSkill.name`` /
    ``RequiredAgent.name`` is the primary defense; this assertion is the
    belt-and-braces check so that a future schema regression cannot escape
    the ``~/.claude`` sandbox. Uses ``resolve(strict=False)`` so the file
    need not exist yet.
    """
    resolved = path.resolve(strict=False)
    base_resolved = base.resolve(strict=False)
    if not resolved.is_relative_to(base_resolved):
        raise ValueError(
            f"refusing to write outside sandbox: {resolved} not under {base_resolved}"
        )


# ---------------------------------------------------------------------------
# CLAUDE.md marker merge
# ---------------------------------------------------------------------------

# Backref on id: the end marker MUST match the same id as the start marker.
# Non-greedy DOTALL so the smallest body is captured even with multiple
# managed blocks in the file.
def _marker_re(block_id: str) -> re.Pattern[str]:
    return re.compile(
        rf"<!-- ccguard:managed start (?P<id>{re.escape(block_id)}) -->"
        r"\n(?P<body>.*?)\n"
        rf"<!-- ccguard:managed end (?P=id) -->",
        re.DOTALL,
    )


def _render_block(block_id: str, content: str) -> str:
    return (
        f"<!-- ccguard:managed start {block_id} -->\n"
        f"{content}\n"
        f"<!-- ccguard:managed end {block_id} -->"
    )


def _merge_claude_md_blocks(existing: str, blocks: list[dict]) -> str:
    """Update/insert managed blocks in CLAUDE.md.

    - Existing block (matched by id-backref regex): body replaced in-place.
    - Missing block: appended to end with one blank-line separator.
    - Blocks NOT in `blocks` are preserved (D-3: no orphan deletion).
    """
    out = existing
    for block in blocks:
        block_id = block["id"]
        content = block["content"]
        rendered = _render_block(block_id, content)
        pattern = _marker_re(block_id)
        if pattern.search(out):
            out = pattern.sub(lambda _m, r=rendered: r, out, count=1)
        else:
            # Append with one blank-line separator (and ensure trailing newline)
            if out and not out.endswith("\n"):
                out += "\n"
            sep = "\n" if out else ""
            out = f"{out}{sep}{rendered}\n"
    if out and not out.endswith("\n"):
        out += "\n"
    return out


# ---------------------------------------------------------------------------
# MCP server merge
# ---------------------------------------------------------------------------

_MANAGED_MARKER = "ccguard"


def _merge_mcp_servers(existing_json: dict, required: list[dict]) -> dict:
    """Return a new ~/.claude.json dict with managed MCP entries updated.

    - Removes every entry where `entry.get("_managed_by") == "ccguard"` (D-7).
    - Adds each `required` entry keyed by its `name`, with `_managed_by` set.
    - User entries are preserved verbatim. Top-level fields are preserved.
    """
    out = dict(existing_json) if existing_json else {}
    servers = dict(out.get("mcpServers", {}) or {})

    # Remove old managed entries by field, NOT key prefix (D-7).
    servers = {
        k: v
        for k, v in servers.items()
        if not (isinstance(v, dict) and v.get("_managed_by") == _MANAGED_MARKER)
    }

    for entry in required:
        entry = dict(entry)
        name = entry.pop("name")
        entry["_managed_by"] = _MANAGED_MARKER
        servers[name] = entry

    out["mcpServers"] = servers
    return out


# ---------------------------------------------------------------------------
# Snapshot / restore
# ---------------------------------------------------------------------------


def _snapshot_id_now() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def _allocate_snapshot_dir(snapshots_root: Path) -> Path:
    snapshots_root.mkdir(parents=True, exist_ok=True)
    base = _snapshot_id_now()
    candidate = snapshots_root / base
    n = 1
    while candidate.exists():
        candidate = snapshots_root / f"{base}-{n}"
        n += 1
    candidate.mkdir(parents=True)
    return candidate


def _snapshot(
    target_paths: list[Path], snapshots_root: Path, home: Path
) -> tuple[Path, dict[Path, Path]]:
    """Copy EXISTING target files into a fresh snapshot dir.

    Returns (snapshot_dir, mapping from original_path → snapshot_path).
    The relative layout under `home` is mirrored inside snapshot_dir.
    """
    snap_dir = _allocate_snapshot_dir(snapshots_root)
    mapping: dict[Path, Path] = {}
    for src in target_paths:
        if not src.exists() or not src.is_file():
            continue
        try:
            rel = src.relative_to(home)
        except ValueError:
            rel = Path(src.name)
        dst = snap_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        mapping[src] = dst
    return snap_dir, mapping


def _prune_snapshots(snapshots_root: Path, keep: int = 5) -> None:
    if not snapshots_root.is_dir():
        return
    snaps = sorted(p for p in snapshots_root.iterdir() if p.is_dir())
    excess = snaps[:-keep] if len(snaps) > keep else []
    for old in excess:
        shutil.rmtree(old, ignore_errors=True)


def _restore(mapping: dict[Path, Path]) -> None:
    """Restore each snapshot file to its original location byte-for-byte."""
    for original, snap_file in mapping.items():
        try:
            data = snap_file.read_bytes()
            atomic_write_bytes(original, data)
        except Exception:
            # Best-effort restore; keep going.
            continue


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def _target_paths_for_policy(policy: dict, home: Path) -> list[Path]:
    paths: list[Path] = []
    for s in policy.get("required_skills") or []:
        paths.append(home / ".claude" / "skills" / s["name"] / "SKILL.md")
    for a in policy.get("required_agents") or []:
        paths.append(home / ".claude" / "agents" / f"{a['name']}.md")
    if policy.get("required_mcp_servers"):
        paths.append(home / ".claude.json")
    if policy.get("managed_claude_md_blocks"):
        paths.append(home / "CLAUDE.md")
    return paths


def apply(
    policy: dict,
    *,
    home: Path | None = None,
    ccguard_root: Path | None = None,
) -> dict[str, Any]:
    """Apply mandatory policy sections to local config files. Best-effort.

    Returns an ApplyResult dict:
      { "result": "success"|"rollback",
        "applied_count": int,
        "snapshot_id": str|None,
        "reason": str|None,
        "failed_file": str|None }

    Never raises into the caller — every exception becomes a rollback result.
    """
    home = home or Path.home()
    ccguard_root = ccguard_root or (home / ".ccguard")
    snapshots_root = ccguard_root / "snapshots"

    target_paths = _target_paths_for_policy(policy, home)

    snap_dir: Path | None = None
    snap_map: dict[Path, Path] = {}
    snapshot_id: str | None = None

    try:
        snap_dir, snap_map = _snapshot(target_paths, snapshots_root, home)
        snapshot_id = snap_dir.name
    except Exception as exc:
        return {
            "result": "rollback",
            "applied_count": 0,
            "snapshot_id": None,
            "reason": f"{type(exc).__name__}: {exc}",
            "failed_file": None,
        }

    current_file: Path | None = None
    applied = 0
    try:
        claude_root = home / ".claude"

        # 1. Skills
        for s in policy.get("required_skills") or []:
            current_file = home / ".claude" / "skills" / s["name"] / "SKILL.md"
            _assert_inside(current_file, claude_root)
            atomic_write_bytes(current_file, s["content"].encode("utf-8"))
            applied += 1

        # 2. Agents
        for a in policy.get("required_agents") or []:
            current_file = home / ".claude" / "agents" / f"{a['name']}.md"
            _assert_inside(current_file, claude_root)
            atomic_write_bytes(current_file, a["content"].encode("utf-8"))
            applied += 1

        # 3. MCP merge into ~/.claude.json
        if policy.get("required_mcp_servers"):
            current_file = home / ".claude.json"
            if current_file.exists():
                try:
                    existing_json = json.loads(current_file.read_text(encoding="utf-8"))
                    if not isinstance(existing_json, dict):
                        existing_json = {}
                except json.JSONDecodeError:
                    existing_json = {}
            else:
                existing_json = {}
            merged = _merge_mcp_servers(existing_json, policy["required_mcp_servers"])
            # CR-02: ~/.claude.json holds admin-supplied MCP `env` dicts that
            # are documented as the channel for API keys / tokens. On multi-
            # user dev hosts (CCGuard's target environment) world-readable
            # mode would leak those secrets to every local UID.
            atomic_write_bytes(
                current_file,
                (json.dumps(merged, indent=2) + "\n").encode("utf-8"),
                mode=0o600,
            )
            applied += 1

        # 4. CLAUDE.md marker merge (D-4: user-home only)
        if policy.get("managed_claude_md_blocks"):
            current_file = home / "CLAUDE.md"
            existing_text = (
                current_file.read_text(encoding="utf-8") if current_file.exists() else ""
            )
            merged_text = _merge_claude_md_blocks(
                existing_text, policy["managed_claude_md_blocks"]
            )
            atomic_write_bytes(current_file, merged_text.encode("utf-8"))
            applied += 1

    except Exception as exc:
        # Rollback: restore snapshot, then prune.
        _restore(snap_map)
        _prune_snapshots(snapshots_root)
        return {
            "result": "rollback",
            "applied_count": applied,
            "snapshot_id": snapshot_id,
            "reason": f"{type(exc).__name__}: {exc}",
            "failed_file": str(current_file) if current_file else None,
        }

    # Success: prune older snapshots.
    _prune_snapshots(snapshots_root)
    return {
        "result": "success",
        "applied_count": applied,
        "snapshot_id": snapshot_id,
        "reason": None,
        "failed_file": None,
    }
