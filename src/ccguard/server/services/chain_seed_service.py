"""Chain-scenario seed loader (ТЗ-09).

Same hybrid pattern as the other seed services: a version-controlled vetted seed
(``data/chain_scenarios_seed.yaml``) loads idempotently at startup. Adding a
scenario is editing that file — no code. Insert-or-skip on ``scenario_key`` (and
per-step on (scenario_key, step_index)); never overwrites admin edits. Never
raises: a broken/missing seed logs a warning and loads nothing.
"""
from __future__ import annotations

import logging
from pathlib import Path

from sqlmodel import Session, select

from ccguard.server.db.models import ChainScenario, ChainStep
from ccguard.server.services import seed_yaml_cache

log = logging.getLogger(__name__)

_SCENARIO_FIELDS = frozenset(
    {"scenario_key", "name", "description", "window_seconds", "severity",
     "enabled", "require_order", "source"}
)
_SCENARIO_REQUIRED = ("scenario_key", "name")
_STEP_FIELDS = frozenset({"scenario_key", "step_index", "tactic", "optional", "description"})
_STEP_REQUIRED = ("step_index", "tactic")


def default_seed_path() -> Path:
    return Path(__file__).resolve().parent.parent / "data" / "chain_scenarios_seed.yaml"


def _read_seed(seed_path: Path) -> list[dict]:
    try:
        if not seed_path.exists():
            log.warning("chain seed: file not found at %s — loading nothing", seed_path)
            return []
        data = seed_yaml_cache.load_yaml(seed_path) or {}
    except Exception as exc:  # noqa: BLE001 — broken seed must not crash boot
        log.warning("chain seed: failed to parse %s: %s", seed_path, exc)
        return []
    scenarios = data.get("scenarios") if isinstance(data, dict) else None
    if not isinstance(scenarios, list):
        log.warning("chain seed: no 'scenarios' list in %s", seed_path)
        return []
    return [e for e in scenarios if isinstance(e, dict)]


def load_chain_seed(session: Session, seed_path: Path | None = None) -> int:
    """Idempotently load chain scenarios + their steps. Returns rows inserted
    (scenarios + steps). Insert-or-skip; never overwrites existing rows."""
    path = seed_path if seed_path is not None else default_seed_path()
    entries = _read_seed(path)
    if not entries:
        return 0

    existing_scen = {r.scenario_key for r in session.exec(select(ChainScenario)).all()}
    existing_steps = {
        (r.scenario_key, r.step_index) for r in session.exec(select(ChainStep)).all()
    }
    inserted = 0
    for entry in entries:
        if not all(entry.get(k) for k in _SCENARIO_REQUIRED):
            log.warning("chain seed: skipping scenario missing keys: %r", entry)
            continue
        key = entry["scenario_key"]
        steps = entry.get("steps")
        if key not in existing_scen:
            fields = {k: v for k, v in entry.items() if k in _SCENARIO_FIELDS}
            session.add(ChainScenario(**fields))
            existing_scen.add(key)
            inserted += 1
        if isinstance(steps, list):
            for step in steps:
                if not isinstance(step, dict):
                    continue
                if not all(k in step for k in _STEP_REQUIRED):
                    log.warning("chain seed: skipping step missing keys in %s: %r", key, step)
                    continue
                pair = (key, step["step_index"])
                if pair in existing_steps:
                    continue
                sfields = {k: v for k, v in step.items() if k in _STEP_FIELDS}
                sfields["scenario_key"] = key
                session.add(ChainStep(**sfields))
                existing_steps.add(pair)
                inserted += 1

    if inserted:
        session.commit()
    return inserted


def list_scenarios(session: Session) -> list[dict]:
    """Active scenarios with their stage-steps — for audit dumps / future UI."""
    out: list[dict] = []
    for sc in session.exec(select(ChainScenario).order_by(ChainScenario.scenario_key)).all():
        steps = session.exec(
            select(ChainStep)
            .where(ChainStep.scenario_key == sc.scenario_key)
            .order_by(ChainStep.step_index)
        ).all()
        out.append(
            {
                "scenario_key": sc.scenario_key,
                "name": sc.name,
                "enabled": sc.enabled,
                "window_seconds": sc.window_seconds,
                "severity": sc.severity,
                "require_order": sc.require_order,
                "steps": [
                    {"step_index": s.step_index, "tactic": s.tactic, "optional": s.optional}
                    for s in steps
                ],
            }
        )
    return out
