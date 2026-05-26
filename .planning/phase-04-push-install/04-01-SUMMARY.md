---
phase: 04-push-install
plan: 01
subsystem: schemas + server.db
tags: [schema, sqlmodel, pydantic, policy, backward-compat]
requires:
  - .planning/phase-04-push-install/04-CONTEXT.md
  - .planning/phase-04-push-install/04-RESEARCH.md
  - src/ccguard/schemas/_base.py
provides:
  - "Pydantic v2 models: RequiredMCPServer, RequiredSkill, RequiredAgent, ManagedClaudeMdBlock"
  - "Policy extended with 4 optional list sections (additive, schema_version unchanged at 1)"
  - "Policy.model_config['extra'] = 'ignore' for v0.1 forward-compat"
  - "PolicyApplyEvent SQLModel table + composite indexes (machine_id,ts) and (result,ts)"
affects:
  - src/ccguard/schemas/policy.py
  - src/ccguard/server/db/models.py
  - src/ccguard/server/db/__init__.py
key-files:
  created:
    - tests/unit/test_policy_mandatory_schema.py
    - tests/unit/test_policy_apply_event_model.py
  modified:
    - src/ccguard/schemas/policy.py
    - src/ccguard/server/db/models.py
    - src/ccguard/server/db/__init__.py
decisions:
  - "D-1 enforced: schema_version stays 1; new fields additive; Policy.extra='ignore' overrides SchemaBase.forbid"
  - "result column stored as TEXT (Phase 1+2 SQLite-portability pattern); Pydantic field_validator gates {'success','rollback'} at model_validate"
  - "D-3 honored: no orphan_deletion fields on PolicyApplyEvent (deferred to v0.3)"
  - "D-5 honored: RequiredSkill.content is single field holding full file (frontmatter + body)"
  - "D-6 honored: schema kept flat — no nested editor; UI handles MCP args/env as JSON textarea in plan 02"
metrics:
  duration_minutes: 12
  completed: 2026-05-26
  tasks_completed: 2
  new_tests: 16
  unit_baseline_before: 383
  unit_baseline_after: 399
  full_suite_before: "545 passed / 8 failed (pre-existing e2e+integration infra)"
  full_suite_after: "561 passed / 8 failed (same pre-existing failures)"
---

# Phase 04 Plan 01: Schema foundation for push-install Summary

Pydantic v2 policy schema is now additively extended with four optional
mandatory-sections (`required_mcp_servers`, `required_skills`,
`required_agents`, `managed_claude_md_blocks`) and `extra='ignore'`, while a
new `PolicyApplyEvent` SQLModel + composite indexes give the server a place
to land agent-reported apply outcomes for plans 02–05.

## What landed

### Pydantic models (`src/ccguard/schemas/policy.py`)

| Model                  | Fields                                                          |
| ---------------------- | --------------------------------------------------------------- |
| `RequiredMCPServer`    | `name: str`, `command: str`, `args: list[str]=[]`, `env: dict[str,str]={}` |
| `RequiredSkill`        | `name: str`, `frontmatter_type: str="skill"`, `content: str` (full file: frontmatter + body, D-5) |
| `RequiredAgent`        | `name: str`, `content: str`                                     |
| `ManagedClaudeMdBlock` | `id: str` (kebab-case `^[a-z0-9]+(-[a-z0-9]+)*$`), `description: str=""`, `content: str` |

`Policy` gets four new optional `list[...]` fields, each defaulting to `[]`
via `Field(default_factory=list)`. `Policy.model_config` sets
`extra='ignore'` (overrides `SchemaBase`'s `extra='forbid'`) — confirmed via
backward-compat test: a v0.1 client reading a policy that contains an
unknown future section silently drops the unknown key instead of raising.

`schema_version` stays at `1` (locked D-1). No migration required.

### PolicyApplyEvent table (`src/ccguard/server/db/models.py`)

| Column            | Type        | Notes                                       |
| ----------------- | ----------- | ------------------------------------------- |
| `id`              | int PK      | autoincrement                               |
| `machine_id`      | str, index  | per-machine query path                      |
| `ts`              | datetime, index | default `_utcnow`                       |
| `result`          | str         | `{success, rollback}` gated by Pydantic field_validator at `model_validate` write boundary |
| `applied_count`   | int=0       |                                             |
| `snapshot_id`     | str \| None |                                             |
| `reason`          | str \| None | rollback explanation                        |
| `failed_file`     | str \| None | drives /audit drill-down                    |
| `policy_revision` | int         |                                             |

Composite indexes declared via `__table_args__`:
- **`ix_policy_apply_machine_ts`** on `(machine_id, ts)` — per-machine timeline
- **`ix_policy_apply_result_ts`** on `(result, ts)` — supports `/audit?event_source=policy_apply&result=rollback` (plan 05)

Per D-3 there are **no** `orphan_deletion_*` fields — deferred to v0.3.

`src/ccguard/server/db/__init__.py` now eagerly imports the models module and
re-exports `PolicyApplyEvent`, ensuring `SQLModel.metadata.create_all` picks
up the new table on every `init_db()` call.

## Tests added (16, all green)

`tests/unit/test_policy_mandatory_schema.py` (9 tests):
- Defaults for 4 new sections are empty lists
- Round-trip for each new section model
- `ManagedClaudeMdBlock.id` kebab-case enforcement (rejects underscore, uppercase, leading/trailing/double dash; accepts single & multi-segment)
- `extra='ignore'` proven: unknown future section silently dropped
- v0.1 fixture (no new sections) validates and dumps empty lists
- `schema_version` stays 1

`tests/unit/test_policy_apply_event_model.py` (7 tests):
- Success and rollback row round-trip
- `ix_policy_apply_machine_ts` and `ix_policy_apply_result_ts` created
- `create_all` registers `policyapplyevent` table
- End-to-end query (filter `result='rollback'`, order `ts desc`) returns expected ordering
- `model_validate` rejects `result` values outside `{success, rollback}`

## Verification

| Check                                                                   | Result |
| ----------------------------------------------------------------------- | ------ |
| `uv run pytest tests/unit/test_policy_mandatory_schema.py -x -q`        | PASS (9) |
| `uv run pytest tests/unit/test_policy_apply_event_model.py -x -q`       | PASS (7) |
| `uv run pytest tests/unit -q`                                           | 399 passed (was 383, +16) |
| `uv run pytest`                                                         | 561 passed / 8 failed (same 8 pre-existing e2e+integration infra failures as baseline; no new regressions) |
| `grep -n "extra.*ignore" src/ccguard/schemas/policy.py`                 | match (line 142) |
| `grep -n "schema_version" src/ccguard/schemas/policy.py`                | match (line 78: `Literal[1] = 1`) |
| `grep -n "class PolicyApplyEvent" src/ccguard/server/db/models.py`      | match (line 228) |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] `result: Literal[...]` is not assignable by SQLModel `table=True`**

- **Found during:** Task 2, GREEN phase
- **Issue:** Declaring `result: Literal["success","rollback"]` on a SQLModel `table=True` class raises `TypeError: issubclass() arg 1 must be a class` inside SQLModel's `get_sqlalchemy_type` — SQLModel cannot infer a SQLAlchemy column type from a `Literal`.
- **Fix:** Declared the column as plain `result: str` (matching the plan's "store as str for SQLite portability" guidance) and added a Pydantic `field_validator("result")` that restricts the set to `{"success", "rollback"}`. The validator runs at the `PolicyApplyEvent.model_validate({...})` write boundary, which is the canonical API path (SQLModel `table=True` deliberately bypasses Pydantic on `__init__` for SQLAlchemy compatibility — this is documented behavior, not a bug).
- **Test impact:** `test_policy_apply_event_result_literal_rejects_invalid_value` was written using `PolicyApplyEvent.model_validate({...})` to assert the canonical write boundary instead of `__init__`. Plan intent — "Pydantic-style validation rejects other values" — is fully satisfied.
- **Files modified:** `src/ccguard/server/db/models.py`, `tests/unit/test_policy_apply_event_model.py`
- **Commit:** `56dc307` (feat(04-01): add PolicyApplyEvent SQLModel with composite indexes)

No other deviations. Plan executed as written.

## Notes for downstream plans

- Plan 02 (admin UI): the policy form should treat `args` and `env` as a single JSON textarea each (D-6 already locked); validation happens at `Policy.model_validate` on save.
- Plan 03 (agent apply): when materialising MCP entries into `~/.claude/mcp.json` the agent will add the `_managed_by: "ccguard"` marker (D-7) — schema accepts this round-tripping today because mcp.json is written by the agent, not stored in the Policy model.
- Plan 05 (audit page): `PolicyApplyEvent` is the source table; filter on `result` uses `ix_policy_apply_result_ts` for the rollback-only view.

## Self-Check: PASSED

- src/ccguard/schemas/policy.py — FOUND
- src/ccguard/server/db/models.py — FOUND
- src/ccguard/server/db/__init__.py — FOUND
- tests/unit/test_policy_mandatory_schema.py — FOUND
- tests/unit/test_policy_apply_event_model.py — FOUND
- Commit a32b078 (test RED task 1) — FOUND
- Commit 4071322 (feat GREEN task 1) — FOUND
- Commit d5a77d8 (test RED task 2) — FOUND
- Commit 56dc307 (feat GREEN task 2) — FOUND
