---
phase: 04-push-install
reviewed: 2026-05-26T00:00:00Z
re_reviewed: 2026-05-26T00:00:00Z
depth: standard
iteration: 2
files_reviewed: 13
files_reviewed_list:
  - src/ccguard/schemas/policy.py
  - src/ccguard/schemas/audit.py
  - src/ccguard/server/db/models.py
  - src/ccguard/server/db/__init__.py
  - src/ccguard/server/api/audit.py
  - src/ccguard/server/web/routes.py
  - src/ccguard/server/web/policy_form.py
  - src/ccguard/server/web/templates/policy_editor.html
  - src/ccguard/server/web/templates/policy_editor_mandatory.html
  - src/ccguard/server/web/templates/audit_feed.html
  - src/ccguard/server/web/templates/components/_audit_policy_apply_table.html
  - src/ccguard/server/web/templates/components/_mandatory_section_required_mcp_servers.html
  - src/ccguard/server/web/templates/components/_mandatory_section_required_skills.html
  - src/ccguard/server/web/templates/components/_mandatory_section_managed_claude_md_blocks.html
  - src/ccguard/server/web/templates/components/_mandatory_row_required_mcp_servers.html
  - src/ccguard/server/web/templates/components/_mandatory_row_required_skills.html
  - src/ccguard/server/web/templates/components/_mandatory_row_required_agents.html
  - src/ccguard/server/web/templates/components/_mandatory_row_managed_claude_md_blocks.html
  - src/ccguard/server/web/templates/components/_policy_tab_strip.html
  - src/ccguard/agent/atomic_io.py
  - src/ccguard/agent/push_install.py
  - src/ccguard/agent/sync.py
  - src/ccguard/agent/cli.py
findings:
  critical: 0
  warning: 0
  info: 5
  total: 5
status: clean
fixed_at: 2026-05-26T00:00:00Z
fix_iteration: 1
fix_scope: critical_warning
fix_summary:
  fixed: 11
  skipped: 5  # all Info (out of scope per --fix critical+warning)
test_baseline: 638
test_final: 638
re_review_test_count: 638
---

# Phase 4: Code Review Report (Iteration 2 — Re-review)

**Reviewed:** 2026-05-26 (iteration 1) / 2026-05-26 (iteration 2 re-review)
**Depth:** standard
**Files Reviewed:** ~20 (sources + templates)
**Status:** clean (Critical + Warning resolved; Info out of scope)

## Re-review Summary (iteration 2)

All 2 Critical (CR-01, CR-02) and all 9 Warning (WR-01..WR-09) findings from iteration 1
were verified resolved by direct source inspection of commits
`77b6b59, 2541643, e4fd435, f159823, f69c765, 369c0f7, 8e9e8a0, ca26a19, 9ff0595, 9b3fffc, fbd060a`.
The full test suite (excluding the network-dependent `tests/e2e/` suite, per project convention)
runs `638 passed`, matching the iteration-1 baseline exactly. No new BLOCKER or WARNING-tier
defects surfaced during re-inspection of the fix surfaces:

- **CR-01** — Verified: `_SAFE_NAME_RE` and `_validate_safe_name` live in `schemas/policy.py:22,25`,
  wired to both `RequiredSkill.name` (l.150) and `RequiredAgent.name` (l.162). Defense-in-depth
  `is_relative_to(base_resolved)` guard active in `push_install.py:43`. Adversarial spot-check:
  values `"../etc/passwd"`, `"/abs"`, `"."`, `".."`, and `"a/b"` all fail the validator; absolute
  paths and traversal segments cannot reach `atomic_write_bytes`.
- **CR-02** — Verified: `atomic_write_bytes(path, data, *, mode: int = 0o644)` exposes a keyword-
  only mode (`atomic_io.py:20`), and `push_install.apply` passes `mode=0o600` exactly at the
  `~/.claude.json` write site (`push_install.py:350`). Docstring no longer claims umask respect.
- **WR-01** — `_split_fenced` (`push_install.py:80`) tokenizes fenced/unfenced segments;
  marker pattern runs only on unfenced text (l.111). Documentation examples inside ``` fences
  survive sync.
- **WR-02** — `MANDATORY_DUPLICATE_COPY` (`policy_form.py:46`) raised at all four parser sites:
  `required_mcp_servers` (l.181), `required_skills` (l.233), `required_agents` (l.261),
  `managed_claude_md_blocks` (l.285).
- **WR-03** — `Policy.model_validate(policy)` re-validation gate in `sync.py:284`, immediately
  before `push_install_apply`. Chains with CR-01's schema validator to foreclose local-cache-
  tamper arbitrary writes.
- **WR-04** — `dict(out.get("mcpServers", {}) or {})` replaced with
  `isinstance(servers_raw, dict)` coercion (`push_install.py:170`). Same idiom mirrors the
  JSON-load path at l.336.
- **WR-05** — `PolicyApplyEventPayload` (`audit.py:40`) and `PolicyApplyBatchIn` (`audit.py:76`)
  each declare `model_config = ConfigDict(extra="ignore", ...)`, overriding the inherited
  `SchemaBase.extra="forbid"`. Forward-compat for v0.3 fields (e.g. `token_id`) is now safe.
- **WR-06** — `_apply_and_report` no longer short-circuits the empty no-op case; all outcomes
  POST to `/api/v1/audit`. Test `*_posts_noop_audit` asserts the row is persisted with
  `applied_count==0`.
- **WR-07** — MCP args switched to one-per-line via `_lines_to_list` and `<textarea>`. Label
  updated to `args (по одному на строку)`. `_build_mandatory_sections_view` joins with `\n`.
- **WR-08** — `__slots__` removed from `_FindingVM` (`routes.py:200`). Historical comment now
  points to the actual URL-encoding defense location (`_finding_row.html`).
- **WR-09** — `_post_policy_apply_event` logs only `status_code` + category
  (`client_error`/`server_error`) on 4xx/5xx (`sync.py:241-249`); response body no longer hits
  the log stream. Protects against reverse-proxy header echo leaking `X-CCGuard-Token`.

**Phase 1-3 untouched:** All 11 fix commits touch only Phase 4 surfaces
(`src/ccguard/{schemas,agent,server}/...` files explicitly enumerated in iteration-1 scope) and
their tests under `tests/`. `git show --stat` confirms no file outside the Phase 4 scope was
modified.

**Test posture:** `uv run pytest --ignore=tests/e2e` → `638 passed, 122 warnings in 30.73s`.
No regressions; baseline preserved.

**No new defects surfaced.** Iteration 2 closes Critical + Warning tiers. Info findings
(IN-01..IN-05) remain documented below for future cleanup but were out of scope for
`--fix critical_warning` and are not blockers.

---

## Iteration-1 Findings (historical — all resolved)

## Summary (iteration 1)

The Phase 4 push-install plumbing is well-structured: best-effort wrapper, snapshot-and-rollback contract, server-side `_managed_by` injection, schema-versioned policy_apply branch, and shared CSRF/session machinery. However adversarial review surfaces two **CRITICAL** trust-boundary defects on the agent side: (a) path traversal via unvalidated `RequiredSkill.name` / `RequiredAgent.name` from the policy, which lets a compromised server OR local cache tamperer write arbitrary files under `~`, and (b) `atomic_write_bytes` writes world-readable `0o644` to `~/.claude.json`, which is the destination for managed MCP entries whose `env` is supplied by admins through the UI and is documented (admin guidance) as a place where secrets land.

Beyond those, the marker-merge logic is regex-driven over the entire CLAUDE.md body (including content inside fenced code blocks), there is no duplicate-id / duplicate-MCP-name detection at the form parser, and the audit payload schemas use `extra="forbid"` which will cause forward-compat 422s the moment v0.3 adds a field.

XSS surface is clean (Jinja2 default autoescape covers `.html` files; user-controlled `content`/`reason`/`failed_file` go through `{{ }}`). CSRF coverage on `/policy/draft`, `/policy/publish` is present. SQL is parameterized via SQLAlchemy. Best-effort wrapping correctly preserves `KeyboardInterrupt`/`SystemExit` propagation.

## Critical Issues

### CR-01: Path traversal in `RequiredSkill.name` / `RequiredAgent.name` — agent writes outside `~/.claude`

> **RESOLVED** (2026-05-26, commit 77b6b59) — `_validate_safe_name` Pydantic field_validator on both `RequiredSkill.name` and `RequiredAgent.name` rejects `/`, `\`, `.`, `..`, and anything not matching `^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`. Defense-in-depth: `push_install.apply` now asserts each computed target file path `is_relative_to(home/.claude)` before writing.
> **RE-VERIFIED** (iteration 2, 2026-05-26): validator present at `schemas/policy.py:22,25,150,162`; apply-time guard at `push_install.py:43`. 638/638 tests green.

**Files:**
- `src/ccguard/schemas/policy.py:112-128`
- `src/ccguard/agent/push_install.py:242-251`

**Issue:** `RequiredSkill` and `RequiredAgent` declare `name: str` with no validator. `push_install.apply` constructs the target path as:

```python
home / ".claude" / "skills" / s["name"] / "SKILL.md"
home / ".claude" / "agents" / f"{a['name']}.md"
```

A `name` value of `"../../../tmp/evil"` (or `"../.bashrc/"`) escapes `~/.claude/...` and writes arbitrary content (the admin-supplied `content`) to any path the user can write. The threat actors here are:

1. A compromised central server (the agent is supposed to be the last line of defense against exactly this kind of supply-chain risk per `CLAUDE.md` "Core Value");
2. A local user/process with write access to the policy cache (`policy.yaml`) — `_apply_and_report` in `sync.py:267` calls `push_install_apply` with a raw `yaml.safe_load(cache)` dict, never re-validating through `Policy`. Combined with `Policy(extra="ignore")` and the missing per-name validator, a tampered cache yields direct arbitrary writes.

Also note: `home / ".claude" / "skills" / s["name"]` with absolute `s["name"]` (e.g. `"/etc/cron.d/evil"`) — `pathlib` resolves `Path('/x/y') / '/abs'` to `/abs`, so absolute names also escape.

**Fix:**

```python
# in policy.py
_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$")

class RequiredSkill(SchemaBase):
    name: str
    ...
    @field_validator("name")
    @classmethod
    def _safe_name(cls, v: str) -> str:
        if not _NAME_RE.match(v) or v in {".", ".."} or "/" in v or "\\" in v:
            raise ValueError(f"name must be a safe single-segment identifier: {v!r}")
        return v
```

Apply identical validation to `RequiredAgent.name`. Additionally, in `push_install._target_paths_for_policy` / `apply`, defensively assert `resolved.is_relative_to(home / ".claude")` before each write — defense in depth so that even a future schema regression cannot escape the sandbox.

---

### CR-02: `~/.claude.json` written world-readable (0o644) — leaks MCP env-secret values on multi-user hosts

> **RESOLVED** (2026-05-26, commit 2541643) — `atomic_write_bytes` accepts a keyword-only `mode` parameter (default `0o644`). Misleading "umask-respecting" claim dropped from docstring. `push_install.apply` passes `mode=0o600` when writing `~/.claude.json` so admin-supplied MCP env-secrets are not world-readable.
> **RE-VERIFIED** (iteration 2, 2026-05-26): `atomic_io.py:20` signature confirmed; `push_install.py:350` passes `mode=0o600`. 638/638 tests green.

**File:** `src/ccguard/agent/atomic_io.py:48-50`

**Issue:** The docstring says "Final file permissions default to 0o644 (umask-respecting)" — this is false on two counts:

1. `os.chmod(tmp_path, 0o644)` sets the mode **exactly** to `0o644`. It does NOT respect umask; `umask` only affects creation, not explicit `chmod`.
2. `0o644` is world-readable. The target list in `_target_paths_for_policy` includes `~/.claude.json`, which holds merged MCP entries. The Phase 4 UI accepts arbitrary `env: dict[str,str]` JSON from the admin — that is the documented channel through which API keys / tokens for MCP servers are configured. On a multi-user dev box (the CCGuard target environment — "developer endpoints"), any other local UID can read `~/.claude.json` and exfiltrate those env values.

The same applies to `~/CLAUDE.md` (managed content may include sensitive operational text — e.g. an internal-only `claudeMd` like the one in this repo's `CLAUDE.md`).

**Fix:** Make the mode caller-controlled, default to `0o600`, and never write secrets-bearing files as world-readable:

```python
def atomic_write_bytes(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    ...
    os.chmod(tmp_path, mode)
    os.replace(tmp_path, path)
```

In `push_install.apply`, write `~/.claude.json` with `mode=0o600` unconditionally. Update the docstring — drop the "umask-respecting" claim. Add a unit test that asserts `(~/.claude.json).stat().st_mode & 0o077 == 0` after apply.

## Warnings

### WR-01: `_merge_claude_md_blocks` regex matches markers inside fenced code blocks

> **RESOLVED** (2026-05-26, commit e4fd435) — New `_split_fenced` helper tokenizes the existing CLAUDE.md text into unfenced and fenced segments. The marker pattern now only runs over unfenced segments; fenced content is reassembled byte-for-byte after substitution. Documentation examples of the marker syntax inside ```` ``` ```` fences are no longer overwritten on sync.
> **RE-VERIFIED** (iteration 2, 2026-05-26): `push_install.py:80,111` confirmed; 638/638 tests green.

**File:** `src/ccguard/agent/push_install.py:39-78`

**Issue:** The marker regex is `re.DOTALL` and runs over the raw text. If an admin (or a teammate writing CLAUDE.md) documents the marker syntax inside a triple-backtick code fence, the agent will treat that fenced example as a managed block and overwrite its body — silently corrupting documentation on the next sync. There is no awareness of markdown structure.

**Fix:** Document the limitation prominently (the marker pair MUST NOT appear inside fenced blocks, even as an example) and reject (or escape) content that contains `<!-- ccguard:managed ` at parse time on the server. A simple gate in `_parse_managed_claude_md_blocks`:

```python
if "<!-- ccguard:managed " in content:
    raise MandatorySectionError("managed_claude_md_blocks", "content cannot contain a managed-block marker")
```

---

### WR-02: No duplicate-id / duplicate-name detection in mandatory form parsers

> **RESOLVED** (2026-05-26, commit f159823) — Each `_parse_required_*` function (mcp_servers, skills, agents, managed_claude_md_blocks) tracks a per-section seen-set and raises `MandatorySectionError` with locked Russian `MANDATORY_DUPLICATE_COPY` on collision.
> **RE-VERIFIED** (iteration 2, 2026-05-26): all four sites at `policy_form.py:181,233,261,285`; 638/638 tests green.

**Files:**
- `src/ccguard/server/web/policy_form.py:154-249`
- `src/ccguard/agent/push_install.py:56-79, 89-113`

**Issue:** `_parse_required_mcp_servers`, `_parse_required_skills`, `_parse_required_agents`, `_parse_managed_claude_md_blocks` all append rows in form order without checking for duplicates. On the agent side:

* Duplicate `RequiredMCPServer.name` → `_merge_mcp_servers` last-wins, earlier entries silently lost.
* Duplicate `ManagedClaudeMdBlock.id` → `_merge_claude_md_blocks` runs both `pattern.sub` calls; the second overwrites the first, so only one block survives.
* Duplicate `RequiredSkill.name` / `RequiredAgent.name` → second write clobbers the first file.

Admin gets no UI feedback; the policy diff looks fine; behavior diverges silently from intent.

**Fix:** In each `_parse_required_*` function, detect duplicate keys and raise `MandatorySectionError` with a locked Russian message ("Дубликат: name/id должен быть уникален").

---

### WR-03: Agent does not re-validate cached policy through `Policy` before applying

> **RESOLVED** (2026-05-26, commit f69c765) — `_apply_and_report` now round-trips the policy dict through `Policy.model_validate` immediately before `push_install_apply`. On `ValidationError` (or any unexpected exception) the apply is skipped with a WARNING log. Chains with CR-01's name-validator to foreclose local-cache-tamper arbitrary-write attacks.
> **RE-VERIFIED** (iteration 2, 2026-05-26): re-validation gate at `sync.py:284`; 638/638 tests green.

**Files:**
- `src/ccguard/agent/cli.py:170-188`
- `src/ccguard/agent/sync.py:249-289`

**Issue:** `_apply_and_report_safe` reads the cache as raw YAML and forwards the resulting `dict` to `push_install_apply`. The validation that happened at `sync.perform_sync` time only proves the *server response* was valid — not that the on-disk cache still is. A local attacker who can write to `~/.config/ccguard/policy.yaml` (same UID, common on dev workstations) can inject arbitrary `required_skills` / `required_agents` / managed blocks. Combined with **CR-01**, that is direct arbitrary write.

**Fix:** Round-trip through `Policy.model_validate` immediately before calling `push_install.apply`. On `ValidationError`, skip apply and emit a single WARNING log line. This costs ~1 ms and forecloses a whole class of local-tamper attacks.

```python
try:
    Policy.model_validate(policy_dict)
except ValidationError as exc:
    _log.warning("policy cache validation failed; skipping apply: %s", exc)
    return
```

---

### WR-04: `_merge_mcp_servers` crashes on non-dict `mcpServers` value (only mitigated by outer try)

> **RESOLVED** (2026-05-26, commit 369c0f7) — `_merge_mcp_servers` now coerces a non-dict `mcpServers` value via `isinstance(..., dict)` to an empty dict, matching the JSON-load idiom one level up. A corrupted `~/.claude.json` no longer triggers an infinite rollback loop.
> **RE-VERIFIED** (iteration 2, 2026-05-26): coercion at `push_install.py:170`; 638/638 tests green.

**File:** `src/ccguard/agent/push_install.py:96-104`

**Issue:** `dict(out.get("mcpServers", {}) or {})` — if `~/.claude.json` contains `"mcpServers": []` or `"mcpServers": "x"`, `dict([])` works but `dict("x")` raises `ValueError`. The outer `apply` `except Exception` swallows this into rollback — but then EVERY apply cycle rolls back forever (the user's malformed file isn't repaired). Recovery requires manual editing.

**Fix:** Coerce defensively:

```python
servers_raw = out.get("mcpServers")
servers = dict(servers_raw) if isinstance(servers_raw, dict) else {}
```

Same coercion already protects the JSON-load path (`if not isinstance(existing_json, dict): existing_json = {}` at `push_install.py:259-262`) — apply the same idiom one level deeper.

---

### WR-05: Audit-event Pydantic schemas use `extra="forbid"` — forward-compat trap

> **RESOLVED** (2026-05-26, commit 8e9e8a0) — `PolicyApplyEventPayload` and `PolicyApplyBatchIn` each override `model_config` with `extra="ignore"`. Future agent versions can add fields like `token_id` without 422-ing on v0.2 servers.
> **RE-VERIFIED** (iteration 2, 2026-05-26): `audit.py:40` and `audit.py:76`; 638/638 tests green.

**File:** `src/ccguard/schemas/audit.py:27-63` (inherits `SchemaBase(extra="forbid")`)

**Issue:** The plan-04-04 docstring claims backward-compat for `schema_version`, but `PolicyApplyEventPayload` and `PolicyApplyBatchIn` both inherit `extra="forbid"` from `SchemaBase`. The moment a v0.3 agent posts a new field (e.g. `token_id` from the documented v0.3 plan in `audit.py:30`), the v0.2 server returns 422 and the audit event is lost. The `event_source` discriminator pattern in `audit.py` route is the right shape; the inner payloads should match.

**Fix:** Override the inner schemas to `extra="ignore"` (matches `Policy`'s pattern, line `policy.py:156-160`):

```python
class PolicyApplyEventPayload(SchemaBase):
    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True)
    ...
```

---

### WR-06: Empty no-op success silently never reported — admin cannot tell agent vs broken policy

> **RESOLVED** (2026-05-26, commit ca26a19) — Removed the no-op skip in `_apply_and_report`. Now ALL outcomes (success/applied_count==0, success/applied_count>0, rollback) post to `/api/v1/audit`. Test `test_apply_and_report_empty_policy_does_not_post_audit` renamed to `test_apply_and_report_empty_policy_posts_noop_audit` and inverted to assert the no-op row IS persisted with `applied_count==0`.
> **RE-VERIFIED** (iteration 2, 2026-05-26): inverted test present in `tests/integration/test_sync_push_install.py`; 638/638 tests green.

**File:** `src/ccguard/agent/sync.py:279-281`

**Issue:** "Empty no-op apply (success with applied_count==0) is intentionally NOT posted." Operationally this means: on the very first sync after publishing mandatory sections, if the policy lands but the agent runs *before* the cache propagation (race), the agent applies nothing, reports nothing, and `/audit?event_source=policy_apply` shows zero events. Admin cannot distinguish "agent applied a no-op policy" from "agent never received the policy" from "agent crashed". For SecOps tooling this is a visibility regression.

**Fix:** Either (a) always POST and let the server collapse no-ops in the UI, or (b) post a once-per-revision heartbeat keyed by `policy_revision`. Add a counter in the `/audit?event_source=policy_apply` view ("no-ops suppressed: N").

---

### WR-07: CSV args parsing loses commas inside argument values

> **RESOLVED** (2026-05-26, commit 9ff0595) — Switched MCP `args` to one-per-line. `_parse_required_mcp_servers` now uses `_lines_to_list`. Row template uses `<textarea>` with label `args (по одному на строку)`. `_build_mandatory_sections_view` joins existing args with `\n` for re-render. Tests sending CSV form data updated to newline format.
> **RE-VERIFIED** (iteration 2, 2026-05-26): textarea template + `_lines_to_list` confirmed; 638/638 tests green.

**File:** `src/ccguard/server/web/policy_form.py:181`

**Issue:** `args = [s.strip() for s in args_raw.split(",") if s.strip()]`. There is no way to encode an arg containing a literal comma (e.g. `--filter=a,b`). The UI label says "args (через запятую)" with no escaping rule. Admin enters `--filter=a,b` → policy applies as `["--filter=a", "b"]` → MCP server starts with wrong args. No validation surfaces the breakage; it only fails at runtime on the developer endpoint.

**Fix:** Either switch to one-arg-per-line (already the pattern for `commands.denylist_patterns`), or JSON-encode the args field like `env`. If the textarea route is chosen, update the UI label and `04-UI-SPEC.md`.

---

### WR-08: `_finding_view_model` assigns a non-`__slots__` attribute

> **RESOLVED** (2026-05-26, commit 9b3fffc) — Dropped `__slots__` on `_FindingVM` (it is not a hot-path object). Stale comment block updated to point to the actual location of the `file_hash` URL-encoding defense (`_finding_row.html`) instead of vaguely citing "WR-06".
> **RE-VERIFIED** (iteration 2, 2026-05-26): `routes.py:200` plain class confirmed; 638/638 tests green.

**File:** `src/ccguard/server/web/routes.py:200-224`

**Issue:** `_FindingVM` declares `__slots__ = ("discovered_at", "machine_id", "rule_id", "severity", "details")` and assigns exactly those 5 attributes — this is fine today. But the inline comment at line 214-221 invites future maintainers to "add new keys" which would silently raise `AttributeError` because `__slots__` forbids it. The comment about URL-encoding `file_hash` references a defense that lives in a different template (`_finding_row.html`) and is unverified here.

**Fix:** Drop `__slots__` (this is not a hot-path object) or convert to a `@dataclass(slots=True)` — both signal intent more clearly. The comment block should reference WHERE the URL-encoding lives, not just claim it does.

---

### WR-09: `_post_policy_apply_event` writes `r.text[:200]` containing potentially sensitive paths to logs

> **RESOLVED** (2026-05-26, commit fbd060a) — `_post_policy_apply_event` no longer logs `r.text` on 4xx/5xx. WARNING log includes only `status_code` and a category (`client_error` / `server_error`). Eliminates the risk of a misconfigured reverse proxy leaking `X-CCGuard-Token` into agent logs.
> **RE-VERIFIED** (iteration 2, 2026-05-26): `sync.py:241-249` logs only status_code + category; 638/638 tests green.

**File:** `src/ccguard/agent/sync.py:240-246`

**Issue:** When the server returns 4xx/5xx with an HTML error page (e.g. a misconfigured reverse proxy), the first 200 chars of its body land in the agent's WARNING log. If the proxy echoes the original request URL or path, this is fine; if it echoes header values it could leak the `X-CCGuard-Token`. Per the project constraint "никаких plain-text токенов в БД" — the same hygiene should extend to logs.

**Fix:** Log only `r.status_code` and a fixed error category. If the body must be logged, strip headers/tokens first.

## Info

### IN-01: Misleading docstring — "umask-respecting 0o644"

**File:** `src/ccguard/agent/atomic_io.py:28-31, 49`

`os.chmod(tmp_path, 0o644)` is not umask-respecting; the comment contradicts the code. (See **CR-02** for the security implication; this is the doc-fix half.)

> **NOTE (iteration 2):** docstring re-inspected — claim now reads "Final file permissions are set EXACTLY to `mode` via `os.chmod`" (`atomic_io.py:28`). The original misleading wording is gone as a side-effect of the CR-02 commit, so IN-01 is effectively resolved despite being out of scope for `--fix critical_warning`. Left in the report for traceability.

---

### IN-02: Dead/unused query in `admin_scan_rescan`

**File:** `src/ccguard/server/web/routes.py:861-865`

`finding_row = session.exec(select(FindingRecord).where(...).order_by(...)).first()` is fetched but only used as the last-resort fallback path that "should not normally happen". The same query is then re-run via `cands` on the next lines. Either consume `finding_row` from the `cands` loop or drop the redundant `first()` query.

---

### IN-03: `_KEBAB_RE` duplicated in `policy.py` and `policy_form.py`

**Files:**
- `src/ccguard/schemas/policy.py:15`
- `src/ccguard/server/web/policy_form.py:46`

Identical regex defined twice. Both copies must stay in sync; today they happen to match. Move to a single constant in `policy.py` and import.

---

### IN-04: `policy_mandatory_row` returns 404 with `detail` but no admin-friendly message

**File:** `src/ccguard/server/web/routes.py:548-554`

`HTTPException(status_code=404, detail="unknown section")` returns JSON to a route that the HTMX UI expects to swap as HTML. A typo / version-skewed JS will paint raw JSON inside the form. Return an HTML 4xx fragment instead.

---

### IN-05: `_render_mandatory_page` recomputes diff_lines on every error re-render

**File:** `src/ccguard/server/web/routes.py:487-529`

Every form-validation re-render walks `diff_policies(current.yaml_text, draft.yaml_text)` again. Cosmetic — the diff has not changed since the form failed validation before any DB write. Cache the diff in the view context on first compute.

## Structural Findings (fallow)

No `<structural_findings>` block was supplied to this review. If a structural pre-pass exists, it should be merged in here verbatim; otherwise this section is intentionally empty.

---

_Reviewed: 2026-05-26T00:00:00Z (iteration 1)_
_Re-reviewed: 2026-05-26T00:00:00Z (iteration 2)_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_

---

## Fix Summary (2026-05-26, iteration 1)

**Scope:** Critical + Warning only (per `--fix critical_warning`). Info findings (IN-01..IN-05) intentionally out of scope and not modified.

**Fixed (11):**

| ID    | Commit  | One-line                                                                       |
|-------|---------|--------------------------------------------------------------------------------|
| CR-01 | 77b6b59 | Pydantic safe-name validator on RequiredSkill/RequiredAgent + apply-time guard |
| CR-02 | 2541643 | atomic_write_bytes mode param; ~/.claude.json now 0o600                        |
| WR-01 | e4fd435 | Marker merge skips fenced code blocks via _split_fenced                        |
| WR-02 | f159823 | Duplicate name/id rejected at policy_form parser                               |
| WR-03 | f69c765 | Agent re-validates cached policy through Policy.model_validate                 |
| WR-04 | 369c0f7 | _merge_mcp_servers coerces non-dict mcpServers gracefully                      |
| WR-05 | 8e9e8a0 | PolicyApplyEventPayload/BatchIn use extra=ignore                               |
| WR-06 | ca26a19 | No-op apply always posts audit event                                           |
| WR-07 | 9ff0595 | MCP args switched to one-per-line (commas survive)                             |
| WR-08 | 9b3fffc | Drop misleading __slots__ on _FindingVM                                        |
| WR-09 | fbd060a | Don't log response body in policy_apply audit POST failure                     |

**Skipped (5):** IN-01..IN-05 — Info-tier, out of scope for `--fix critical_warning`.

**Tests:** 638 baseline / 638 final (e2e suite excluded — requires network). Two existing tests updated in lockstep with semantic changes: `test_apply_and_report_empty_policy_does_not_post_audit` renamed to `*_posts_noop_audit` (WR-06 inverted behavior), and `_empty_policy`/`_policy_with_skill` fixtures now include `meta.updated_at` (WR-03 added a Policy re-validation gate that requires the full schema).

**Privacy / constraints check:**
- Token never logged (WR-09) — meets "никаких plain-text токенов в БД" extended to logs.
- ~/.claude.json now 0o600 (CR-02) — admin-supplied MCP env-secrets sealed from other local UIDs.
- No new external dependencies.
- No changes to PreToolUse hook hot path; perf budget preserved.
- Schema additivity preserved (Policy/audit schemas remain schema_version=1; WR-05 adds forward-compat ignore but does not bump the version).

_Fixed: 2026-05-26T00:00:00Z_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_

---

## Re-review Result (2026-05-26, iteration 2)

**Verdict:** `clean`. All 2 Critical and all 9 Warning resolutions verified by source inspection;
test suite at `638 passed` (matches iteration-1 baseline). Phase 1-3 untouched per
`git show --stat` review of every fix commit. No new BLOCKER or WARNING-tier defects surfaced.

**Outstanding:** 5 Info-tier findings (IN-01..IN-05) remain documented for future cleanup but
were out of scope for `--fix critical_warning`. IN-01 was effectively resolved as a side-effect
of CR-02 (docstring no longer claims umask respect).

_Re-reviewed: 2026-05-26T00:00:00Z_
_Re-reviewer: Claude (gsd-code-reviewer)_
_Iteration: 2_
