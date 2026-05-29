# Behavioral Detection v2 — Design Spec

**Date:** 2026-05-30
**Status:** Approved for planning
**Goal:** Turn ccguard's naive 3σ anomaly detection into a production-grade,
SOC-trustworthy behavioral detection feature for a real security-team pilot.

## 1. Why

Today's anomaly detection is a 3σ threshold on 4 volumetric metrics per machine
(`anomaly_service.py`). It "beeps" with no explainability, no tuning, no noise
suppression, and no triage workflow. For a security team running a real pilot,
**trust** in the detection (low false positives, explainability, tunability)
matters more than flashiness.

The target user is AppSec/SecOps. ccguard's moat is **action/tool-call-level**
behavioral detection of an AI coding agent on the endpoint — the blind spot
classic EDR (CrowdStrike, SentinelOne) and prompt-level AI guardrails (Lakera)
do not cover.

### Market basis (research synthesis)

- **UEBA/EDR (Exabeam, Splunk, CrowdStrike):** nobody alerts on one metric. The
  load-bearing pattern is a **cumulative weighted risk score per entity**; many
  weak signals aggregate into one prioritized alert at a threshold.
- **CrowdStrike IOAs:** behavioral *sequence* rules (exec → persistence → exfil)
  have lower false-positive rates than statistics or signatures.
- **Trust = explainability:** Smart Timeline / Storyline show the analyst *why*
  an alert fired — contributing signals with weights + the raw events.
- **MITRE ATLAS** has agent-specific techniques: `AI Agent Tool Invocation`
  (AML.T0053), `Modify AI Agent Configuration` (persistence via swapping
  MCP/skills/agents) — validates ccguard's inventory as a rug-pull detector.
- **Highest-signal / lowest-FP detections:** the sequence "sensitive-read →
  network egress", and config-drift on previously-approved tools.

## 2. Core constraint that shapes everything

`ToolUseEvent` stores only a **16-hex fingerprint of `tool_input`, never the raw
content** (privacy rule in CLAUDE.md: only hashes/encrypted). But the best IOA
signals need to know *what* the command/file was.

**Resolution — agent-side signal extraction.** The agent already sees the raw
`tool_input` on the endpoint. It classifies the input into a set of
privacy-preserving **tags** (e.g. `cred.read.aws`, `egress.curl_new_host`),
mapped to ATT&CK/ATLAS, and sends the **tags, not the content**. The server runs
the risk engine over tags. Privacy is preserved (raw data never leaves the
endpoint) — exactly how a real EDR sensor emits categorized telemetry, not dumps.

## 3. Architecture

```
PostToolUse (agent)
  → signal extractor (raw tool_input → list[signal_id])   [NEW, agent-side]
  → audit buffer → flusher                                 [existing]
  → server ingests ToolUseEvent.signals_json              [extended field]
  → risk_service.tick() under scheduler                    [NEW, server-side]
     → weighted cumulative score + peer normalization + decay
     → IOA rules + sequence detector
     → FindingRecord at threshold (severity per enforcement_mode)
  → triage UI (risk timeline + fleet overview)             [NEW]
```

Reuses the existing pipeline (buffer/flusher/`ToolUseEvent`, `FindingRecord`,
APScheduler single-writer `tick` idiom, `SettingsRecord` KV store,
`MachineBaseline.baseline_ready` warm-up). Old agents (v0.1) send empty signals
→ graceful degradation.

## 4. Components

### 4.1 Telemetry — agent-side signal extractor
- New package `ccguard/agent/signals/` with a declarative catalog
  `catalog.py`: `{id, attack_technique, default_weight, matcher}`.
- Extractor runs at PostToolUse, returns `list[signal_id]` for the event.
- **NO raw `tool_input` leaves the endpoint** — only signal IDs.
- Extend `ToolUseEvent` with `signals_json: str` (default `"[]"`).
- Starter catalog (~12 rules, ATT&CK/ATLAS-mapped):
  - `cred.read.aws|ssh|env|pem` (T1552) — sensitive-file access
  - `egress.curl_new_host` / `egress.pipe_network` (T1041/T1071)
  - `exec.pipe_to_shell` / `exec.obfuscated` (T1059)
  - `persist.shell_rc` / `persist.cron` (T1547)
  - `persist.agent_config` (ATLAS Modify AI Agent Config) — MCP/hooks/skills drift
  - `discovery.burst` (T1057) — whoami/env/aws sts spike
  - `collection.bulk_read` (T1119) — recursive secret grep / mass reads

### 4.2 Risk-scoring engine — `risk_service.py`
- `tick(session)` under APScheduler, mirroring `anomaly_service.tick` (single
  writer, coalesce, per-machine try/except).
- Cumulative weighted score per machine over a rolling window (default 24h):
  `score = Σ(signal_weight × novelty_factor × decay)`.
- **Novelty:** rare for this machine AND its peer group → higher; routine for
  the peer group → ~0 (noise suppression).
- **Peer grouping:** cluster machines by installed MCP/agent set from
  `InventorySnapshot` (lightweight, no ML).
- **Decay:** exponential — old signals fade so score doesn't accumulate forever.
- **Warm-up:** alert only when machine baseline is ready (reuse
  `MachineBaseline.baseline_ready`).
- Emit `FindingRecord` `rule_id="risk.elevated"` at threshold; payload carries
  the explainability breakdown (see 4.4).
- Weights + threshold + window live in `SettingsRecord` → tunable without redeploy.

### 4.3 IOA rules + sequence detector
- Declarative IOA rules over the signal stream.
- **Sequence detector (primary low-FP detection):** `cred.read.*` followed by
  `egress.*` from the same machine within T minutes → single `FindingRecord`
  `rule_id="ioa.exfil_sequence"`.
- **Config-drift / rug-pull:** previously-approved MCP/skill changes hash/args →
  `persist.agent_config`.

### 4.4 Explainability + triage UI
- **Machine risk timeline** on `machine_detail`: each alert expands into "why it
  fired" — contributing signals with weights + raw events (Exabeam Smart
  Timeline style).
- **Fleet risk overview:** machines sorted by current score with top contributors;
  replaces the current beep.
- Each signal links to its ATT&CK/ATLAS technique (trust + analyst training).

### 4.5 Tuning, allowlist, non-blocking
- **One-click suppression** on an alert ("expected for this machine/group") →
  writes a tuning rule to `SettingsRecord`, decays that signal's weight. Primary
  alert-fatigue defense.
- **Non-blocking by default (closes "remove all blocking" ask):** global
  `enforcement_mode = observe | enforce` in `SettingsRecord`, default `observe`.
  In `observe` the engine only emits findings, never returns deny — removes all
  blocking via one switch without deleting logic.

## 5. Testing

- **Unit (signal matchers):** table-driven "input → expected tags", including
  evasions (whitespace, quoting, base64, unicode homoglyphs — precedent in the
  PI engine).
- **Risk engine:** deterministic scenarios for score / decay / peer-normalization
  / warm-up.
- **Sequence:** positive (cred→egress in window) + negatives (reverse order,
  window expired, different machines).
- **Integration:** synthetic `ToolUseEvent` firehose → tick → expected
  `FindingRecord` + explainability payload.
- **Attack simulator:** small script replaying an AIShellJack-style profile
  (cred-access → collection → exfil) as an E2E pilot demo.

## 6. Staging (incremental, each shippable)

1. **Telemetry foundation** — signal catalog + extractor + `signals_json` field
   + agent emits tags. (No scoring yet; just data flowing.)
2. **Risk engine** — `risk_service.tick`, scoring + decay + warm-up + threshold +
   `risk.elevated` finding.
3. **IOA + sequence** — exfil-sequence detector + config-drift.
4. **Explainability UI** — machine risk timeline + fleet overview.
5. **Tuning + modes** — one-click suppression + `enforcement_mode=observe` default.

Peer-group normalization can land with stage 2 (basic) and refine later.

## 7. Out of scope (YAGNI)

- Heavy ML baselining (clustering/VAE) — rules + light stats only.
- Multi-tenant, Postgres — deferred to v0.3 per project constraints.
- Reworking the LLM content scanner or prompt-injection engine.

## 8. Backward compatibility

- v0.1 agents send no signals → empty `signals_json` → engine treats as no-signal
  events; no errors. `enforcement_mode=observe` default means nothing new blocks.
