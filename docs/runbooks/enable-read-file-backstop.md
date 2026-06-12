# Runbook — activate the read_file semantic PI backstop (P5) on prod

The read_file backstop is the **server-side LLM scan of untrusted read content**.
The agent's cheap regex catalog catches *templated* prompt injection; the backstop
catches *natural-language* injection the regex misses. It is fully implemented but
ships **dormant** (off by default, no API key), so turning it on is a deploy step,
not a code change.

## How the pipeline works (so you know what to watch)

1. **Agent** — on a `Read` of untrusted content, `read_pi_escalation.should_escalate`
   applies cheap heuristics (STRONG signals + WEAK-signal pairing). On a hit, the
   content is spooled to `~/.ccguard/read-scan-spool/` (masked, capped at 64 files,
   username-scrubbed).
2. **Sync** — `inventory_scan.collect_read_scan_items` drains the spool and POSTs it
   to `/api/v1/scan-content` with `scope=read_file`, batched with config artifacts.
3. **Server** — `ScanService.scan_file` gates on `llm_scanner_enabled` + the daily
   budget, then calls `LLMClient.scan_content` (which prepends an *untrusted-input*
   framing so the model judges injection-vs-data). `risk_score >= 30` →
   `FindingRecord(rule_id="llm.scan.<category>")` at info/warn/critical by score.
   Repeat content short-circuits via the `ScanResult` cache (30-day TTL).

## Prerequisites

- An **Anthropic API key** for the server (the only external dependency; the LLM
  scanner is the one optional cloud call in an otherwise on-prem product).
- Admin access to the server host (env) **or** the `/settings` web UI.

## Activation

1. **Set the API key** in the server environment — this is what builds the
   `ScanService` at startup; without it `/api/v1/scanner-config` returns
   `enabled=false` and `/scan-content` returns `503`:

   ```sh
   export ANTHROPIC_API_KEY=sk-ant-...
   ```

2. **Enable the scanner.** Two equivalent ways:

   - **Deploy-time (recommended, no UI step):** set the env var. When set, it is
     **authoritative at every boot** — it flips the `llm_scanner_enabled` setting on
     (or off) each startup, so a restart can't silently leave it off:

     ```sh
     export CCGUARD_LLM_SCANNER_ENABLED=true
     ```

   - **UI-managed:** leave `CCGUARD_LLM_SCANNER_ENABLED` unset and flip the toggle in
     **/settings** (the seeded default is off). Admin edits persist across restarts.

   > Pick one. If the env var is set it wins each boot; unset it to manage via the UI.

3. **Restart the server** so the lifespan rebuilds `ScanService` and applies the flag.

4. **Verify**:
   ```sh
   curl -s http://<server>/api/v1/scanner-config        # → {"enabled": true, ...}
   ```
   and open **/settings** — the scanner shows enabled, with the daily-budget usage
   counter.

## Tuning & monitoring

- **Daily budget** — `daily_call_budget` (default `100`) caps LLM calls/day; tune in
  `/settings`. Exhaustion → `429` (`budget_exhausted`) on `/scan-content`; spooled
  items retry after the daily reset.
- **Findings** — watch `llm.scan.<category>` findings in the Findings feed; these are
  the natural-language injections the regex catalog missed.
- **Cost** — each scanned read is one cheap classifier call; the cache means repeat
  content is free. Size caps: 100 KiB soft (truncated), 1 MiB hard (rejected).
- **Privacy** — content is masked, capped, and username-scrubbed agent-side before it
  ever leaves the endpoint.

## Disable / roll back

Unset `CCGUARD_LLM_SCANNER_ENABLED` (or set it `false`) and restart, **or** flip the
`/settings` toggle off. Disabled → `/scan-content` returns `503`; the agent stops
spooling on the next `scanner-config` poll. Removing `ANTHROPIC_API_KEY` also disables
it (the `ScanService` is never built).

## Distinguishing "offline" vs "disabled"

Both currently surface as `503` / `enabled=false`:

- **No `ANTHROPIC_API_KEY`** → the `ScanService` was never constructed (scanner
  *offline*). Fix: set the key + restart.
- **Key present but `llm_scanner_enabled=false`** → scanner built but gated off
  (*disabled*). Fix: flip the flag (env or UI).

If `/api/v1/scanner-config` says `enabled=false` with a key set, the flag is off.
