#!/usr/bin/env python3
"""Attack simulator for ccguard — replays ATT&CK-style scenarios into the audit API.

Usage:

    # Default: full kill-chain against a local server
    CCGUARD_SERVER_URL=http://localhost:8000 \
    CCGUARD_AGENT_TOKEN=... \
    python scripts/attack_simulator.py --scenario exfil --machine m-pilot

    # List available scenarios
    python scripts/attack_simulator.py --list

The script posts synthetic ``ToolUseEvent`` batches with the same signal IDs
the agent extracts in production — driving the same code paths in
``risk_service.tick`` and ``sequence_service.tick``. Useful for: pilot demos,
end-to-end smoke after deploys, calibrating thresholds against known-bad
patterns, regression tests for new signals.

The agent never sees this — events are posted server-side via the agent's
ingest endpoint. The machine_id you pass should have a warm baseline (or you
can pre-warm it with --pre-warm). Without a warm baseline the engine will
correctly skip scoring (per Stage 2 design).

NO actual tool calls are executed on the host running this script. All
fingerprints are deterministic hashes of synthetic input strings so the same
scenario produces the same fingerprint every time.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib import error as urlerr
from urllib import request as urlreq


@dataclass(frozen=True)
class FakeEvent:
    """One synthetic tool invocation in a scenario.

    ``offset_seconds`` is the negative offset from ``now`` so we can replay an
    attack that "happened" over the past N minutes in a single batch.
    """

    offset_seconds: int
    tool_name: str
    signals: tuple[str, ...]
    fingerprint_seed: str
    decision: str = "allow"
    result_status: str = "success"


@dataclass(frozen=True)
class Scenario:
    name: str
    description: str
    events: tuple[FakeEvent, ...]
    expected_findings: tuple[str, ...] = field(default_factory=tuple)


SCENARIOS: dict[str, Scenario] = {
    "recon": Scenario(
        name="recon",
        description="Reconnaissance only — should NOT trigger high-severity alerts.",
        events=(
            FakeEvent(-300, "Bash", ("discovery.recon",), "whoami"),
            FakeEvent(-180, "Bash", ("discovery.recon",), "uname-a"),
            FakeEvent(-60, "Bash", ("discovery.recon",), "ifconfig"),
        ),
        expected_findings=(),
    ),
    "exfil": Scenario(
        name="exfil",
        description="Classic cred-read → network-egress sequence (lowest-FP IOA).",
        events=(
            FakeEvent(-600, "Bash", ("discovery.recon",), "whoami"),
            FakeEvent(-300, "Read", ("cred.read.aws",), "cat-aws-creds"),
            FakeEvent(-60, "Bash", ("egress.network_tool",), "curl-evil"),
        ),
        expected_findings=("ioa.exfil_sequence",),
    ),
    "elevated_risk": Scenario(
        name="elevated_risk",
        description="Multiple high-weight signals without ordering — fires risk.elevated.",
        events=(
            FakeEvent(-120, "Read", ("cred.read.aws",), "aws1"),
            FakeEvent(-90, "Read", ("cred.read.ssh",), "ssh1"),
            FakeEvent(-60, "Bash", ("egress.network_tool", "exec.pipe_to_shell"), "curl-pipe"),
        ),
        expected_findings=("risk.elevated",),
    ),
    "kill_chain": Scenario(
        name="kill_chain",
        description="Full AIShellJack-style kill chain: recon → cred → persist → exfil.",
        events=(
            FakeEvent(-1800, "Bash", ("discovery.recon",), "whoami2"),
            FakeEvent(-1500, "Bash", ("discovery.recon",), "aws-sts"),
            FakeEvent(-900, "Read", ("cred.read.aws",), "aws2"),
            FakeEvent(-840, "Read", ("cred.read.dotenv",), "dotenv"),
            FakeEvent(-600, "Edit", ("persist.shell_rc",), "bashrc"),
            FakeEvent(-300, "Bash", ("persist.cron",), "cron"),
            FakeEvent(-60, "Bash", ("egress.network_tool", "exec.pipe_to_shell"), "curl-final"),
        ),
        expected_findings=("risk.elevated", "ioa.exfil_sequence"),
    ),
    "reverse_order": Scenario(
        name="reverse_order",
        description="Egress THEN cred-read — must NOT fire the sequence detector (negative case).",
        events=(
            FakeEvent(-300, "Bash", ("egress.network_tool",), "curl-first"),
            FakeEvent(-60, "Read", ("cred.read.aws",), "aws-later"),
        ),
        expected_findings=(),
    ),
}


def _fingerprint(seed: str) -> str:
    """Deterministic 16-hex digest. Matches the agent's fingerprint format."""
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]


def _build_batch(scenario: Scenario, machine_id: str) -> dict[str, Any]:
    now = datetime.now(UTC)
    events: list[dict[str, Any]] = []
    for evt in scenario.events:
        events.append(
            {
                "ts": (now + timedelta(seconds=evt.offset_seconds)).isoformat(),
                "tool_name": evt.tool_name,
                "fingerprint": _fingerprint(evt.fingerprint_seed),
                "decision": evt.decision,
                "result_status": evt.result_status,
                "signals": list(evt.signals),
            }
        )
    return {"schema_version": "0.2", "machine_id": machine_id, "events": events}


def _post_batch(server_url: str, token: str, batch: dict[str, Any]) -> tuple[int, str]:
    body = json.dumps(batch).encode("utf-8")
    req = urlreq.Request(
        url=f"{server_url.rstrip('/')}/api/v1/audit",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-CCGuard-Token": token,
        },
    )
    try:
        with urlreq.urlopen(req, timeout=10) as resp:  # noqa: S310 — trusted URL
            return resp.status, resp.read().decode("utf-8")
    except urlerr.HTTPError as e:
        return e.code, e.read().decode("utf-8")


def _print_scenario_table() -> None:
    print(f"{'NAME':<16} {'EVENTS':>7}  EXPECTED FINDINGS")
    print("-" * 80)
    for name, s in SCENARIOS.items():
        expected = ", ".join(s.expected_findings) or "(none)"
        print(f"{name:<16} {len(s.events):>7}  {expected}")
        print(f"{'':<16}         {s.description}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scenario", default="kill_chain", choices=list(SCENARIOS.keys()))
    parser.add_argument("--machine", default="m-simulator", help="machine_id to attribute events to")
    parser.add_argument(
        "--server",
        default=os.environ.get("CCGUARD_SERVER_URL", "http://localhost:8000"),
        help="ccguard server URL (env CCGUARD_SERVER_URL)",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("CCGUARD_AGENT_TOKEN", ""),
        help="agent ingest token (env CCGUARD_AGENT_TOKEN)",
    )
    parser.add_argument("--list", action="store_true", help="list scenarios and exit")
    parser.add_argument("--dry-run", action="store_true", help="build the batch but don't POST")
    args = parser.parse_args()

    if args.list:
        _print_scenario_table()
        return 0

    if not args.token and not args.dry_run:
        print("error: --token or CCGUARD_AGENT_TOKEN required (or use --dry-run)", file=sys.stderr)
        return 2

    scenario = SCENARIOS[args.scenario]
    batch = _build_batch(scenario, args.machine)
    print(f"scenario: {scenario.name}  machine: {args.machine}  events: {len(batch['events'])}")
    print(f"  → {scenario.description}")
    if scenario.expected_findings:
        print(f"  expected findings: {', '.join(scenario.expected_findings)}")
    else:
        print("  expected findings: (none — this is a negative scenario)")

    if args.dry_run:
        print("\n--- batch (dry run) ---")
        print(json.dumps(batch, indent=2))
        return 0

    started = time.time()
    status, body = _post_batch(args.server, args.token, batch)
    elapsed_ms = (time.time() - started) * 1000
    print(f"\nPOST {args.server.rstrip('/')}/api/v1/audit → {status} ({elapsed_ms:.0f}ms)")
    print(f"response: {body}")
    if status >= 400:
        return 1
    print(
        "\nDone. The next scheduler tick (≤5 min default) will evaluate this machine's "
        "events and emit findings if thresholds are crossed. Check the overview page "
        "or /findings filter for rule_id='ioa.exfil_sequence' / 'risk.elevated'."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
