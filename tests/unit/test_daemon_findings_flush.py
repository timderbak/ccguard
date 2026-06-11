"""P6: the daemon ships locally-buffered findings every cycle (transport fix).

Before this, findings_hook.flush() had no production caller — PI/Read findings
sat in findings_buffer.db forever. The daemon now drains the buffer best-effort
on each sync cycle, and a console-script exists for manual/cron use.
"""
from __future__ import annotations

import ccguard.agent.daemon as daemon
import ccguard.agent.findings_hook.flusher as flusher
import ccguard.agent.findings_hook.flusher_main as flusher_main


def test_flush_findings_best_effort_calls_flush(monkeypatch):
    called = {"n": 0}

    def fake_flush():
        called["n"] += 1

    monkeypatch.setattr(flusher, "flush", fake_flush)
    daemon._flush_findings_best_effort()
    assert called["n"] == 1


def test_flush_findings_best_effort_swallows_errors(monkeypatch):
    def boom():
        raise RuntimeError("network down")

    monkeypatch.setattr(flusher, "flush", boom)
    # Must not raise — a flush failure can never break the daemon sync cycle.
    daemon._flush_findings_best_effort()


def test_flusher_main_entrypoint_calls_flush_and_returns_zero(monkeypatch):
    called = {"n": 0}

    def fake_flush():
        called["n"] += 1

    monkeypatch.setattr(flusher, "flush", fake_flush)
    assert flusher_main.main() == 0
    assert called["n"] == 1
