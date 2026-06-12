#!/usr/bin/env python3
"""Deterministic precision eval for the P2-width-3 collection.* signals.

Reads an adversarial corpus (list of {command, target_signal, should_fire})
and runs each command through the REAL agent signal extractor, so false
positives / false negatives are a fact of the code, not a model judgement.

Usage:
    python scripts/collection_precision_eval.py corpus.json

Corpus item shape:
    {"command": "...", "target_signal": "collection.archive_staging",
     "should_fire": true, "rationale": "..."}

Exit code is non-zero if any FP/FN remain, so it doubles as a gate.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from ccguard.agent.signals.extractor import extract_signals


def _fired(cmd: str) -> set[str]:
    return set(extract_signals("Bash", {"command": cmd}))


def main(path: str) -> int:
    corpus = json.loads(Path(path).read_text())
    fp: list[dict] = []  # benign that wrongly fired
    fn: list[dict] = []  # attack that was missed
    for item in corpus:
        cmd = item["command"]
        sig = item["target_signal"]
        should = bool(item["should_fire"])
        fired = sig in _fired(cmd)
        if should and not fired:
            fn.append(item)
        elif not should and fired:
            fp.append(item)

    total = len(corpus)
    print(f"corpus={total}  FP={len(fp)}  FN={len(fn)}  clean={total - len(fp) - len(fn)}")
    if fp:
        print("\n--- FALSE POSITIVES (benign wrongly fired) ---")
        for i in fp:
            print(f"  [{i['target_signal']}] {i['command']!r}\n      ↳ {i['rationale']}")
    if fn:
        print("\n--- FALSE NEGATIVES (attack missed) ---")
        for i in fn:
            print(f"  [{i['target_signal']}] {i['command']!r}\n      ↳ {i['rationale']}")
    return 1 if (fp or fn) else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
