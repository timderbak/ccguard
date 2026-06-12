"""P5 suspicion-gate red-team evaluation harness (dev-only, not shipped).

Reads a corpus JSON ({attacks:[{text,technique,lens}], benign:[{text,kind,lens}]})
and runs each example through BOTH tiers:

  * tier 1 — strict PI catalog (prompt_injection_engine.scan, default cfg)
  * tier 2 — the read-content suspicion gate (read_pi_escalation.should_escalate)

Reports:
  * recall (any tier catches an attack) and gate-incremental recall
    (gate catches attacks the strict catalog missed — the whole point of P5)
  * gate false-positive rate on benign content (cost = shipping benign to Anthropic)
  * the exact FN list (both tiers missed) and gate-FP list, with fired categories

Usage: .venv/bin/python scripts/p5_gate_eval.py <corpus.json>
"""
from __future__ import annotations

import json
import sys

from ccguard.agent.prompt_injection_engine import scan as strict_scan
from ccguard.agent.read_pi_escalation import matched_categories, should_escalate
from ccguard.schemas.policy import PromptInjectionConfig

CFG = PromptInjectionConfig()  # enabled, llama_guard off by default


def _strict_hit(text: str) -> bool:
    r = strict_scan(text, CFG)
    return r is not None and r.rule_id != "prompt_injection.llama_guard.model_missing"


def main(path: str) -> int:
    corpus = json.loads(open(path, encoding="utf-8").read())
    attacks = corpus.get("attacks", [])
    benign = corpus.get("benign", [])

    fn = []          # attacks both tiers missed
    gate_only = 0    # attacks the gate caught that strict missed (P5 value)
    strict_caught = 0
    for a in attacks:
        t = a["text"]
        s = _strict_hit(t)
        g = should_escalate(t)
        if s:
            strict_caught += 1
        elif g:
            gate_only += 1
        else:
            fn.append({**a, "cats": sorted(matched_categories(t))})

    gate_fp = []     # benign the gate escalated
    strict_fp = []   # benign the strict catalog flagged (tier-1 FP, noted)
    for b in benign:
        t = b["text"]
        s = _strict_hit(t)
        g = should_escalate(t)
        if g:
            gate_fp.append({**b, "cats": sorted(matched_categories(t))})
        if s:
            strict_fp.append(b)

    na, nb = len(attacks), len(benign)
    strict_missed = na - strict_caught
    print("=" * 70)
    print(f"ATTACKS: {na}   BENIGN: {nb}")
    print(f"  strict caught:        {strict_caught}")
    print(f"  gate caught (strict missed): {gate_only}")
    print(f"  MISSED by both (FN):  {len(fn)}")
    if na:
        print(f"  total recall:         {(strict_caught + gate_only)/na:.1%}")
    if strict_missed:
        print(f"  gate incremental recall (of strict-missed): {gate_only/strict_missed:.1%}")
    print(f"  gate FALSE POSITIVES on benign: {len(gate_fp)}  ({len(gate_fp)/nb:.1%})" if nb else "")
    print(f"  (strict-catalog FPs on benign, FYI: {len(strict_fp)})")

    print("\n--- FALSE NEGATIVES (both tiers missed) ---")
    for x in fn:
        print(f"[{x.get('lens')}/{x.get('technique')}] cats={x['cats']}")
        print(f"   {x['text']!r}")

    print("\n--- GATE FALSE POSITIVES (benign escalated) ---")
    for x in gate_fp:
        print(f"[{x.get('lens')}/{x.get('kind')}] cats={x['cats']}")
        print(f"   {x['text']!r}")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "/tmp/p5_corpus.json"))
