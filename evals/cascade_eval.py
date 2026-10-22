"""Cascade results at several thresholds, and rules versus cascade. PLUMBING CHECK: the tiers are mock stubs.

chain A = [mock (Jev-like: reports confidence)]; chain B = [mock, mock-llm (LLM-like: no confidence)].
Both fall back to the rules under the default fail-closed policy. Compared with the rules alone.
"""
from __future__ import annotations

from peephole.backends import MockBackend
from peephole.cascade import Cascade
from peephole.evaluation import run_action, run_input, summarise_action, summarise_input

from .common import STUB_LABEL, action_checks, datasets, input_checks, write_json

THRESHOLDS = [0.5, 0.6, 0.7, 0.8, 0.9, 0.95]


def _chain(kind: str, thr: float) -> Cascade:
    if kind == "rules_only":
        return Cascade()
    tiers = [MockBackend("mock-jev-like", True)]
    if kind == "mock_then_mock_llm":
        tiers.append(MockBackend("mock-llm-like", False, thorough=True))
    return Cascade(tiers, threshold=thr)


def _row(si: dict, sa: dict, rin: list, rac: list) -> dict:
    ov, ab = si["overall"], sa["headline_firm_labels_only"]
    return {"input_detection": ov["injections"], "input_false_block": ov["benign_false_block"],
            "input_heldout_detection": si["by_split"]["heldout"]["injections"],
            "action_exact_match": ab["exact_match"], "action_deny_to_allow": ab["deny_to_allow"],
            "action_over_block": ab["over_block"],
            "escalation_rate_input": round(sum(r["escalated"] for r in rin) / len(rin), 4),
            "escalation_rate_action": round(sum(r["escalated"] for r in rac) / len(rac), 4),
            "sources_input": si["sources"], "sources_action": sa["sources"]}


def run() -> dict:
    d = datasets()
    out = {"label": STUB_LABEL, "backend_is_stub": True, "thresholds": THRESHOLDS, "results": {}}
    for kind in ("rules_only", "mock_only_fallback_rules", "mock_then_mock_llm"):
        ths = [None] if kind == "rules_only" else THRESHOLDS
        out["results"][kind] = {}
        for thr in ths:
            rin = run_input(input_checks(lambda: _chain(kind, thr or 0.8)), d["input"])
            rac = run_action(action_checks(lambda: _chain(kind, thr or 0.8)), d["action"])
            key = "n/a" if thr is None else f"{thr:.2f}"
            out["results"][kind][key] = _row(summarise_input(rin), summarise_action(rac), rin, rac)
    write_json("cascade.json", out)
    return out
