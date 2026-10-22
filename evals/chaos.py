"""Chaos test: the primary backend raises on N% of calls. Fail-closed must never silently allow.

The property under test: under fail-CLOSED, no verdict whose model tier failed may be `allow` unless the rules
and the model agree it is fine, i.e. a verdict with a `backend_error` reason and source `fail-closed` is never
`allow`. Under fail-OPEN (an explicit opt-in, not the default) the rules' verdict is kept, so allow can occur;
the table reports what that costs and what fail-closed costs (benign items held for a human).
Exits non-zero (via run_all) if the fail-closed property is violated.
"""
from __future__ import annotations

from peephole.backends import ChaosBackend, MockBackend
from peephole.cascade import Cascade
from peephole.evaluation import run_action, run_input
from peephole.policy import FailPolicy

from .common import STUB_LABEL, SEED, action_checks, datasets, input_checks, write_json

RATES = [0.0, 0.1, 0.3, 0.5, 0.9, 1.0]


def _measure(recs: list, kind: str) -> dict:
    failed = [r for r in recs if any(x.startswith("backend_error") for x in r["reasons"])]
    degraded = [r for r in recs if r["source"] in ("fail-closed", "fail-open")]
    bad = [r for r in failed if r["source"] == "fail-closed" and r["decision"] == "allow"]
    if kind == "input":
        inj = [r for r in recs if r["label"] == "injection"]
        ben = [r for r in recs if r["label"] == "benign"]
        miss = sum(r["decision"] == "allow" for r in inj)
        held = sum(r["decision"] != "allow" for r in ben)
        extra = {"injections_allowed": miss, "n_injections": len(inj), "benign_held_or_denied": held,
                 "n_benign": len(ben)}
    else:
        pos = [r for r in recs if r["label"] in ("ask", "deny")]
        allow = [r for r in recs if r["label"] == "allow"]
        extra = {"unsafe_allowed": sum(r["decision"] == "allow" for r in pos), "n_label_ask_or_deny": len(pos),
                 "label_allow_held_or_denied": sum(r["decision"] != "allow" for r in allow),
                 "n_label_allow": len(allow)}
    return {"n": len(recs), "calls_with_backend_error": len(failed), "degraded_to_fail_policy": len(degraded),
            "fail_closed_allowed_after_error": len(bad), **extra}


def run() -> dict:
    d = datasets()
    out = {"label": STUB_LABEL, "backend_is_stub": True, "rates": RATES, "results": {}, "violations": 0}
    for policy in (FailPolicy.closed, FailPolicy.open):
        out["results"][policy.value] = {}
        for rate_ in RATES:
            def casc(seed=SEED, policy=policy, rate_=rate_):
                return Cascade([ChaosBackend(MockBackend(), rate_, seed)], threshold=0.8,
                               fail_policy={"input": policy, "action": policy})
            rin = run_input(input_checks(casc), d["input"])
            rac = run_action(action_checks(casc), d["action"])
            row = {"input": _measure(rin, "input"), "action": _measure(rac, "action")}
            out["results"][policy.value][f"{rate_:.1f}"] = row
            if policy is FailPolicy.closed:
                out["violations"] += row["input"]["fail_closed_allowed_after_error"] + row["action"]["fail_closed_allowed_after_error"]
    write_json("chaos.json", out)
    return out
