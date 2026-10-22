"""In-process latency of the deterministic layers and the gate plumbing (p50/p95). NO model call is included.

One machine, one thread, after warm-up; treat as an order of magnitude. A live Jev or LLM call would dominate by
orders of magnitude and is NOT measured here (not run live).
"""
from __future__ import annotations

import time

from peephole.audit import AuditLog
from peephole.backends import MockBackend
from peephole.cascade import Cascade
from peephole.gates import ActionGate, InputGate
from peephole.stats import latency_summary

from .common import datasets, write_json

REPEATS = 5


def _time(fn, items) -> dict:
    for it in items[:20]:
        fn(it)
    ms = []
    for _ in range(REPEATS):
        for it in items:
            t0 = time.perf_counter()
            fn(it)
            ms.append((time.perf_counter() - t0) * 1000.0)
    return latency_summary(ms)


def run() -> dict:
    d = datasets()
    ins, acts = d["input"], d["action"]
    rules_in, rules_act = InputGate(Cascade()), ActionGate(Cascade())
    mock_in = InputGate(Cascade([MockBackend()]))
    audited = InputGate(Cascade(), audit=AuditLog())
    out = {"caveat": "in-process, one machine, no model call; order of magnitude only",
           "rules_input_gate": _time(lambda e: rules_in.check(e.text, e.context), ins),
           "rules_action_gate": _time(lambda e: rules_act.check(e.task, e.tool_name, e.tool_args, e.context), acts),
           "mock_cascade_input_gate": _time(lambda e: mock_in.check(e.text, e.context), ins),
           "rules_input_gate_with_audit_chain": _time(lambda e: audited.check(e.text, e.context), ins)}
    write_json("latency.json", out)
    return out
