"""Calibration of a confidence-reporting backend: reliability table, ECE, risk-coverage curve.

Run here ONLY on the MockBackend stub, to prove the metric code end to end. The mock's confidence is a function
of keyword counts, so its ECE and risk-coverage say nothing about Jev. The same functions run on a real Jev run in
`scripts/run_live_eval.py` (not run yet).
"""
from __future__ import annotations

from peephole.backends import MockBackend
from peephole.evaluation import calibration, run_action, run_input

from .common import STUB_LABEL, backend_action, backend_input, datasets, write_json

THRESHOLDS = [0.0, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95]


def run() -> dict:
    d = datasets()
    mock = MockBackend()
    rin = run_input(backend_input(mock), d["input"])
    rac = run_action(backend_action(mock), d["action"])
    out = {"label": STUB_LABEL, "backend_is_stub": True, "backend": "mock",
           "input": calibration(rin, thresholds=THRESHOLDS), "action": calibration(rac, thresholds=THRESHOLDS),
           "note": "risk_coverage: coverage = share of ALL items decided automatically at confidence >= threshold; "
                   "error_rate = share wrong among those"}
    write_json("calibration.json", out)
    return out
