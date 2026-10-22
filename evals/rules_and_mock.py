"""Input and action evaluation of (a) the rules backend and (b) the MockBackend stub, each on its own.

Rules numbers are real (deterministic baseline, author-written). Mock numbers are PLUMBING CHECKS only.
Output: results/offline/input.json and results/offline/action.json.
"""
from __future__ import annotations

from peephole.backends import MockBackend, RulesBackend
from peephole.cascade import Cascade
from peephole.evaluation import run_action, run_input, summarise_action, summarise_input

from .common import (RULES_LABEL, STUB_LABEL, action_checks, backend_action, backend_input, datasets,
                     input_checks, write_json)


def run() -> dict:
    d = datasets()
    rules_in = run_input(input_checks(lambda: Cascade()), d["input"])
    mock_in = run_input(backend_input(MockBackend()), d["input"])
    rules_act = run_action(action_checks(lambda: Cascade()), d["action"])
    mock_act = run_action(backend_action(MockBackend()), d["action"])
    out_in = {"label": {"rules": RULES_LABEL, "mock": STUB_LABEL},
              "n_examples": len(d["input"]),
              "rules": summarise_input(rules_in), "mock": {"backend_is_stub": True, **summarise_input(mock_in)}}
    out_act = {"label": {"rules": RULES_LABEL, "mock": STUB_LABEL},
               "n_examples": len(d["action"]),
               "rules": summarise_action(rules_act), "mock": {"backend_is_stub": True, **summarise_action(mock_act)}}
    write_json("input.json", out_in)
    write_json("action.json", out_act)
    return {"input": out_in, "action": out_act, "records": {"rules_in": rules_in, "rules_act": rules_act}}
