"""Shared helpers for the offline evals: metadata, JSON output, labels, the gates under test."""
from __future__ import annotations

import json
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List

from peephole.backends import MockBackend, RulesBackend
from peephole.cascade import Cascade
from peephole.datasets import (ActionExample, InputExample, load_action_examples, load_input_examples)
from peephole.evaluation import backend_verdict_action, backend_verdict_input
from peephole.gates import ActionGate, InputGate

ROOT = Path(__file__).resolve().parents[1]
RESULTS = Path(__file__).resolve().parent / "results" / "offline"
SEED = 0

STUB_LABEL = ("PLUMBING CHECK ONLY. The MockBackend is a deterministic keyword stub, not Jev and not an LLM; its "
              "'confidence' is a function of keyword counts, not a probability. These numbers verify that the "
              "harness, cascade, metrics and audit trail work. They say nothing about how Jev or any model performs.")
RULES_LABEL = ("The rules backend is a real deterministic baseline, but its rules (copied from agent-whetstone) and "
               "all labelled data were written by one author; 'heldout' = families the rules were not written for. "
               "Not real traffic.")


def meta() -> Dict[str, Any]:
    try:
        commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=ROOT, capture_output=True,
                                text=True, timeout=10).stdout.strip()
    except Exception:
        commit = ""
    return {"environment": "OFFLINE: no model, no network, no API key; synthetic data only",
            "python": sys.version.split()[0], "platform": platform.platform(terse=True), "git_commit": commit,
            "seed": SEED}


def write_json(name: str, payload: Dict[str, Any]) -> Path:
    RESULTS.mkdir(parents=True, exist_ok=True)
    path = RESULTS / name
    path.write_text(json.dumps({"meta": meta(), **payload}, indent=2, sort_keys=True) + "\n")
    return path


# ---- the gates under test ------------------------------------------------------------------------------------------
def input_checks(cascade_factory: Callable[[], Cascade]) -> Callable[[InputExample], Any]:
    g = InputGate(cascade_factory())
    return lambda ex: g.check(ex.text, ex.context)


def action_checks(cascade_factory: Callable[[], Cascade]) -> Callable[[ActionExample], Any]:
    g = ActionGate(cascade_factory())
    return lambda ex: g.check(ex.task, ex.tool_name, ex.tool_args, ex.context)


def datasets() -> Dict[str, List[Any]]:
    return {"input": load_input_examples(), "action": load_action_examples()}


def backend_input(backend) -> Callable[[InputExample], Any]:
    return lambda ex: backend_verdict_input(backend, ex)


def backend_action(backend) -> Callable[[ActionExample], Any]:
    return lambda ex: backend_verdict_action(backend, ex)
