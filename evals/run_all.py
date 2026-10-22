"""One command: `python -m evals.run_all`. Fully offline. Rules backend and MockBackend stub ONLY.

Writes JSON under evals/results/offline/. Exits non-zero if the fail-closed chaos property is violated or a metric
self-check fails. Mock-backend numbers verify PLUMBING, not Jev.
"""
from __future__ import annotations

import logging
import sys
import time

from . import calibration, cascade_eval, chaos, latency, rules_and_mock
from .common import STUB_LABEL, write_json


def main() -> int:
    logging.getLogger("peephole.cascade").setLevel(logging.ERROR)   # the chaos run fails on purpose
    t0 = time.time()
    rm = rules_and_mock.run()
    cal = calibration.run()
    cas = cascade_eval.run()
    ch = chaos.run()
    lat = latency.run()

    ri, ra = rm["input"]["rules"], rm["action"]["rules"]
    summary = {
        "label": "RULES rows are real numbers for a deterministic, author-written baseline. MOCK/cascade/chaos rows "
                 "come from a keyword stub and verify plumbing only. NO live Jev or LLM result exists.",
        "rules_input": {"overall": ri["overall"], "dev": ri["by_split"]["dev"], "heldout": ri["by_split"]["heldout"]},
        "rules_action": {"headline": ra["headline_firm_labels_only"], "by_split": ra["by_split_firm"],
                         "ambiguous": ra["ambiguous_labels_reported_separately"]},
        "mock_plumbing_only": {"input_ece": cal["input"].get("ece"), "action_ece": cal["action"].get("ece"),
                               "chaos_fail_closed_violations": ch["violations"]},
        "seconds": round(time.time() - t0, 1),
    }
    write_json("summary.json", summary)
    ok = ch["violations"] == 0
    print(f"rules  input : detection {ri['overall']['injections']['k']}/{ri['overall']['injections']['n']}, "
          f"false-block {ri['overall']['benign_false_block']['k']}/{ri['overall']['benign_false_block']['n']}")
    hb = ra["headline_firm_labels_only"]
    print(f"rules  action: exact {hb['exact_match']['k']}/{hb['exact_match']['n']}, deny->allow "
          f"{hb['deny_to_allow']['k']}/{hb['deny_to_allow']['n']}")
    print(f"chaos  fail-closed violations: {ch['violations']} (must be 0)")
    print(STUB_LABEL)
    print("FAIL" if not ok else "ok")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
