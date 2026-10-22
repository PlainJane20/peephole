import json
import logging

import pytest

from evals import calibration, cascade_eval, chaos, common, latency, rules_and_mock, run_all


@pytest.fixture
def results(tmp_path, monkeypatch):
    monkeypatch.setattr(common, "RESULTS", tmp_path)
    logging.getLogger("peephole.cascade").setLevel(logging.ERROR)
    return tmp_path


def load(results, name):
    return json.loads((results / name).read_text())


def test_rules_and_mock_outputs_are_labelled(results):
    rules_and_mock.run()
    for name in ("input.json", "action.json"):
        d = load(results, name)
        assert "PLUMBING" in d["label"]["mock"] and d["mock"]["backend_is_stub"] is True
        assert "backend_is_stub" not in d["rules"]
        assert d["meta"]["environment"].startswith("OFFLINE")


def test_input_eval_has_every_required_metric(results):
    rules_and_mock.run()
    r = load(results, "input.json")["rules"]
    assert {"overall", "by_split", "by_family_rate_of_non_allow", "by_kind_rate_of_non_allow",
            "confusion_label_by_decision", "latency"} <= set(r)
    assert set(r["by_split"]) == {"dev", "heldout"}
    assert "wilson95" in r["overall"]["injections"]


def test_action_eval_reports_ambiguous_separately(results):
    rules_and_mock.run()
    r = load(results, "action.json")["rules"]
    assert r["n_ambiguous_labels"] > 0 and r["ambiguous_labels_reported_separately"]["n"] == r["n_ambiguous_labels"]
    assert r["headline_firm_labels_only"]["n"] == r["n_firm_labels"]
    assert set(r["by_kind_firm"]) >= {"consistent", "injected-deviation", "over-broad"}


def test_rules_have_no_calibration_but_mock_does(results):
    calibration.run()
    d = load(results, "calibration.json")
    assert d["backend_is_stub"] and d["input"]["available"] and d["action"]["available"]
    assert "PLUMBING" in d["label"]
    assert len(d["input"]["risk_coverage"]) == len(calibration.THRESHOLDS)


def test_risk_coverage_coverage_falls_as_threshold_rises(results):
    calibration.run()
    cov = [p["coverage"] for p in load(results, "calibration.json")["input"]["risk_coverage"]]
    assert cov == sorted(cov, reverse=True)


def test_cascade_eval_has_thresholds_and_rules_comparison(results):
    cascade_eval.run()
    d = load(results, "cascade.json")
    assert d["backend_is_stub"] and set(d["results"]) == {"rules_only", "mock_only_fallback_rules", "mock_then_mock_llm"}
    assert set(d["results"]["mock_then_mock_llm"]) == {f"{t:.2f}" for t in cascade_eval.THRESHOLDS}


def test_higher_threshold_escalates_more(results):
    cascade_eval.run()
    r = load(results, "cascade.json")["results"]["mock_only_fallback_rules"]
    esc = [r[f"{t:.2f}"]["escalation_rate_input"] for t in cascade_eval.THRESHOLDS]
    assert esc == sorted(esc)


def test_chaos_fail_closed_has_zero_violations_and_open_can_allow(results):
    out = chaos.run()
    assert out["violations"] == 0
    closed, opn = out["results"]["closed"]["1.0"], out["results"]["open"]["1.0"]
    assert closed["input"]["injections_allowed"] == 0
    assert closed["input"]["benign_held_or_denied"] == closed["input"]["n_benign"]      # the availability cost
    assert opn["input"]["benign_held_or_denied"] < closed["input"]["benign_held_or_denied"]


def test_chaos_more_failures_means_more_calls_with_errors(results):
    out = chaos.run()
    errs = [out["results"]["closed"][f"{r:.1f}"]["input"]["calls_with_backend_error"] for r in chaos.RATES]
    assert errs == sorted(errs) and errs[0] == 0 and errs[-1] > 0


def test_latency_eval_runs_and_has_percentiles(results):
    d = latency.run()
    assert d["rules_input_gate"]["p50_ms"] is not None and d["rules_input_gate"]["p95_ms"] >= d["rules_input_gate"]["p50_ms"]
    assert "no model call" in d["caveat"]


def test_run_all_exit_zero_and_writes_every_file(results, capsys):
    assert run_all.main() == 0
    names = {p.name for p in results.iterdir()}
    assert names == {"input.json", "action.json", "calibration.json", "cascade.json", "chaos.json", "latency.json", "summary.json"}
    out = capsys.readouterr().out
    assert "PLUMBING CHECK ONLY" in out and "violations" in out
    s = load(results, "summary.json")
    assert "NO live Jev or LLM result exists" in s["label"]


def test_run_all_is_deterministic_apart_from_latency(results):
    run_all.main()
    a = {n: load(results, n) for n in ("input.json", "action.json", "cascade.json", "chaos.json", "calibration.json")}
    run_all.main()
    for n, d in a.items():
        b = load(results, n)
        for part in (d, b):
            for k in ("latency",):
                part.pop(k, None)
        def strip(x):
            if isinstance(x, dict):
                return {k: strip(v) for k, v in x.items() if k != "latency"}
            return x
        assert strip(d) == strip(b), n


def test_run_all_fails_loudly_if_fail_closed_is_broken(results, monkeypatch):
    from peephole import policy
    import peephole.cascade as casc
    monkeypatch.setattr(casc, "apply_fail_policy", lambda p, d: d)      # simulate a regression: closed lets allow through
    assert run_all.main() == 1
