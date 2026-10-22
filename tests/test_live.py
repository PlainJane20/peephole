"""The guarded live runner, tested with STUB backends only. No model is ever called."""
import json
from pathlib import Path

import pytest

from peephole import live
from peephole.audit import load_and_verify
from peephole.backends import MockBackend, RulesBackend
from peephole.backends.base import Answer
from peephole.live import EXIT_BUDGET, EXIT_ERROR, EXIT_KILL, EXIT_OK, EXIT_REFUSED, KillSwitch, main, plan, Config
from peephole.types import ActionQuestions, InputQuestions, Intent


class StubModel:
    """Deterministic stub standing in for Jev/Haiku. Counts calls; can fail on a schedule."""
    deterministic = False

    def __init__(self, name, reports=True, fail_plan=None, conf=0.9):
        self.name, self.reports_confidence = name, reports
        self.calls = 0
        self.fail_plan = list(fail_plan or [])      # one entry per call: None = ok, or an exception to raise
        self.conf = conf

    def _next(self):
        self.calls += 1
        if self.fail_plan:
            e = self.fail_plan.pop(0)
            if e is not None:
                raise e

    def answer_input(self, text, ctx):
        self._next()
        bad = "ignore" in text.lower() or "forward" in text.lower()
        c = {f: self.conf for f in ("addresses_assistant", "intent", "risk")} if self.reports_confidence else {
            f: None for f in ("addresses_assistant", "intent", "risk")}
        return Answer(InputQuestions(addresses_assistant=bad, intent=Intent.instruction if bad else Intent.none,
                                     risk=3 if bad else 0), c, self.name, {"requests": 1})

    def answer_action(self, task, tool, args, ctx):
        self._next()
        ok = tool in ("list_emails", "read_email")
        c = {f: self.conf for f in ("consistent_with_task", "touches_sensitive_data")} if self.reports_confidence else {
            f: None for f in ("consistent_with_task", "touches_sensitive_data")}
        return Answer(ActionQuestions(consistent_with_task=ok, touches_sensitive_data=False), c, self.name)


class Boom(Exception):
    pass


class HTTPErr(Exception):
    def __init__(self, status, msg="err"):
        super().__init__(msg)
        self.status_code = status


class InvalidOut(Exception):
    pass


InvalidOut.__name__ = "UnexpectedModelBehavior"


def env(**kw):
    e = {"TYPESAFE_API_KEY": "test-key-not-real", "ANTHROPIC_API_KEY": "test-key-not-real-2"}
    e.update(kw)
    return e


def facs(jev=None, haiku=None):
    jev, haiku = jev or StubModel("jev"), haiku or StubModel("haiku", reports=False)
    return {"rules": RulesBackend, "jev": lambda: jev, "haiku": lambda: haiku}, jev, haiku


def run(argv, environ=None, factories=None, tmp_path=None, kill=None, sleeps=None, clock=lambda: 1_700_000_000.0):
    out = []
    base = ["--out-dir", str(tmp_path), "--kill-file", str(tmp_path / "KILL")]
    code = main(base + list(argv), environ if environ is not None else env(), factories=factories,
                kill=kill, out=out.append, sleep=(sleeps.append if sleeps is not None else (lambda s: None)), clock=clock)
    return code, "\n".join(out)


def saved(tmp_path):
    dirs = [d for d in tmp_path.iterdir() if d.is_dir()]
    assert len(dirs) == 1
    return dirs[0], json.loads((dirs[0] / "summary.json").read_text()), json.loads((dirs[0] / "state.json").read_text())


SMALL = ["--limit", "6", "--repeats", "2", "--batch-size", "4"]


# ---- dry run --------------------------------------------------------------------------------------------------------------
def test_dry_run_makes_zero_calls_writes_nothing_and_needs_no_key(tmp_path):
    f, jev, haiku = facs()
    code, out = run(["--dry-run"], environ={}, factories=f, tmp_path=tmp_path)
    assert code == EXIT_OK and jev.calls == 0 and haiku.calls == 0
    assert list(tmp_path.iterdir()) == [] and "Dry run" in out


def test_dry_run_prints_exact_call_counts_per_backend(tmp_path):
    code, out = run(["--dry-run"] + SMALL, environ={}, tmp_path=tmp_path)
    # 6 input + 6 action examples, 2 repeats => 24 calls per model backend
    assert "jev   : 24 calls planned" in out and "haiku : 24 calls planned" in out and "rules : 0 model calls" in out


def test_plan_counts_for_full_datasets():
    p = plan(Config())
    n_in, n_act = 265, 270
    assert p["backends"]["jev"]["model_calls_planned"] == (n_in + n_act) * 3
    assert p["backends"]["rules"]["model_calls"] == 0
    assert p["backends"]["jev"]["input_tokens_upper_bound"] > 0 and p["backends"]["jev"]["output_tokens_upper_bound"] > 0
    assert "NOT measured" in p["token_bounds_note"] or "GUESS" in p["token_bounds_note"]


def test_plan_reflects_cap_and_retry_worst_case():
    p = plan(Config(max_calls=100, limit=None))["backends"]["jev"]
    assert p["model_calls_allowed_by_cap"] == 100 and p["cap_truncates_run"]
    assert p["worst_case_http_attempts_with_retries"] == 100 + min(100, 100 * 4)
    assert p["input_tokens_upper_bound"] < plan(Config())["backends"]["jev"]["input_tokens_upper_bound"]


def test_plan_haiku_output_bound_is_larger_than_jev():
    p = plan(Config())["backends"]
    assert p["haiku"]["output_tokens_upper_bound"] > p["jev"]["output_tokens_upper_bound"]


# ---- refusals ----------------------------------------------------------------------------------------------------------------
def test_refuses_without_live(tmp_path):
    f, jev, _ = facs()
    code, _ = run([], factories=f, tmp_path=tmp_path)
    assert code == EXIT_REFUSED and jev.calls == 0 and list(tmp_path.iterdir()) == []


def test_refuses_live_without_yes(tmp_path):
    f, jev, _ = facs()
    code, _ = run(["--live"], factories=f, tmp_path=tmp_path)
    assert code == EXIT_REFUSED and jev.calls == 0


def test_refuses_live_without_the_jev_key_in_the_environment(tmp_path):
    f, jev, _ = facs()
    code, _ = run(["--live", "--yes"], environ={}, factories=f, tmp_path=tmp_path)
    assert code == EXIT_REFUSED and jev.calls == 0


def test_haiku_is_optional_and_skipped_without_its_key(tmp_path):
    f, jev, haiku = facs()
    code, out = run(["--live", "--yes"] + SMALL, environ={"TYPESAFE_API_KEY": "k"}, factories=f, tmp_path=tmp_path)
    assert code == EXIT_OK and haiku.calls == 0 and jev.calls > 0 and "Haiku is skipped" in out


def test_explicitly_requested_haiku_without_key_is_refused(tmp_path):
    f, jev, haiku = facs()
    code, _ = run(["--live", "--yes", "--backends", "rules,jev,haiku"] + SMALL, environ={"TYPESAFE_API_KEY": "k"},
                  factories=f, tmp_path=tmp_path)
    assert code == EXIT_REFUSED and jev.calls == 0


def test_rules_only_needs_no_key_and_no_model(tmp_path):
    f, jev, haiku = facs()
    code, _ = run(["--live", "--yes", "--backends", "rules"] + SMALL, environ={}, factories=f, tmp_path=tmp_path)
    assert code == EXIT_OK and jev.calls == haiku.calls == 0


def test_keys_cannot_be_passed_as_flags():
    import argparse
    ap = live._parser()
    flags = {s for a in ap._actions for s in a.option_strings}
    assert not [f for f in flags if "key" in f or "token" in f or "secret" in f]
    with pytest.raises(SystemExit):
        ap.parse_args(["--api-key", "x"])


def test_script_source_never_reads_keys_from_anything_but_the_environment():
    import re
    src = Path(live.__file__).read_text()
    assert src.count("environ.get(") >= 2 and "getpass" not in src
    assert not re.search(r"(?<![\w.])input\(", src)                 # no interactive key prompt
    assert "add_argument(\"--api" not in src and "dotenv" not in src


def test_unknown_backend_or_dataset_is_a_usage_error(tmp_path):
    assert run(["--dry-run", "--backends", "gpt"], tmp_path=tmp_path)[0] == EXIT_REFUSED
    assert run(["--dry-run", "--datasets", "nope"], tmp_path=tmp_path)[0] == EXIT_REFUSED
    assert run(["--dry-run", "--repeats", "0"], tmp_path=tmp_path)[0] == EXIT_REFUSED


# ---- a full stubbed run -------------------------------------------------------------------------------------------------------
def test_full_stub_run_saves_summary_state_audit_and_metadata(tmp_path):
    f, jev, haiku = facs()
    code, out = run(["--live", "--yes"] + SMALL, factories=f, tmp_path=tmp_path)
    assert code == EXIT_OK
    d, summary, state = saved(tmp_path)
    assert d.name == "20231114-221320-seed0" and summary["status"] == "complete"
    assert jev.calls == 24 and haiku.calls == 24
    m = summary["meta"]
    assert m["models"] == {"jev": "jev-latest", "haiku": "anthropic:claude-haiku-4-5-20251001"} and m["seed"] == 0
    assert m["started_utc"].startswith("2023-11-14") and "python" in m["versions"] and "git_commit" in m
    assert set(summary["backends"]) == {"rules", "jev", "haiku"}
    assert (d / "audit.jsonl").exists() and load_and_verify(d / "audit.jsonl")[0]
    assert summary["audit"]["chain_ok"] and summary["audit"]["records"] >= 5


def test_summary_headline_is_repeat_zero_and_reports_agreement(tmp_path):
    f, *_ = facs()
    run(["--live", "--yes"] + SMALL, factories=f, tmp_path=tmp_path)
    _, summary, _ = saved(tmp_path)
    j = summary["backends"]["jev"]["input"]
    assert j["examples_answered_in_repeat_0"] == 6 and j["repeats_present"] == [0, 1]
    assert j["decision_agreement_across_repeats"]["rate"] == 1.0
    assert summary["backends"]["rules"]["input"]["repeats_present"] == [0]          # rules: one repeat


def test_jev_calibration_present_and_haiku_calibration_unavailable(tmp_path):
    f, *_ = facs()
    run(["--live", "--yes"] + SMALL, factories=f, tmp_path=tmp_path)
    b = saved(tmp_path)[1]["backends"]
    assert b["jev"]["input"]["calibration_repeat_0"]["available"] is True
    assert b["haiku"]["input"]["calibration_repeat_0"]["available"] is False


def test_cascade_replay_is_computed_from_recorded_answers_with_no_new_calls(tmp_path):
    f, jev, haiku = facs()
    run(["--live", "--yes", "--limit", "8", "--repeats", "1"], factories=f, tmp_path=tmp_path)
    calls = (jev.calls, haiku.calls)
    _, summary, _ = saved(tmp_path)
    r = summary["cascade_replay"]
    assert set(r["thresholds"]) == {f"{t:.2f}" for t in live.THRESHOLDS}
    assert r["thresholds"]["0.80"]["input"]["injections"]["n"] > 0
    assert calls == (16, 16)


def test_state_stores_answers_and_confidences_never_text(tmp_path):
    f, *_ = facs()
    run(["--live", "--yes", "--limit", "10", "--repeats", "1"], factories=f, tmp_path=tmp_path)
    d, _, state = saved(tmp_path)
    blob = (d / "state.json").read_text() + (d / "audit.jsonl").read_text() + (d / "summary.json").read_text()
    from peephole.datasets import load_input_examples, load_action_examples
    for ex in load_input_examples()[:60]:
        assert ex.text[:60] not in blob
    for ex in load_action_examples()[:60]:
        assert ex.task not in blob or len(ex.task) < 15
    rec = next(iter(state["records"].values()))
    assert "confidences" in rec and "decision" in rec and "text" not in rec


def test_no_tmp_files_left_after_atomic_saves(tmp_path):
    f, *_ = facs()
    run(["--live", "--yes"] + SMALL, factories=f, tmp_path=tmp_path)
    d, *_ = saved(tmp_path)
    assert not list(d.glob("*.tmp")) and {p.name for p in d.iterdir()} == {"state.json", "summary.json", "audit.jsonl"}


def test_state_is_saved_every_batch(tmp_path, monkeypatch):
    writes = []
    real = live._atomic_write
    monkeypatch.setattr(live, "_atomic_write", lambda p, payload: (writes.append((p.name, len(payload.get("records", {})))), real(p, payload)))
    f, *_ = facs()
    run(["--live", "--yes", "--backends", "jev", "--limit", "5", "--repeats", "1", "--batch-size", "3"], factories=f, tmp_path=tmp_path)
    counts = [n for name, n in writes if name == "state.json"]
    assert counts[0] == 3 and counts[-1] == 10 and counts == sorted(counts)


# ---- budgets ------------------------------------------------------------------------------------------------------------------------
def test_max_calls_is_a_hard_cap_per_backend_and_exits_3(tmp_path):
    f, jev, haiku = facs()
    code, out = run(["--live", "--yes", "--max-calls", "5"] + SMALL, factories=f, tmp_path=tmp_path)
    assert code == EXIT_BUDGET and jev.calls == 5 and haiku.calls == 0 and "resume with" in out
    _, summary, _ = saved(tmp_path)
    assert summary["status"] == "partial_budget_reached" and summary["calls_made_this_invocation"]["jev"] == 5


def test_budget_cap_does_not_limit_the_rules_baseline(tmp_path):
    f, *_ = facs()
    run(["--live", "--yes", "--max-calls", "0"] + SMALL, factories=f, tmp_path=tmp_path)
    _, summary, state = saved(tmp_path)
    assert summary["backends"]["rules"]["input"]["examples_answered_in_repeat_0"] == 6


def test_truncated_run_samples_examples_in_a_seeded_shuffled_order_not_first_n(tmp_path):
    f, jev, _ = facs()
    run(["--live", "--yes", "--backends", "jev", "--datasets", "input", "--max-calls", "20", "--repeats", "1", "--limit", "60"],
        factories=f, tmp_path=tmp_path)
    _, _, state = saved(tmp_path)
    ids = [r["id"] for r in state["records"].values()]
    assert len(ids) == 20 and len({i.split("/")[0] for i in ids}) > 3          # spread over families


# ---- resume -----------------------------------------------------------------------------------------------------------------------------
def test_resume_completes_without_repeating_finished_calls(tmp_path):
    f1, jev1, haiku1 = facs()
    code, _ = run(["--live", "--yes", "--max-calls", "7"] + SMALL, factories=f1, tmp_path=tmp_path)
    assert code == EXIT_BUDGET
    rid = saved(tmp_path)[0].name
    f2, jev2, haiku2 = facs()
    code, out = run(["--live", "--yes", "--resume", rid] + SMALL, factories=f2, tmp_path=tmp_path)
    assert code == EXIT_OK
    assert jev1.calls + jev2.calls == 24 and haiku2.calls == 24                       # exactly the plan, no repeats
    _, summary, state = saved(tmp_path)
    assert summary["status"] == "complete" and summary["calls_made_total"]["jev"] == 24
    assert load_and_verify(tmp_path / rid / "audit.jsonl")[0]
    assert any(r["event"] == "run_resume" for r in json.loads("[" + ",".join((tmp_path / rid / "audit.jsonl").read_text().splitlines()) + "]"))


def test_resume_of_a_complete_run_makes_no_calls(tmp_path):
    f1, *_ = facs()
    run(["--live", "--yes"] + SMALL, factories=f1, tmp_path=tmp_path)
    rid = saved(tmp_path)[0].name
    f2, jev2, haiku2 = facs()
    code, _ = run(["--live", "--yes", "--resume", rid] + SMALL, factories=f2, tmp_path=tmp_path)
    assert code == EXIT_OK and jev2.calls == haiku2.calls == 0


def test_resume_refuses_a_different_configuration(tmp_path):
    f1, *_ = facs()
    run(["--live", "--yes", "--max-calls", "3"] + SMALL, factories=f1, tmp_path=tmp_path)
    rid = saved(tmp_path)[0].name
    f2, jev2, _ = facs()
    code, _ = run(["--live", "--yes", "--resume", rid, "--limit", "6", "--repeats", "3"], factories=f2, tmp_path=tmp_path)
    assert code == EXIT_REFUSED and jev2.calls == 0
    code, _ = run(["--live", "--yes", "--resume", rid, "--seed", "5", "--repeats", "2", "--limit", "6"], factories=f2, tmp_path=tmp_path)
    assert code == EXIT_REFUSED


def test_resume_of_unknown_run_is_refused(tmp_path):
    code, _ = run(["--live", "--yes", "--resume", "nope"], tmp_path=tmp_path)
    assert code == EXIT_REFUSED


def test_resume_dry_run_still_makes_no_calls(tmp_path):
    f, jev, _ = facs()
    code, _ = run(["--dry-run", "--resume", "whatever"] + SMALL, factories=f, tmp_path=tmp_path)
    assert code == EXIT_OK and jev.calls == 0


# ---- kill switch --------------------------------------------------------------------------------------------------------------------------
def test_kill_file_before_start_refuses(tmp_path):
    (tmp_path / "KILL").write_text("")
    f, jev, _ = facs()
    code, _ = run(["--live", "--yes"] + SMALL, factories=f, tmp_path=tmp_path)
    assert code == EXIT_KILL and jev.calls == 0


def test_kill_env_before_start_refuses(tmp_path):
    f, jev, _ = facs()
    code, _ = run(["--live", "--yes"] + SMALL, environ=env(PEEPHOLE_KILL_SWITCH="1"), factories=f, tmp_path=tmp_path,
                  kill=KillSwitch(str(tmp_path / "KILL"), env(PEEPHOLE_KILL_SWITCH="1")))
    assert code == EXIT_KILL and jev.calls == 0


def test_kill_switch_mid_run_stops_and_saves_partial(tmp_path):
    f, jev, _ = facs()

    class K:
        def __init__(self):
            self.n = 0

        def reason(self):
            self.n += 1
            return "pulled" if jev.calls >= 4 else ""
    code, out = run(["--live", "--yes", "--batch-size", "2"] + SMALL, factories=f, tmp_path=tmp_path, kill=K())
    assert code == EXIT_KILL and jev.calls == 4
    _, summary, state = saved(tmp_path)
    assert summary["status"] == "partial_kill_switch" and len(state["records"]) >= 4


def test_kill_switch_object_reads_file_and_env(tmp_path):
    k = KillSwitch(str(tmp_path / "K"), {})
    assert k.reason() == ""
    (tmp_path / "K").write_text("")
    assert "kill file" in k.reason()
    assert "PEEPHOLE_KILL_SWITCH" in KillSwitch(str(tmp_path / "none"), {"PEEPHOLE_KILL_SWITCH": "true"}).reason()


# ---- retries and errors ---------------------------------------------------------------------------------------------------------------------
def test_transient_errors_are_retried_with_backoff_then_succeed(tmp_path):
    jev = StubModel("jev", fail_plan=[HTTPErr(529), HTTPErr(429), None])
    f, *_ = facs(jev=jev)
    sleeps = []
    code, _ = run(["--live", "--yes", "--backends", "jev", "--limit", "3", "--repeats", "1", "--retry-base-s", "2"],
                  factories=f, tmp_path=tmp_path, sleeps=sleeps)
    assert code == EXIT_OK and jev.calls == 6 + 2          # 6 logical calls + 2 retries
    assert len(sleeps) == 2 and sleeps[1] >= sleeps[0] * 0.9 and max(sleeps) <= 60
    _, summary, _ = saved(tmp_path)
    assert summary["transient_retries"] == 2


def test_permanent_error_stops_the_run_with_exit_5_and_saves_partial(tmp_path):
    jev = StubModel("jev", fail_plan=[None, None, HTTPErr(401, "bad key")])
    f, *_ = facs(jev=jev)
    code, out = run(["--live", "--yes", "--backends", "jev", "--limit", "5", "--repeats", "1"], factories=f, tmp_path=tmp_path)
    assert code == EXIT_ERROR and jev.calls == 3
    _, summary, state = saved(tmp_path)
    assert summary["status"] == "partial_error" and len(state["records"]) == 2
    assert state["failures"][-1]["kind"] == "abort" and "api_permanent" in state["failures"][-1]["reason"]


def test_retries_exhausted_stops_the_run(tmp_path):
    jev = StubModel("jev", fail_plan=[HTTPErr(503)] * 10)
    f, *_ = facs(jev=jev)
    code, _ = run(["--live", "--yes", "--backends", "jev", "--limit", "3", "--repeats", "1", "--retry-max-attempts", "3"],
                  factories=f, tmp_path=tmp_path)
    assert code == EXIT_ERROR and jev.calls == 3


def test_global_retry_cap_stops_the_run(tmp_path):
    jev = StubModel("jev", fail_plan=[HTTPErr(503)] * 50)
    f, *_ = facs(jev=jev)
    code, _ = run(["--live", "--yes", "--backends", "jev", "--limit", "3", "--repeats", "1", "--max-total-retries", "1"],
                  factories=f, tmp_path=tmp_path)
    assert code == EXIT_ERROR and jev.calls == 2


def test_invalid_model_output_is_recorded_and_the_run_continues(tmp_path):
    jev = StubModel("jev", fail_plan=[InvalidOut("bad json"), None, None])
    f, *_ = facs(jev=jev)
    code, _ = run(["--live", "--yes", "--backends", "jev", "--datasets", "input", "--limit", "3", "--repeats", "1"],
                  factories=f, tmp_path=tmp_path)
    assert code == EXIT_OK
    _, summary, state = saved(tmp_path)
    assert summary["failures"] == 1 and summary["failure_kinds"] == ["invalid_output"]
    assert summary["backends"]["jev"]["input"]["examples_answered_in_repeat_0"] == 2
    assert summary["backends"]["jev"]["input"]["examples_expected"] == 3


def test_an_unexpected_bug_stops_the_run_and_is_not_swallowed(tmp_path):
    jev = StubModel("jev", fail_plan=[None, KeyError("bug")])
    f, *_ = facs(jev=jev)
    code, _ = run(["--live", "--yes", "--backends", "jev", "--limit", "3", "--repeats", "1"], factories=f, tmp_path=tmp_path)
    assert code == EXIT_ERROR


def test_error_details_are_key_redacted_in_every_written_file(tmp_path):
    secret = "sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUV"
    other = "apikey_ZZZZZZZZZZZZZZZZZZZZ"
    jev = StubModel("jev", fail_plan=[HTTPErr(401, f"invalid x-api-key: {secret} and Authorization: Bearer {other}")])
    f, *_ = facs(jev=jev)
    code, out = run(["--live", "--yes", "--backends", "jev", "--limit", "2", "--repeats", "1"], factories=f, tmp_path=tmp_path)
    assert code == EXIT_ERROR
    d, *_ = saved(tmp_path)
    blob = out + "".join(p.read_text() for p in d.iterdir())
    assert secret not in blob and other not in blob and "[REDACTED]" in blob


def test_the_environment_key_values_never_appear_in_outputs(tmp_path):
    f, *_ = facs()
    code, out = run(["--live", "--yes"] + SMALL, factories=f, tmp_path=tmp_path, environ=env(TYPESAFE_API_KEY="UNIQUE-KEY-VALUE-123"))
    d, *_ = saved(tmp_path)
    assert "UNIQUE-KEY-VALUE-123" not in out + "".join(p.read_text() for p in d.iterdir())


def test_audit_chain_records_abort_and_verifies(tmp_path):
    jev = StubModel("jev", fail_plan=[HTTPErr(400, "bad request")])
    f, *_ = facs(jev=jev)
    run(["--live", "--yes", "--backends", "jev", "--limit", "2", "--repeats", "1"], factories=f, tmp_path=tmp_path)
    d, *_ = saved(tmp_path)
    ok, bad, n = load_and_verify(d / "audit.jsonl")
    events = [json.loads(l)["event"] for l in (d / "audit.jsonl").read_text().splitlines()]
    assert ok and "aborted" in events and events[0] == "run_start" and events[-1] == "run_end"


def test_a_second_run_with_the_same_timestamp_is_refused_not_overwritten(tmp_path):
    f, *_ = facs()
    run(["--live", "--yes", "--backends", "rules"] + SMALL, factories=f, tmp_path=tmp_path)
    code, _ = run(["--live", "--yes", "--backends", "rules"] + SMALL, factories=f, tmp_path=tmp_path)
    assert code == EXIT_REFUSED
