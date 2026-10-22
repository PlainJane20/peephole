import itertools

import pytest

from peephole import policy
from peephole.policy import (ACTION_TABLE, DEFAULT_FAIL_POLICY, DEFAULT_THRESHOLD, INPUT_TABLE, FailPolicy,
                             apply_fail_policy, decide_action, decide_input, validate_threshold)
from peephole.types import (ActionVerdict, Decision, InputQuestions, InputVerdict, Intent)


@pytest.mark.parametrize("addr,risk,expected", [
    (True, 3, "deny"), (True, 2, "deny"), (True, 1, "ask"), (True, 0, "ask"),
    (False, 3, "ask"), (False, 2, "ask"), (False, 1, "ask"), (False, 0, "allow")])
def test_input_table_every_row(addr, risk, expected):
    assert decide_input(addr, risk)[0].value == expected


@pytest.mark.parametrize("cons,sens,expected", [
    (False, False, "deny"), (False, True, "deny"), (True, True, "ask"), (True, False, "allow")])
def test_action_table_every_row(cons, sens, expected):
    assert decide_action(cons, sens)[0].value == expected


def test_input_function_matches_table_for_every_combination():
    ids = {r: d for r, _, d in INPUT_TABLE}
    seen = set()
    for addr, risk in itertools.product([True, False], range(4)):
        d, rid = decide_input(addr, risk)
        assert ids[rid] is d
        seen.add(rid)
    assert seen == set(ids)          # every table row is reachable, none is dead


def test_action_function_matches_table_for_every_combination():
    ids = {r: d for r, _, d in ACTION_TABLE}
    seen = set()
    for c, s in itertools.product([True, False], repeat=2):
        d, rid = decide_action(c, s)
        assert ids[rid] is d
        seen.add(rid)
    assert seen == set(ids)


def test_single_threshold_in_one_place():
    assert DEFAULT_THRESHOLD == 0.8
    import inspect, pathlib, re
    from peephole.cascade import Cascade
    from peephole.live import Config
    assert inspect.signature(Cascade.__init__).parameters["threshold"].default == DEFAULT_THRESHOLD
    assert Config().threshold == DEFAULT_THRESHOLD
    src = pathlib.Path(inspect.getsourcefile(policy)).parent
    lit = re.compile(r"threshold\s*[:=][^=\n]*?\b0?\.\d+\b")
    offenders = [p.name for p in src.rglob("*.py") if p.name != "policy.py" and lit.search(p.read_text())]
    assert offenders == [], offenders


@pytest.mark.parametrize("bad", [-0.1, 1.1, True, "0.8", None])
def test_threshold_validation_rejects(bad):
    with pytest.raises(ValueError):
        validate_threshold(bad)


@pytest.mark.parametrize("ok", [0, 0.0, 0.5, 1, 1.0])
def test_threshold_validation_accepts(ok):
    assert validate_threshold(ok) == float(ok)


def test_default_fail_policy_is_closed_for_both_gates():
    assert DEFAULT_FAIL_POLICY == {"input": FailPolicy.closed, "action": FailPolicy.closed}


def test_fail_closed_upgrades_allow_only():
    assert apply_fail_policy(FailPolicy.closed, Decision.allow) is Decision.ask
    assert apply_fail_policy(FailPolicy.closed, Decision.ask) is Decision.ask
    assert apply_fail_policy(FailPolicy.closed, Decision.deny) is Decision.deny


def test_fail_open_keeps_the_rules_verdict():
    for d in Decision:
        assert apply_fail_policy(FailPolicy.open, d) is d


def test_questions_model_fields_and_descriptions():
    f = InputQuestions.model_fields
    assert set(f) == {"addresses_assistant", "intent", "risk"}
    assert all(v.description for v in f.values())
    with pytest.raises(Exception):
        InputQuestions(addresses_assistant=True, intent="none", risk=4)
    with pytest.raises(Exception):
        InputQuestions(addresses_assistant=True, intent="made_up", risk=1)


def test_intent_enum_has_the_six_values():
    assert [i.value for i in Intent] == ["none", "instruction", "exfiltration", "impersonation",
                                         "authority_pressure", "other"]


def test_verdict_min_confidence():
    v = InputVerdict(addresses_assistant=True, intent=Intent.instruction, risk=2, decision=Decision.deny,
                     source="jev", confidences={"a": 0.9, "b": None, "c": 0.7})
    assert v.min_confidence == 0.7
    v2 = InputVerdict(addresses_assistant=False, intent=Intent.none, risk=0, decision=Decision.allow, source="rules")
    assert v2.min_confidence is None


def test_action_verdict_roundtrip_json():
    v = ActionVerdict(consistent_with_task=True, touches_sensitive_data=False, decision=Decision.allow, source="x")
    assert ActionVerdict.model_validate_json(v.model_dump_json()) == v


def test_policy_text_mentions_every_field_and_the_shared_constants():
    t = policy.INPUT_INSTRUCTIONS
    for w in ("addresses_assistant", "intent", "risk", "exfiltration", "impersonation", "authority_pressure"):
        assert w in t
    a = policy.ACTION_INSTRUCTIONS
    assert policy.INTERNAL_DOMAIN in a and policy.INTERNAL_CHANNEL in a
    for tool in policy.TOOLS:
        assert tool in a


def test_decision_tables_export():
    t = policy.decision_tables()
    assert len(t["input"]) == 5 and len(t["action"]) == 3
