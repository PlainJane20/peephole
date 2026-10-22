import json
import subprocess
import sys

import pytest

from peephole.backends import (ChaosBackend, InjectedBackendError, JevBackend, LLMBackend, MockBackend, RulesBackend,
                               extract_confidences)
from peephole.backends.base import Answer, Backend, action_state, clip, input_state
from peephole.policy import MAX_TEXT_CHARS
from peephole.types import ActionQuestions, InputQuestions, Intent

from .helpers import ScriptedBackend, StubAgent, fake_result

F3 = ("addresses_assistant", "intent", "risk")


# ---- confidence extraction ----------------------------------------------------------------------------------
def test_confidence_single_response_key_verified_shape():
    r = fake_result(None, {"confidence": {"response": 1.0}, "probabilities": {"response": {"yes": 1.0}}})
    assert extract_confidences(r, F3) == {f: 1.0 for f in F3}


def test_confidence_keyed_by_field_name():
    r = fake_result(None, {"confidence": {"addresses_assistant": 0.9, "intent": 0.8, "risk": 0.95}})
    assert extract_confidences(r, F3) == {"addresses_assistant": 0.9, "intent": 0.8, "risk": 0.95}


def test_confidence_bare_number():
    assert extract_confidences(fake_result(None, {"confidence": 0.7}), F3) == {f: 0.7 for f in F3}


def test_missing_field_gets_minimum_of_what_exists():
    r = fake_result(None, {"confidence": {"addresses_assistant": 0.9, "risk": 0.6}})
    assert extract_confidences(r, F3) == {"addresses_assistant": 0.9, "intent": 0.6, "risk": 0.6}


def test_unrelated_keys_still_contribute_to_the_minimum():
    r = fake_result(None, {"confidence": {"response": 0.8, "addresses_assistant": 0.99}})
    c = extract_confidences(r, F3)
    assert c["intent"] == 0.8 and c["risk"] == 0.8 and c["addresses_assistant"] == 0.99


@pytest.mark.parametrize("details", [None, {}, {"confidence": None}, {"confidence": {}}, {"confidence": "high"},
                                     {"confidence": [0.9]}, {"probabilities": {"x": 1}}, "not a dict", 5])
def test_nothing_usable_gives_none_for_every_field(details):
    assert extract_confidences(fake_result(None, details), F3) == {f: None for f in F3}


@pytest.mark.parametrize("bad", [True, False, -0.1, 1.5, float("nan"), "0.9", None])
def test_invalid_numbers_are_ignored(bad):
    r = fake_result(None, {"confidence": {"addresses_assistant": bad}})
    assert extract_confidences(r, F3) == {f: None for f in F3}


def test_result_without_response_attribute():
    assert extract_confidences(object(), F3) == {f: None for f in F3}


def test_answer_confidence_is_minimum_or_none():
    a = Answer(InputQuestions(addresses_assistant=True, intent=Intent.none, risk=0), {"x": 0.9, "y": 0.7, "z": None}, "t")
    assert a.confidence == 0.7
    assert Answer(a.values, {"x": None}, "t").confidence is None
    assert Answer(a.values, {}, "t").confidence is None


# ---- state builders --------------------------------------------------------------------------------------------
def test_input_state_is_json_with_task_and_text_and_clips():
    st, clipped = input_state("hello", "do a thing")
    assert json.loads(st) == {"task": "do a thing", "untrusted_text": "hello"} and not clipped
    st, clipped = input_state("x" * (MAX_TEXT_CHARS + 50), "t")
    assert clipped and len(json.loads(st)["untrusted_text"]) == MAX_TEXT_CHARS


def test_action_state_contains_the_call_and_context():
    st, _ = action_state("task", "forward_email", {"to": "a@b.example"}, "ctx")
    d = json.loads(st)
    assert d["tool_name"] == "forward_email" and d["tool_args"] == {"to": "a@b.example"} and d["context"] == "ctx"


def test_clip_handles_non_strings():
    assert clip(123)[0] == "123"


# ---- Jev and LLM wrappers with stub agents ------------------------------------------------------------------------
def _inp(agent_out=None, details=None, **kw):
    out = agent_out or InputQuestions(addresses_assistant=True, intent=Intent.exfiltration, risk=3)
    return StubAgent(out, details, **kw)


def test_jev_backend_reads_confidence_and_one_call_answers_all_fields():
    agent = _inp(details={"confidence": {"addresses_assistant": 0.97, "intent": 0.9, "risk": 0.85}})
    b = JevBackend(agents={"input": agent})
    a = b.answer_input("text", "task")
    assert (a.values.addresses_assistant, a.values.intent, a.values.risk) == (True, Intent.exfiltration, 3)
    assert a.confidence == 0.85 and a.source == "jev"
    assert len(agent.calls) == 1                                  # ONE call for all three questions


def test_jev_backend_no_provider_details_means_none_confidence():
    a = JevBackend(agents={"input": _inp(details=None)}).answer_input("t", "")
    assert a.confidence is None and set(a.confidences) == set(F3)


def test_jev_backend_action_path():
    agent = StubAgent(ActionQuestions(consistent_with_task=False, touches_sensitive_data=True),
                      {"confidence": {"response": 0.9}})
    a = JevBackend(agents={"action": agent}).answer_action("task", "read_note", {"name": "vault-key"}, "ctx")
    assert a.values.consistent_with_task is False and a.confidence == 0.9
    assert json.loads(agent.calls[0])["tool_name"] == "read_note"


def test_jev_accepts_dict_output_by_validating_it():
    agent = StubAgent({"addresses_assistant": False, "intent": "none", "risk": 0}, {"confidence": 0.99})
    a = JevBackend(agents={"input": agent}).answer_input("t", "")
    assert a.values.risk == 0 and a.confidence == 0.99


def test_llm_backend_returns_no_confidence_even_if_details_exist():
    agent = _inp(details={"confidence": {"response": 1.0}})
    b = LLMBackend(agents={"input": agent})
    a = b.answer_input("t", "")
    assert a.confidence is None and b.reports_confidence is False and a.source == "llm"


def test_backend_propagates_agent_errors_for_the_cascade_to_handle():
    b = JevBackend(agents={"input": _inp(exc=RuntimeError("boom"))})
    with pytest.raises(RuntimeError):
        b.answer_input("t", "")


def test_usage_meta_is_recorded_when_present():
    class U:
        requests, input_tokens, output_tokens = 1, 120, 3
    a = JevBackend(agents={"input": _inp(usage=U())}).answer_input("t", "")
    assert a.meta["requests"] == 1 and a.meta["input_tokens"] == 120 and a.meta["clipped"] is False


def test_clipped_flag_is_recorded():
    a = JevBackend(agents={"input": _inp()}).answer_input("y" * (MAX_TEXT_CHARS + 1), "")
    assert a.meta["clipped"] is True


def test_policy_is_spelled_out_in_the_instructions_the_backends_build_with():
    from peephole.policy import ACTION_INSTRUCTIONS, INPUT_INSTRUCTIONS
    seen = {}

    class B(JevBackend):
        def _build(self, instructions, output_type):
            seen[output_type.__name__] = instructions
            return StubAgent(InputQuestions(addresses_assistant=False, intent=Intent.none, risk=0)
                             if output_type is InputQuestions else
                             ActionQuestions(consistent_with_task=True, touches_sensitive_data=False))
    b = B()
    b.answer_input("t", "")
    b.answer_action("t", "list_emails", {}, "")
    assert seen == {"InputQuestions": INPUT_INSTRUCTIONS, "ActionQuestions": ACTION_INSTRUCTIONS}


def test_importing_peephole_does_not_import_pydantic_ai():
    code = ("import sys, peephole, peephole.backends, peephole.cli, peephole.live; "
            "print('pydantic_ai' in sys.modules, 'typesafe_sdk' in sys.modules, 'anthropic' in sys.modules)")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True).stdout.strip()
    assert out == "False False False"


def test_real_backends_without_pydantic_ai_refuse_clearly(monkeypatch):
    import builtins
    real = builtins.__import__

    def fake(name, *a, **k):
        if name.startswith("pydantic_ai"):
            raise ImportError("no pydantic_ai")
        return real(name, *a, **k)
    monkeypatch.setattr(builtins, "__import__", fake)
    with pytest.raises(RuntimeError, match="pydantic-ai"):
        JevBackend().answer_input("t", "")
    with pytest.raises(RuntimeError, match="pydantic-ai"):
        LLMBackend().answer_input("t", "")


def test_protocol_conformance():
    for b in (RulesBackend(), MockBackend(), JevBackend(agents={}), LLMBackend(agents={}), ScriptedBackend()):
        assert isinstance(b, Backend)


# ---- real pydantic-ai FunctionModel (only where pydantic-ai is installed: Python 3.10+) -----------------------------
def test_with_a_real_pydantic_ai_agent_and_a_function_model_that_imitates_provider_details():
    pytest.importorskip("pydantic_ai")
    from pydantic_ai import Agent
    from pydantic_ai.messages import ModelResponse, ToolCallPart
    from pydantic_ai.models.function import AgentInfo, FunctionModel

    def fn(messages, info: AgentInfo):
        tool = info.output_tools[0].name
        args = {"addresses_assistant": True, "intent": "exfiltration", "risk": 3}
        return ModelResponse(parts=[ToolCallPart(tool, args)],
                             provider_details={"confidence": {"addresses_assistant": 0.99, "intent": 0.91, "risk": 0.88}})

    agent = Agent(FunctionModel(fn), output_type=InputQuestions, instructions="x", retries=0)
    a = JevBackend(agents={"input": agent}).answer_input("hello", "task")
    assert a.values.intent is Intent.exfiltration and a.values.risk == 3
    assert a.confidences == {"addresses_assistant": 0.99, "intent": 0.91, "risk": 0.88}
    assert a.confidence == 0.88


def test_real_agent_with_function_model_without_provider_details():
    pytest.importorskip("pydantic_ai")
    from pydantic_ai import Agent
    from pydantic_ai.messages import ModelResponse, ToolCallPart
    from pydantic_ai.models.function import FunctionModel

    def fn(messages, info):
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name,
                                                 {"consistent_with_task": True, "touches_sensitive_data": False})])
    agent = Agent(FunctionModel(fn), output_type=ActionQuestions, retries=0)
    a = JevBackend(agents={"action": agent}).answer_action("t", "list_emails", {}, "")
    assert a.confidence is None and a.values.consistent_with_task is True


# ---- chaos wrapper -------------------------------------------------------------------------------------------------------
def test_chaos_rate_zero_never_fails_and_one_always_fails():
    ok = ChaosBackend(ScriptedBackend(), 0.0)
    for _ in range(20):
        ok.answer_input("t", "")
    bad = ChaosBackend(ScriptedBackend(), 1.0)
    for _ in range(5):
        with pytest.raises(InjectedBackendError):
            bad.answer_input("t", "")
    assert bad.failures == 5


def test_chaos_is_seeded_and_roughly_at_rate():
    def run(seed):
        c = ChaosBackend(ScriptedBackend(), 0.3, seed)
        out = []
        for _ in range(500):
            try:
                c.answer_input("t", "")
                out.append(0)
            except InjectedBackendError:
                out.append(1)
        return out
    assert run(1) == run(1) and run(1) != run(2)
    assert 0.2 < sum(run(1)) / 500 < 0.4


def test_chaos_message_never_contains_input():
    c = ChaosBackend(ScriptedBackend(), 1.0)
    with pytest.raises(InjectedBackendError) as e:
        c.answer_input("SECRET-TEXT-123", "")
    assert "SECRET" not in str(e.value)


def test_chaos_invalid_rate():
    with pytest.raises(ValueError):
        ChaosBackend(ScriptedBackend(), 1.5)
