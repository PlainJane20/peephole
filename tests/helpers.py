"""Stub backends and fake results shared by the tests. None of these is a model."""
from types import SimpleNamespace
from typing import Any, Dict, Mapping, Optional

from peephole.backends.base import Answer
from peephole.types import ActionQuestions, InputQuestions, Intent


def fake_result(output: Any, details: Any = None, usage: Any = None):
    return SimpleNamespace(output=output, response=SimpleNamespace(provider_details=details),
                           usage=(lambda: usage) if usage is not None else None)


class StubAgent:
    """Mimics pydantic-ai's Agent.run_sync for the Backend wrappers."""

    def __init__(self, output, details=None, exc=None, usage=None):
        self.output, self.details, self.exc, self.usage = output, details, exc, usage
        self.calls = []

    def run_sync(self, state):
        self.calls.append(state)
        if self.exc:
            raise self.exc
        return fake_result(self.output, self.details, self.usage)


class ScriptedBackend:
    """Returns a fixed typed answer with fixed confidences, or raises."""
    deterministic = False

    def __init__(self, name="jev", reports_confidence=True, addresses=True, risk=3, conf: Optional[float] = 0.95,
                 consistent=False, sensitive=False, exc: Optional[Exception] = None, intent=Intent.instruction):
        self.name, self.reports_confidence = name, reports_confidence
        self.addresses, self.risk, self.conf = addresses, risk, conf
        self.consistent, self.sensitive, self.exc, self.intent = consistent, sensitive, exc, intent
        self.calls = 0

    def _confs(self, fields):
        return {f: self.conf for f in fields}

    def answer_input(self, text, task_context):
        self.calls += 1
        if self.exc:
            raise self.exc
        return Answer(InputQuestions(addresses_assistant=self.addresses, intent=self.intent, risk=self.risk),
                      self._confs(("addresses_assistant", "intent", "risk")), self.name)

    def answer_action(self, task, tool_name, tool_args, context):
        self.calls += 1
        if self.exc:
            raise self.exc
        return Answer(ActionQuestions(consistent_with_task=self.consistent, touches_sensitive_data=self.sensitive),
                      self._confs(("consistent_with_task", "touches_sensitive_data")), self.name)
