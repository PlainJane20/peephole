"""ChaosBackend: wraps a backend and raises on a seeded fraction of calls (for the fail-closed chaos test)."""
from __future__ import annotations

import random
from typing import Any, Mapping

from .base import Answer, Backend


class InjectedBackendError(RuntimeError):
    """The failure the chaos wrapper raises. Its message deliberately contains nothing from the input."""


class ChaosBackend:
    def __init__(self, inner: Backend, failure_rate: float, seed: int = 0) -> None:
        if not 0.0 <= failure_rate <= 1.0:
            raise ValueError("failure_rate must be within [0, 1]")
        self.inner = inner
        self.failure_rate = failure_rate
        self._rng = random.Random(seed)
        self.name = inner.name
        self.reports_confidence = inner.reports_confidence
        self.deterministic = inner.deterministic
        self.calls = 0
        self.failures = 0

    def _maybe_fail(self) -> None:
        self.calls += 1
        if self._rng.random() < self.failure_rate:
            self.failures += 1
            raise InjectedBackendError("injected backend failure")

    def answer_input(self, text: str, task_context: str) -> Answer:
        self._maybe_fail()
        return self.inner.answer_input(text, task_context)

    def answer_action(self, task: str, tool_name: str, tool_args: Mapping[str, Any], context: str) -> Answer:
        self._maybe_fail()
        return self.inner.answer_action(task, tool_name, tool_args, context)
