"""Shared plumbing for the two Pydantic AI backends (Jev and the LLM). Imports of pydantic-ai are LAZY.

STATUS: BUILT AND OFFLINE-TESTED ONLY, NOT RUN LIVE. Nothing in this repository has been run against Jev or Claude Haiku.
Offline tests use stub agents and, where pydantic-ai is installed (Python 3.10+), a FunctionModel that
imitates a decision model's `provider_details`. How the real services behave is not verified here.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, Mapping, Optional

from pydantic import BaseModel

from ..policy import ACTION_INSTRUCTIONS, INPUT_INSTRUCTIONS
from ..types import ACTION_FIELDS, INPUT_FIELDS, ActionQuestions, InputQuestions
from .base import Answer, action_state, extract_confidences, input_state


def _need_pydantic_ai(extra: str) -> None:
    try:
        import pydantic_ai  # noqa: F401
    except ImportError as exc:
        raise RuntimeError(f"this backend needs pydantic-ai (Python 3.10+): pip install -e '.[{extra}]'") from exc


class PydanticAIBackend:
    """Runs `output_type=<questions model>` through a Pydantic AI Agent: ONE call answers every question."""

    name = "pai"
    reports_confidence = False
    deterministic = False
    _extra = "llm"

    def __init__(self, agents: Optional[Mapping[str, Any]] = None) -> None:
        # `agents` lets tests inject stubs with .run_sync(state) -> result; real agents are built lazily.
        self._agents: Dict[str, Any] = dict(agents or {})

    def _build(self, instructions: str, output_type: type) -> Any:  # pragma: no cover - needs pydantic-ai
        raise NotImplementedError

    def _agent(self, kind: str) -> Any:
        if kind not in self._agents:
            if kind == "input":
                self._agents[kind] = self._build(INPUT_INSTRUCTIONS, InputQuestions)
            else:
                self._agents[kind] = self._build(ACTION_INSTRUCTIONS, ActionQuestions)
        return self._agents[kind]

    def _run(self, kind: str, state: str, clipped: bool, model: type, fields: tuple) -> Answer:
        result = self._agent(kind).run_sync(state)
        out = result.output
        values = out if isinstance(out, BaseModel) else model.model_validate(out)
        conf = extract_confidences(result, fields) if self.reports_confidence else {f: None for f in fields}
        meta: Dict[str, Any] = {"clipped": clipped}
        usage = getattr(result, "usage", None)
        try:
            u = usage() if callable(usage) else usage
            for k in ("requests", "input_tokens", "output_tokens"):
                v = getattr(u, k, None)
                if isinstance(v, int) and not isinstance(v, bool):
                    meta[k] = v
        except Exception:                                   # usage is optional detail, never fatal
            pass
        return Answer(values, conf, self.name, meta)

    def answer_input(self, text: str, task_context: str) -> Answer:
        state, clipped = input_state(text, task_context)
        return self._run("input", state, clipped, InputQuestions, INPUT_FIELDS)

    def answer_action(self, task: str, tool_name: str, tool_args: Mapping[str, Any], context: str) -> Answer:
        state, clipped = action_state(task, tool_name, tool_args, context)
        return self._run("action", state, clipped, ActionQuestions, ACTION_FIELDS)
