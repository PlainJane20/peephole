"""LLMBackend: the same typed questions and the same policy text through a Claude model. BUILT, NOT RUN LIVE.

`Agent('anthropic:claude-haiku-4-5-20251001', output_type=<questions model>, instructions=<policy>)`.
An LLM returns no calibrated confidence, so `reports_confidence` is False and every confidence is None. In the
cascade it is therefore a terminal tier: when reached, its answer is accepted. Needs `pip install -e '.[llm]'`
and ANTHROPIC_API_KEY in the environment.
"""
from __future__ import annotations

from typing import Any, Mapping, Optional

from .pai import PydanticAIBackend, _need_pydantic_ai

DEFAULT_MODEL = "anthropic:claude-haiku-4-5-20251001"


class LLMBackend(PydanticAIBackend):
    name = "llm"
    reports_confidence = False
    deterministic = False
    _extra = "llm"

    def __init__(self, model: str = DEFAULT_MODEL, agents: Optional[Mapping[str, Any]] = None) -> None:
        super().__init__(agents)
        self.model = model

    def _build(self, instructions: str, output_type: type) -> Any:  # pragma: no cover - needs the live SDK
        _need_pydantic_ai("llm")
        from pydantic_ai import Agent

        return Agent(self.model, output_type=output_type, instructions=instructions, retries=0,
                     model_settings={"temperature": 0.0, "max_tokens": 300})
