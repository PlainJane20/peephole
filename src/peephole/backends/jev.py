"""JevBackend: TypeSafe's Jev through Pydantic AI. BUILT, OFFLINE-TESTED, NOT RUN LIVE.

`Agent(TypeSafeModel('jev-latest'), output_type=<questions model>, instructions=<policy>)`. Jev answers typed
questions about a text with a confidence each, rather than writing text; every field of the output type is one
question, so a single request answers all of them. The decision POLICY IS SPELLED OUT in the instructions and in
the field descriptions (edge-sentinel's finding: without it Jev guesses with near-uniform probabilities).

Needs `pip install -e '.[jev]'` and TYPESAFE_API_KEY in the environment. Per-field confidence is read from
`result.response.provider_details` defensively (see `base.extract_confidences`).
"""
from __future__ import annotations

from typing import Any, Mapping, Optional

from .pai import PydanticAIBackend, _need_pydantic_ai

DEFAULT_MODEL = "jev-latest"


class JevBackend(PydanticAIBackend):
    name = "jev"
    reports_confidence = True
    deterministic = False
    _extra = "jev"

    def __init__(self, model_name: str = DEFAULT_MODEL, agents: Optional[Mapping[str, Any]] = None) -> None:
        super().__init__(agents)
        self.model_name = model_name

    def _build(self, instructions: str, output_type: type) -> Any:  # pragma: no cover - needs the live SDK
        _need_pydantic_ai("jev")
        from pydantic_ai import Agent
        from pydantic_ai.models.typesafe import TypeSafeModel

        return Agent(TypeSafeModel(self.model_name), output_type=output_type, instructions=instructions,
                     retries=0)
