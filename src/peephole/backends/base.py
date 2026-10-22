"""The backend Protocol, the `Answer` type, and defensive confidence extraction.

A backend answers the typed questions for ONE input (or ONE proposed action). It never decides allow/ask/deny:
the mapping from typed fields to a decision lives in `policy.py`, and the escalation logic in `cascade.py`.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Protocol, Sequence, Tuple, runtime_checkable

from pydantic import BaseModel

from ..policy import MAX_TEXT_CHARS


@dataclass
class Answer:
    values: BaseModel                                  # InputQuestions or ActionQuestions
    confidences: Dict[str, Optional[float]]            # per field; None = the backend gave no number
    source: str                                        # the backend's name
    meta: Dict[str, Any] = field(default_factory=dict)  # identifiers and numbers only (requests, tokens)

    @property
    def confidence(self) -> Optional[float]:
        """The cascade's single number: the minimum over fields; None when nothing exists (counts as unsure)."""
        vals = [v for v in self.confidences.values() if v is not None]
        return min(vals) if vals else None


@runtime_checkable
class Backend(Protocol):
    name: str
    reports_confidence: bool      # True: the cascade needs confidence >= threshold, missing counts as unsure
    deterministic: bool           # True: no model, same input -> same answer (rules); never escalated

    def answer_input(self, text: str, task_context: str) -> Answer: ...

    def answer_action(self, task: str, tool_name: str, tool_args: Mapping[str, Any], context: str) -> Answer: ...


def clip(text: str, limit: int = MAX_TEXT_CHARS) -> Tuple[str, bool]:
    text = text if isinstance(text, str) else str(text)
    return (text, False) if len(text) <= limit else (text[:limit], True)


def input_state(text: str, task_context: str) -> Tuple[str, bool]:
    """The JSON the model judges. Clipped to bound tokens; the flag says whether it was clipped."""
    body, clipped = clip(text)
    task, _ = clip(task_context, 500)
    return json.dumps({"task": task, "untrusted_text": body}, ensure_ascii=False), clipped


def action_state(task: str, tool_name: str, tool_args: Mapping[str, Any], context: str) -> Tuple[str, bool]:
    ctx, clipped = clip(context)
    t, _ = clip(task, 500)
    return json.dumps({"task": t, "tool_name": tool_name, "tool_args": dict(tool_args), "context": ctx},
                      ensure_ascii=False, default=str), clipped


def _num(v: Any) -> Optional[float]:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    f = float(v)
    return f if (not math.isnan(f) and 0.0 <= f <= 1.0) else None


def extract_confidences(result: Any, fields: Sequence[str]) -> Dict[str, Optional[float]]:
    """Per-field confidence from `result.response.provider_details`, read defensively.

    Verified once, live, for a SINGLE question: {'confidence': {'response': 1.0},
    'probabilities': {'response': {...}}}. For several fields the installed pydantic-ai documents
    `provider_details['confidence']` keyed by field name, but that has NOT been seen live, so this accepts:
      * a dict keyed by field name (the documented shape),
      * a dict with only a 'response' key, or any other keys,
      * a bare number.
    A field with no number of its own gets the MINIMUM of the numbers that exist. When nothing usable exists
    every field is None, which the cascade treats as unsure. Out-of-range, NaN and boolean values are ignored.
    """
    out: Dict[str, Optional[float]] = {f: None for f in fields}
    details = getattr(getattr(result, "response", None), "provider_details", None)
    if not isinstance(details, Mapping):
        return out
    c = details.get("confidence")
    if isinstance(c, Mapping):
        found = {k: n for k, n in ((k, _num(v)) for k, v in c.items() if isinstance(k, str)) if n is not None}
        fill = min(found.values()) if found else None
        for f in fields:
            out[f] = found.get(f, fill)
    else:
        n = _num(c)
        if n is not None:
            out = {f: n for f in fields}
    return out
