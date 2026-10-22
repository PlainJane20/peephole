"""OpenTelemetry spans. A no-op unless an SDK TracerProvider is configured (opentelemetry-api only at runtime).

PRIVACY BY CONSTRUCTION: the text a gate judges and the arguments of a tool call must never reach a span. This
module enforces it instead of hoping callers behave: only attribute KEYS in `ALLOWED_KEYS` are set, string values
must match a short identifier pattern (enums, rule ids, backend names, exception CLASS names), and everything
else (including any longer or free-form string) is dropped. Numbers and booleans pass.
"""
from __future__ import annotations

import re
from contextlib import contextmanager
from typing import Any, Optional

from opentelemetry import trace

_provider: Optional[Any] = None

ALLOWED_KEYS = frozenset({
    "gate", "decision", "source", "escalated", "threshold", "min_confidence", "backends_tried", "fail_policy",
    "backend", "outcome", "error_class", "confidence", "addresses_assistant", "intent", "risk",
    "consistent_with_task", "touches_sensitive_data", "tool", "text_len", "hard_deny", "policy_version",
    "rule",
})
_SAFE_STR = re.compile(r"^[A-Za-z0-9_.:\-]{1,48}$")


def configure(provider: Optional[Any]) -> None:
    """Use `provider` for this package's spans (None restores the global default)."""
    global _provider
    _provider = provider


def _tracer():
    if _provider is not None:
        return trace.get_tracer("peephole", tracer_provider=_provider)
    return trace.get_tracer("peephole")


def _clean(v: Any) -> Any:
    """Return a span-safe value or None to drop it."""
    if isinstance(v, bool) or isinstance(v, (int, float)):
        return v
    if hasattr(v, "value") and isinstance(getattr(v, "value"), str):      # an Enum member
        v = v.value
    if isinstance(v, str) and _SAFE_STR.match(v):
        return v
    return None


def set_attrs(s: Any, **attrs: Any) -> None:
    for k, v in attrs.items():
        if k not in ALLOWED_KEYS or v is None:
            continue
        c = _clean(v)
        if c is not None:
            s.set_attribute(k, c)


@contextmanager
def span(name: str, **attrs: Any):
    with _tracer().start_as_current_span(f"peephole.{name}") as s:
        set_attrs(s, **attrs)
        yield s
