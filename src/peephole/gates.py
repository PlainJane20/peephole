"""InputGate and ActionGate: a Cascade plus an audit record and a span per decision."""
from __future__ import annotations

from typing import Any, Mapping, Optional

from . import tracing
from .audit import AuditLog, fingerprint
from .cascade import Cascade
from .policy import POLICY_VERSION, TOOLS
from .types import ActionVerdict, InputVerdict


def _safe_tool(name: str) -> str:
    """A tool name an agent invented can carry anything: only known tool names are recorded as-is."""
    return name if name in TOOLS else "other"


class _Gate:
    kind = ""

    def __init__(self, cascade: Optional[Cascade] = None, audit: Optional[AuditLog] = None) -> None:
        self.cascade = cascade or Cascade()
        self.audit = audit

    def _record(self, verdict: Any, extra: dict) -> None:
        if self.audit is None:
            return
        data = {"gate": self.kind, "policy_version": POLICY_VERSION, "threshold": self.cascade.threshold,
                "fail_policy": self.cascade.fail_policy[self.kind].value,
                "decision": verdict.decision.value, "source": verdict.source, "escalated": verdict.escalated,
                "confidences": verdict.confidences, "reasons": verdict.reasons}
        data.update(extra)
        self.audit.append(f"{self.kind}_gate", data)


class InputGate(_Gate):
    kind = "input"

    def check(self, text: str, task_context: str = "") -> InputVerdict:
        with tracing.span("input_gate", gate="input", text_len=len(text), threshold=self.cascade.threshold,
                          policy_version=POLICY_VERSION) as sp:
            v = self.cascade.check_input(text, task_context)
            tracing.set_attrs(sp, decision=v.decision, source=v.source, escalated=v.escalated,
                              min_confidence=v.min_confidence, addresses_assistant=v.addresses_assistant,
                              intent=v.intent, risk=v.risk, backends_tried=len(self.cascade.chain),
                              hard_deny=v.source == "hard-deny")
        self._record(v, {"text_sha256": fingerprint(text), "text_len": len(text),
                         "addresses_assistant": v.addresses_assistant, "intent": v.intent.value, "risk": v.risk})
        return v


class ActionGate(_Gate):
    kind = "action"

    def check(self, task: str, tool_name: str, tool_args: Mapping[str, Any], context: str = "") -> ActionVerdict:
        tool = _safe_tool(tool_name)
        with tracing.span("action_gate", gate="action", tool=tool, threshold=self.cascade.threshold,
                          policy_version=POLICY_VERSION) as sp:
            v = self.cascade.check_action(task, tool_name, tool_args, context)
            tracing.set_attrs(sp, decision=v.decision, source=v.source, escalated=v.escalated,
                              min_confidence=v.min_confidence, consistent_with_task=v.consistent_with_task,
                              touches_sensitive_data=v.touches_sensitive_data,
                              backends_tried=len(self.cascade.chain), hard_deny=v.source == "hard-deny")
        self._record(v, {"tool": tool, "args_sha256": fingerprint(dict(tool_args)),
                         "task_sha256": fingerprint(task),
                         "consistent_with_task": v.consistent_with_task,
                         "touches_sensitive_data": v.touches_sensitive_data})
        return v
