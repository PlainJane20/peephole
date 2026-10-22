"""The cascade: hard deny first, then ordered backends with a confidence threshold, then fail policy.

    hard deny (deterministic)  ->  primary (default Jev)  ->  next tier (default LLM)  ->  fail policy

* A backend that `reports_confidence` (Jev) is decisive only when its confidence >= threshold. A missing
  confidence, a confidence below the threshold, or an exception all mean "unsure": escalate to the next tier.
* A backend that does not report confidence (an LLM) is decisive when reached (a terminal tier).
* A deterministic backend (rules) is always decisive and is never escalated.
* If nobody was decisive: the rules' verdict, with `allow` upgraded to `ask` under fail-CLOSED (the default).
  Fail-OPEN is an explicit opt-in that keeps the rules' verdict as it is. Never a silent `allow` from a failure.
* The decision always comes from the one mapping table in `policy.py`.
"""
from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from pydantic import BaseModel

from . import tracing
from .backends.base import Answer, Backend
from .backends.rules import RulesBackend
from .policy import (DEFAULT_FAIL_POLICY, DEFAULT_THRESHOLD, FailPolicy, apply_fail_policy, decide_action,
                     decide_input, validate_threshold)
from .types import (ACTION_FIELDS, INPUT_FIELDS, ActionQuestions, ActionVerdict, Decision, InputQuestions,
                    InputVerdict, Intent)

log = logging.getLogger("peephole.cascade")


class _Outcome:
    def __init__(self, values: BaseModel, decision: Decision, source: str, escalated: bool,
                 confidences: Dict[str, Optional[float]], reasons: List[str]) -> None:
        self.values, self.decision, self.source = values, decision, source
        self.escalated, self.confidences, self.reasons = escalated, confidences, reasons


class Cascade:
    def __init__(self, chain: Sequence[Backend] = (), rules: Optional[RulesBackend] = None,
                 threshold: float = DEFAULT_THRESHOLD,
                 fail_policy: Optional[Mapping[str, FailPolicy]] = None) -> None:
        self.chain = list(chain)
        self.rules = rules or RulesBackend()
        self.threshold = validate_threshold(threshold)
        fp = dict(DEFAULT_FAIL_POLICY)
        fp.update(fail_policy or {})
        self.fail_policy = fp

    # ---- public ------------------------------------------------------------------------------------
    def check_input(self, text: str, task_context: str = "") -> InputVerdict:
        hard = _safely(lambda: self.rules.hard_deny_input(text), [])
        o = self._run(
            "input", hard,
            ask=lambda b: b.answer_input(text, task_context),
            rules_answer=lambda: self.rules.answer_input(text, task_context),
            decide=lambda v: decide_input(v.addresses_assistant, v.risk),
            fields=INPUT_FIELDS,
            fallback=InputQuestions(addresses_assistant=True, intent=Intent.other, risk=1))
        v = o.values
        return InputVerdict(addresses_assistant=v.addresses_assistant, intent=v.intent, risk=int(v.risk),
                            decision=o.decision, source=o.source, escalated=o.escalated,
                            confidences=o.confidences, reasons=o.reasons)

    def check_action(self, task: str, tool_name: str, tool_args: Mapping[str, Any],
                     context: str = "") -> ActionVerdict:
        hard = _safely(lambda: self.rules.hard_deny_action(task, tool_name, tool_args), [])
        o = self._run(
            "action", hard,
            ask=lambda b: b.answer_action(task, tool_name, tool_args, context),
            rules_answer=lambda: self.rules.answer_action(task, tool_name, tool_args, context),
            decide=lambda v: decide_action(v.consistent_with_task, v.touches_sensitive_data),
            fields=ACTION_FIELDS,
            fallback=ActionQuestions(consistent_with_task=False, touches_sensitive_data=True))
        v = o.values
        return ActionVerdict(consistent_with_task=v.consistent_with_task,
                             touches_sensitive_data=v.touches_sensitive_data, decision=o.decision,
                             source=o.source, escalated=o.escalated, confidences=o.confidences,
                             reasons=o.reasons)

    # ---- the one generic flow ------------------------------------------------------------------------
    def _run(self, kind: str, hard: List[str], ask: Callable[[Backend], Answer],
             rules_answer: Callable[[], Answer], decide: Callable[[Any], Tuple[Decision, str]],
             fields: Tuple[str, ...], fallback: BaseModel) -> _Outcome:
        reasons: List[str] = []
        none_conf: Dict[str, Optional[float]] = {}
        rules = _safely_answer(rules_answer, fallback)

        if hard:
            reasons.extend(f"hard_deny:{h}" for h in hard)
            return _Outcome(rules.values, Decision.deny, "hard-deny", False, none_conf, reasons)

        if not self.chain:                                  # rules ARE the backend (not a failure)
            d, rid = decide(rules.values)
            if rules.source == "error":
                d = Decision.ask
                reasons.append("rules_error")
            return _Outcome(rules.values, d, "rules", False, none_conf, reasons + [rid])

        escalated = False
        last_unsure: Optional[Answer] = None
        for b in self.chain:
            with tracing.span("backend_call", backend=b.name, gate=kind) as sp:
                try:
                    ans = ask(b)
                except Exception as exc:                    # noqa: BLE001 - every failure degrades, never raises
                    cls = type(exc).__name__                # the class name only: messages can hold content
                    reasons.append(f"backend_error:{b.name}:{cls}")
                    tracing.set_attrs(sp, outcome="error", error_class=cls)
                    log.warning("backend %s failed (%s); escalating", b.name, cls)
                    escalated = True
                    continue
                conf = ans.confidence
                tracing.set_attrs(sp, confidence=conf)
                if b.reports_confidence and not b.deterministic:
                    if conf is None:
                        reasons.append(f"no_confidence:{b.name}")
                        tracing.set_attrs(sp, outcome="no_confidence")
                        escalated, last_unsure = True, ans
                        continue
                    if conf < self.threshold:
                        reasons.append(f"unsure:{b.name}")
                        tracing.set_attrs(sp, outcome="unsure")
                        escalated, last_unsure = True, ans
                        continue
                tracing.set_attrs(sp, outcome="decided")
                d, rid = decide(ans.values)
                return _Outcome(ans.values, d, b.name, escalated, dict(ans.confidences), reasons + [rid])

        # nobody was decisive: fail policy over the rules' verdict
        policy = self.fail_policy[kind]
        d_rules, rid = decide(rules.values)
        if rules.source == "error":
            d_rules = Decision.ask
            reasons.append("rules_error")
        d = apply_fail_policy(policy, d_rules)
        if d is not d_rules:
            reasons.append("fail_closed:allow_upgraded_to_ask")
        reasons.append(rid)
        src = "fail-closed" if policy is FailPolicy.closed else "fail-open"
        confs = dict(last_unsure.confidences) if last_unsure is not None else none_conf
        return _Outcome(rules.values, d, src, True, confs, reasons)


def _safely(fn: Callable[[], Any], default: Any) -> Any:
    try:
        return fn()
    except Exception:                                       # noqa: BLE001
        log.warning("deterministic layer raised; treating as no match")
        return default


def _safely_answer(fn: Callable[[], Answer], fallback: BaseModel) -> Answer:
    try:
        return fn()
    except Exception:                                       # noqa: BLE001
        log.warning("rules backend raised; using the conservative fallback")
        return Answer(fallback, {}, "error")
