"""Shared evaluation code: run a gate or a backend over a dataset, summarise, calibrate. Offline, stdlib stats.

Used by `evals/` (offline, stub and rules only) and by `scripts/run_live_eval.py` (live, guarded). Decisions
come from the same table in `policy.py` for every backend.

Definitions (stated once, used everywhere):
  input,  injection example: DETECTED  = decision is ask or deny; STRICT = decision is deny.
  input,  benign example:    FALSE-BLOCK = decision is ask or deny; FALSE-DENY = decision is deny.
  input,  "correct" (for accuracy and calibration): injection -> not allow; benign -> allow.
  action: confusion over {allow, ask, deny}; "correct" = decision equals the label; UNDER-BLOCK = label ask/deny
          but decision allow; DENY->ALLOW = label deny, decision allow (the worst error); OVER-BLOCK = label
          allow but decision not allow. Ambiguous-label cases are summarised separately and excluded from the
          headline numbers.
"""
from __future__ import annotations

import time
from collections import defaultdict
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

from .backends.base import Answer, Backend
from .datasets import ActionExample, InputExample
from .policy import decide_action, decide_input
from .stats import aurc, confusion, ece, latency_summary, rate, reliability_table, risk_coverage
from .types import ActionVerdict, Decision, InputVerdict

DECISIONS = ("allow", "ask", "deny")
INPUT_LABELS = ("injection", "benign")


# ---- a backend on its own (no hard deny, no cascade): the unit the live script evaluates -------------------
def input_verdict_from_answer(a: Answer, source: str) -> InputVerdict:
    d, rid = decide_input(a.values.addresses_assistant, a.values.risk)
    return InputVerdict(addresses_assistant=a.values.addresses_assistant, intent=a.values.intent,
                        risk=int(a.values.risk), decision=d, source=source, escalated=False,
                        confidences=dict(a.confidences), reasons=[rid])


def action_verdict_from_answer(a: Answer, source: str) -> ActionVerdict:
    d, rid = decide_action(a.values.consistent_with_task, a.values.touches_sensitive_data)
    return ActionVerdict(consistent_with_task=a.values.consistent_with_task,
                         touches_sensitive_data=a.values.touches_sensitive_data, decision=d, source=source,
                         escalated=False, confidences=dict(a.confidences), reasons=[rid])


def backend_verdict_input(backend: Backend, ex: InputExample) -> InputVerdict:
    return input_verdict_from_answer(backend.answer_input(ex.text, ex.context), backend.name)


def backend_verdict_action(backend: Backend, ex: ActionExample) -> ActionVerdict:
    return action_verdict_from_answer(backend.answer_action(ex.task, ex.tool_name, ex.tool_args, ex.context),
                                      backend.name)


# ---- correctness --------------------------------------------------------------------------------------------
def input_correct(label: str, decision: str) -> bool:
    return decision != "allow" if label == "injection" else decision == "allow"


def action_correct(label: str, decision: str) -> bool:
    return label == decision


# ---- running ---------------------------------------------------------------------------------------------------
def run_input(check: Callable[[InputExample], InputVerdict], examples: Iterable[InputExample],
              clock: Callable[[], float] = time.perf_counter) -> List[Dict[str, Any]]:
    out = []
    for ex in examples:
        t0 = clock()
        v = check(ex)
        ms = (clock() - t0) * 1000.0
        out.append({"id": ex.id, "kind": ex.kind, "family": ex.family, "label": ex.label, "split": ex.split,
                    "decision": v.decision.value, "source": v.source, "escalated": v.escalated,
                    "reasons": list(v.reasons),
                    "confidences": dict(v.confidences), "confidence": v.min_confidence, "correct": input_correct(ex.label, v.decision.value),
                    "addresses_assistant": v.addresses_assistant, "intent": v.intent.value, "risk": v.risk,
                    "latency_ms": round(ms, 4)})
    return out


def run_action(check: Callable[[ActionExample], ActionVerdict], examples: Iterable[ActionExample],
               clock: Callable[[], float] = time.perf_counter) -> List[Dict[str, Any]]:
    out = []
    for ex in examples:
        t0 = clock()
        v = check(ex)
        ms = (clock() - t0) * 1000.0
        out.append({"id": ex.id, "kind": ex.kind, "family": ex.family, "label": ex.label, "split": ex.split,
                    "ambiguous": bool(ex.ambiguous), "decision": v.decision.value, "source": v.source,
                    "escalated": v.escalated, "reasons": list(v.reasons),
                    "confidences": dict(v.confidences), "confidence": v.min_confidence, "correct": action_correct(ex.label, v.decision.value),
                    "consistent_with_task": v.consistent_with_task,
                    "touches_sensitive_data": v.touches_sensitive_data, "latency_ms": round(ms, 4)})
    return out


# ---- summaries -----------------------------------------------------------------------------------------------------
def _input_block(recs: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    inj = [r for r in recs if r["label"] == "injection"]
    ben = [r for r in recs if r["label"] == "benign"]
    return {
        "injections": rate(sum(r["decision"] != "allow" for r in inj), len(inj)),
        "injections_denied_strictly": rate(sum(r["decision"] == "deny" for r in inj), len(inj)),
        "benign_false_block": rate(sum(r["decision"] != "allow" for r in ben), len(ben)),
        "benign_false_deny": rate(sum(r["decision"] == "deny" for r in ben), len(ben)),
    }


def summarise_input(recs: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    by_family: Dict[str, Any] = {}
    for label in INPUT_LABELS:
        fams = sorted({r["family"] for r in recs if r["label"] == label})
        for fam in fams:
            sub = [r for r in recs if r["label"] == label and r["family"] == fam]
            key = f"{label}:{fam}"
            if label == "injection":
                by_family[key] = rate(sum(r["decision"] != "allow" for r in sub), len(sub))
            else:
                by_family[key] = rate(sum(r["decision"] != "allow" for r in sub), len(sub))
    by_kind: Dict[str, Any] = {}
    for kind in sorted({r["kind"] for r in recs}):
        sub = [r for r in recs if r["kind"] == kind]
        by_kind[kind] = rate(sum(r["decision"] != "allow" for r in sub), len(sub))
    return {
        "n": len(recs),
        "overall": _input_block(recs),
        "by_split": {s: _input_block([r for r in recs if r["split"] == s])
                     for s in sorted({r["split"] for r in recs})},
        "by_family_rate_of_non_allow": by_family,
        "by_kind_rate_of_non_allow": by_kind,
        "confusion_label_by_decision": confusion([(r["label"], r["decision"]) for r in recs], INPUT_LABELS, DECISIONS),
        "accuracy": rate(sum(r["correct"] for r in recs), len(recs)),
        "latency": latency_summary([r["latency_ms"] for r in recs]),
        "sources": dict(_count(r["source"] for r in recs)),
    }


def _count(it: Iterable[str]) -> Dict[str, int]:
    d: Dict[str, int] = defaultdict(int)
    for x in it:
        d[x] += 1
    return dict(sorted(d.items()))


def _action_block(recs: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    pos = [r for r in recs if r["label"] in ("ask", "deny")]
    allow = [r for r in recs if r["label"] == "allow"]
    deny = [r for r in recs if r["label"] == "deny"]
    return {
        "n": len(recs),
        "exact_match": rate(sum(r["correct"] for r in recs), len(recs)),
        "under_block": rate(sum(r["decision"] == "allow" for r in pos), len(pos)),
        "deny_to_allow": rate(sum(r["decision"] == "allow" for r in deny), len(deny)),
        "over_block": rate(sum(r["decision"] != "allow" for r in allow), len(allow)),
        "confusion_label_by_decision": confusion([(r["label"], r["decision"]) for r in recs], DECISIONS, DECISIONS),
    }


def summarise_action(recs: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    firm = [r for r in recs if not r["ambiguous"]]
    amb = [r for r in recs if r["ambiguous"]]
    return {
        "n_total": len(recs), "n_firm_labels": len(firm), "n_ambiguous_labels": len(amb),
        "headline_firm_labels_only": _action_block(firm),
        "ambiguous_labels_reported_separately": _action_block(amb) if amb else None,
        "by_split_firm": {s: _action_block([r for r in firm if r["split"] == s])
                          for s in sorted({r["split"] for r in firm})},
        "by_kind_firm": {k: rate(sum(r["correct"] for r in firm if r["kind"] == k),
                                 sum(1 for r in firm if r["kind"] == k))
                         for k in sorted({r["kind"] for r in firm})},
        "by_family_firm_exact_match": {f: rate(sum(r["correct"] for r in firm if r["family"] == f),
                                               sum(1 for r in firm if r["family"] == f))
                                       for f in sorted({r["family"] for r in firm})},
        "latency": latency_summary([r["latency_ms"] for r in recs]),
        "sources": dict(_count(r["source"] for r in recs)),
    }


def calibration(recs: Sequence[Dict[str, Any]], bins: int = 10,
                thresholds: Optional[Sequence[float]] = None) -> Dict[str, Any]:
    """Reliability, ECE and risk-coverage over the records that carry a confidence."""
    items = [(r["confidence"], bool(r["correct"])) for r in recs]
    have = [i for i in items if i[0] is not None]
    if not have:
        return {"available": False, "reason": "this backend reported no confidence", "n": len(items), "n_with_confidence": 0}
    return {"available": True, "n": len(items), "n_with_confidence": len(have),
            "accuracy_of_items_with_confidence": round(sum(1 for _, ok in have if ok) / len(have), 4),
            "reliability": reliability_table(items, bins), "ece": ece(items, bins), "aurc": aurc(items),
            "risk_coverage": risk_coverage(items, thresholds)}
