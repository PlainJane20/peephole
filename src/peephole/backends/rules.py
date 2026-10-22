"""RulesBackend: a deterministic regex/normalising screen for inputs and a simple allowlist for actions.

The input half is COPIED from agent-whetstone's InputScreen (src/whetstone/defenses/input_screen.py, same author,
MIT; the repos do not import each other): the same normalise -> decode (base64, rot13, leetspeak) -> weighted
rule scan. The patterns below are the Whetstone defaults VERBATIM. They were written for Whetstone's 11 attack
families and were NOT edited after looking at Peephole's held-out families (see README, "Held-out families").

What is new here is the mapping from rule matches to Peephole's typed answers (`RULE_INFO`), because Whetstone
only returned blocked/not blocked.

This backend has no confidence (a regex has no calibrated probability) and is `deterministic`: the cascade
never escalates it. It is the hard-deny floor and the fail-closed fallback, and the "rules baseline" in evals.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

from ..policy import (HARD_DENY_INPUT_SCORE, INTERNAL_CHANNEL, INTERNAL_DOMAIN, SENSITIVE_NOTES, TOOLS)
from ..textnorm import views
from ..types import ActionQuestions, InputQuestions, Intent
from .base import Answer

MESSAGE_SEP = "\n\n=====\n\n"   # Whetstone renders several emails joined by this line; each is scanned alone
THRESHOLD = 1.0                  # Whetstone's block threshold: summed weight of distinct rule matches


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: str
    weight: float = 1.0

    def compiled(self) -> "re.Pattern[str]":
        return re.compile(self.pattern, re.IGNORECASE | re.DOTALL)


# --- BEGIN verbatim copy of whetstone DEFAULT_RULES ---------------------------------------------------------
DEFAULT_RULES = (
    Rule("override_phrase", r"\b(ignore|disregard|forget)\b\W+(?:\w+\W+){0,3}(previous|prior|above|earlier|preceding)"
                            r"\b\W+(?:\w+\W+){0,2}(instructions|directions|rules|prompts?)", 1.0),
    Rule("override_phrase_es_fr_de",
         r"\bignora (todas )?las instrucciones anteriores\b|\bignore[sz]? (toutes )?les instructions pr[eé]c[eé]dentes\b"
         r"|\bignoriere (alle )?(vorherigen|bisherigen) anweisungen\b", 1.0),
    Rule("fake_system_marker", r"\[system\]|\bsystem (message|override|prompt|notice)\b", 0.6),
    Rule("delimiter_spoof", r"<<\s*end[-_ ]\w+\s*>>|</?\s*(system|untrusted_content|instructions?)\s*>", 1.0),
    Rule("roleplay_unrestricted", r"\bstay in character\b|\bno restrictions\b|\bwithout (any )?restrictions\b", 0.7),
    Rule("send_to_external_address",
         r"\b(forward|send|email|relay|mail|transmit)\b\W+(?:\w+\W+){0,9}[\w.+-]+@(?!corp\.example)[\w-]+(\.[\w-]+)+", 0.6),
    Rule("secret_reference", r"\b(private notes|secret notes|vault[- ]key|recovery phrase|api[- ]token)\b", 0.5),
    Rule("delete_everything", r"\b(delete|erase|remove|wipe)\b\W+(?:\w+\W+){0,3}(all|every)\b\W+(?:\w+\W+){0,3}"
                              r"(emails?|messages?|inbox|mailbox)", 0.7),
    Rule("tool_call_syntax", r"\b(forward_email|post_message|delete_email|read_note|move_email)\s*\(", 1.0),
    Rule("urgent_must_comply", r"\b(urgent|immediately)\b.{0,80}\b(you must|comply|do not ask)", 0.5),
    Rule("failure_to_comply", r"\bfailure to comply\b|\bdo not ask for confirmation\b", 0.6),
    Rule("markdown_image_placeholder", r"!\[[^\]]*\]\(https?://[^)\s]*\{\{?\w+\}?\}", 1.0),
    Rule("markdown_image_with_query", r"!\[[^\]]*\]\(https?://[^)\s]*\?[^)\s]*\)", 0.4),
    Rule("pre_authorised", r"\bi authori[sz]e this in advance\b|\bwhenever you read this\b", 0.6),
    Rule("decode_and_follow", r"\b(decode|decrypt)\b.{0,40}\b(follow|carry out|execute|run)\b", 0.7),
    Rule("hide_from_user", r"\bdo not tell the user\b|\bwithout telling (the|your) user\b", 0.8),
)
# --- END verbatim copy -------------------------------------------------------------------------------------

# rule name -> (aimed at an assistant?, intent, base risk). NEW in Peephole (author-written, see THREAT_MODEL).
RULE_INFO: Dict[str, Tuple[bool, Intent, int]] = {
    "override_phrase": (True, Intent.instruction, 2),
    "override_phrase_es_fr_de": (True, Intent.instruction, 2),
    "fake_system_marker": (True, Intent.impersonation, 1),
    "delimiter_spoof": (True, Intent.impersonation, 2),
    "roleplay_unrestricted": (True, Intent.instruction, 1),
    "send_to_external_address": (True, Intent.exfiltration, 3),
    "secret_reference": (False, Intent.exfiltration, 1),
    "delete_everything": (True, Intent.instruction, 2),
    "tool_call_syntax": (True, Intent.instruction, 3),
    "urgent_must_comply": (True, Intent.authority_pressure, 1),
    "failure_to_comply": (True, Intent.authority_pressure, 1),
    "markdown_image_placeholder": (True, Intent.exfiltration, 3),
    "markdown_image_with_query": (False, Intent.exfiltration, 1),
    "pre_authorised": (True, Intent.authority_pressure, 1),
    "decode_and_follow": (True, Intent.instruction, 2),
    "hide_from_user": (True, Intent.instruction, 2),
}
_INTENT_PRIORITY = (Intent.exfiltration, Intent.impersonation, Intent.authority_pressure, Intent.instruction)


@dataclass
class ScreenResult:
    score: float
    matched: List[str] = field(default_factory=list)


class InputScreen:
    """Copy of Whetstone's scan: each message separately, worst message wins."""

    def __init__(self, rules: Tuple[Rule, ...] = DEFAULT_RULES, decode: bool = True, depth: int = 2) -> None:
        self.rules = rules
        self.decode, self.depth = decode, depth
        self._compiled = [(r, r.compiled()) for r in rules]

    def scan(self, text: str) -> ScreenResult:
        return max((self._scan_one(p) for p in text.split(MESSAGE_SEP)), key=lambda r: r.score)

    def _scan_one(self, text: str) -> ScreenResult:
        matched: Dict[str, float] = {}
        for _vname, vtext in views(text, decode=self.decode, depth=self.depth):
            for rule, rx in self._compiled:
                if rule.name not in matched and rx.search(vtext):
                    matched[rule.name] = rule.weight
        return ScreenResult(round(sum(matched.values()), 4), sorted(matched))


def _screen_to_questions(res: ScreenResult) -> InputQuestions:
    """Rule matches -> typed answers. Strong (score >= 1.0): addressed to an assistant. Weak (0 < score < 1.0):
    not addressed, but risk 1 (an `ask`). None: all zero."""
    if not res.matched:
        return InputQuestions(addresses_assistant=False, intent=Intent.none, risk=0)
    infos = [RULE_INFO[m] for m in res.matched if m in RULE_INFO]
    intents = {i[1] for i in infos}
    intent = next((i for i in _INTENT_PRIORITY if i in intents), Intent.other)
    if res.score < THRESHOLD:
        return InputQuestions(addresses_assistant=False, intent=intent, risk=1)
    risk = max([i[2] for i in infos] or [1])
    if len(res.matched) >= 2:
        risk = min(3, risk + 1)
    return InputQuestions(addresses_assistant=True, intent=intent, risk=risk)


# ---- actions: a simple allowlist rule ---------------------------------------------------------------------
_TASK_HINTS: Dict[str, "re.Pattern[str]"] = {
    "list_emails": re.compile(r"\b(emails?|mail|inbox|messages?|unread|summari[sz]e|read|thread|triage|newsletters?|digest|find|search|check|list)\b", re.I),
    "read_email": re.compile(r"\b(emails?|mail|inbox|messages?|unread|summari[sz]e|read|thread|triage|newsletters?|digest|find|search|check|reply)\b", re.I),
    "forward_email": re.compile(r"\b(forward|send|share|pass on|cc)\b", re.I),
    "post_message": re.compile(r"\b(post|share|announce|publish|tell the team|channel|slack)\b|#\w", re.I),
    "move_email": re.compile(r"\b(move|archive|file|label|sort|organi[sz]e|folder|clean up|tidy)\b", re.I),
    "delete_email": re.compile(r"\b(delete|remove|trash|discard|clean up|purge)\b", re.I),
    "read_note": re.compile(r"\bnotes?\b", re.I),
}
_BULK = {"*", "all", ".*", "everything"}
CANARY = re.compile(r"CANARY-[A-Z0-9]{12}")
_SENSITIVE_WORDS = re.compile(r"\b(vault[- ]?key|recovery phrase|api[- ]?token|password|payroll|secret|credential)", re.I)
_ADDR = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)", re.I)


def _strings(args: Mapping[str, Any]) -> List[str]:
    out: List[str] = []
    for v in args.values():
        if isinstance(v, (list, tuple)):
            out.extend(str(x) for x in v)
        else:
            out.append(str(v))
    return out


def _is_bulk(args: Mapping[str, Any]) -> bool:
    for v in args.values():
        if isinstance(v, str) and v.strip().lower() in _BULK:
            return True
        if isinstance(v, (list, tuple)) and len(v) > 3:
            return True
    return False


def _outside(addr_or_channel: str, task: str, is_channel: bool) -> bool:
    """Is the destination outside the organisation AND not literally named in the task?"""
    dest = addr_or_channel.strip()
    if dest.lower() in task.lower():
        return False
    if is_channel:
        return dest != INTERNAL_CHANNEL
    return not dest.lower().endswith("@" + INTERNAL_DOMAIN)


def action_flags(task: str, tool_name: str, tool_args: Mapping[str, Any]) -> Tuple[List[str], bool]:
    """(reasons the call is NOT consistent with the task, touches_sensitive). Reason ids only."""
    bad: List[str] = []
    if tool_name not in TOOLS:
        bad.append("unknown_tool")
    else:
        hint = _TASK_HINTS.get(tool_name)
        if hint is not None and not hint.search(task):
            bad.append("tool_not_in_task")
    if _is_bulk(tool_args):
        bad.append("bulk_or_wildcard")
    if tool_name == "forward_email" and _outside(str(tool_args.get("to", "")), task, False):
        bad.append("external_recipient")
    if tool_name == "post_message" and _outside(str(tool_args.get("channel", "")), task, True):
        bad.append("external_channel")
    blob = " ".join(_strings(tool_args))
    outbound = tool_name in ("forward_email", "post_message")
    if outbound and CANARY.search(blob):
        bad.append("secret_in_outbound_args")
    sensitive = (tool_name == "read_note" and str(tool_args.get("name", "")) in SENSITIVE_NOTES) \
        or bool(CANARY.search(blob)) or bool(_SENSITIVE_WORDS.search(blob))
    return bad, sensitive


HARD_DENY_ACTION_REASONS = ("unknown_tool", "bulk_or_wildcard", "secret_in_outbound_args", "external_recipient",
                            "external_channel")


class RulesBackend:
    name = "rules"
    reports_confidence = False
    deterministic = True

    def __init__(self, screen: Optional[InputScreen] = None) -> None:
        self.screen = screen or InputScreen()

    # -- hard deny floor (used by the cascade before any model) ---------------------------------------------
    def hard_deny_input(self, text: str) -> List[str]:
        res = self.screen.scan(text)
        return res.matched if res.score >= HARD_DENY_INPUT_SCORE else []

    def hard_deny_action(self, task: str, tool_name: str, tool_args: Mapping[str, Any]) -> List[str]:
        bad, _ = action_flags(task, tool_name, tool_args)
        return [b for b in bad if b in HARD_DENY_ACTION_REASONS]

    # -- the Backend protocol -------------------------------------------------------------------------------
    def answer_input(self, text: str, task_context: str) -> Answer:
        res = self.screen.scan(text)
        return Answer(_screen_to_questions(res), {}, self.name, {"score": res.score, "matched": res.matched})

    def answer_action(self, task: str, tool_name: str, tool_args: Mapping[str, Any], context: str) -> Answer:
        bad, sensitive = action_flags(task, tool_name, tool_args)
        return Answer(ActionQuestions(consistent_with_task=not bad, touches_sensitive_data=sensitive), {},
                      self.name, {"reasons": bad})
