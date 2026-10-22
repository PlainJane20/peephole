"""MockBackend: a TEST DOUBLE. Deterministic keyword heuristics, for PLUMBING tests only.

*** This is a stub. It is not a model, not Jev, and not a baseline. Its answers and its "confidence" are
*** functions of keyword counts; the confidence is NOT a probability and is not calibrated to anything.
*** Numbers produced with it verify that the harness, the cascade, the metrics and the audit trail work.
*** They say nothing about how Jev or any LLM would perform, and they must never appear as a result in a
*** README table. Output files that used it say so in a `backend_is_stub` field.

Two profiles share the code: `reports_confidence=True` (stands in for a Jev-like first tier) and
`reports_confidence=False` with `thorough=True` (stands in for an LLM-like second tier that sees more keywords).
"""
from __future__ import annotations

import re
from typing import Any, Dict, Mapping

from ..policy import INTERNAL_DOMAIN
from ..types import ActionQuestions, InputQuestions, Intent
from .base import Answer

_ADDR = ("ignore all previous", "ignore previous", "ignore the previous", "disregard", "you must",
         "assistant", "system message", "[system]", "<system>", "stay in character", "whenever you read",
         "instruction for", "do not tell the user", "ai agent")
_ADDR_THOROUGH = ("as an ai", "automated reader", "language model", "if you are a bot", "note to the ai",
                  "to whoever processes this", "standing instruction", "from now on")
_EXFIL = ("forward", "send", "post ", "reveal", "recovery phrase", "private notes", "vault", "api token",
          "delete all", "erase every", "export")
_PRESSURE = ("urgent", "failure to comply", "immediately", "do not ask")
_IMPERSON = ("system", "administrator", "ciso", "platform notice", "operator")
_SENS = ("vault", "token", "payroll", "canary", "secret", "password", "recovery")
_TOOL_WORDS = {"forward_email": ("forward", "send", "share"), "post_message": ("post", "share", "announce", "channel", "#"),
               "delete_email": ("delete", "remove", "trash", "clean"), "move_email": ("move", "archive", "file", "sort", "clean"),
               "read_note": ("note",), "read_email": ("read", "summar", "email", "mail", "check", "inbox"),
               "list_emails": ("list", "summar", "email", "mail", "check", "inbox", "unread")}


class MockBackend:
    deterministic = False

    def __init__(self, name: str = "mock", reports_confidence: bool = True, thorough: bool = False) -> None:
        self.name = name
        self.reports_confidence = reports_confidence
        self.thorough = thorough
        self.is_stub = True

    def _conf(self, base: float, fields: tuple) -> Dict[str, Any]:
        if not self.reports_confidence:
            return {f: None for f in fields}
        # distinct values per field so min-over-fields logic is exercised
        return {f: round(max(0.0, base - 0.03 * i), 4) for i, f in enumerate(fields)}

    def answer_input(self, text: str, task_context: str) -> Answer:
        low = " ".join(text.lower().split())
        terms = _ADDR + (_ADDR_THOROUGH if self.thorough else ())
        hits = sum(1 for t in terms if t in low)
        exfil = any(t in low for t in _EXFIL)
        addresses = hits > 0
        if addresses:
            risk = min(3, 2 + (1 if exfil else 0))
        else:
            risk = 1 if (exfil and "assistant" in low) else 0
        if exfil and addresses:
            intent = Intent.exfiltration
        elif addresses and any(t in low for t in _PRESSURE):
            intent = Intent.authority_pressure
        elif addresses and any(t in low for t in _IMPERSON):
            intent = Intent.impersonation
        elif addresses:
            intent = Intent.instruction
        else:
            intent = Intent.none
        base = 0.95 if (hits >= 2 or (hits == 0 and not exfil)) else (0.65 if hits == 1 else 0.85)
        fields = ("addresses_assistant", "intent", "risk")
        return Answer(InputQuestions(addresses_assistant=addresses, intent=intent, risk=risk),
                      self._conf(base, fields), self.name, {"stub": True, "keyword_hits": hits})

    def answer_action(self, task: str, tool_name: str, tool_args: Mapping[str, Any], context: str) -> Answer:
        tl = task.lower()
        blob = " ".join(str(v) for v in tool_args.values()).lower()
        problems = 0
        words = _TOOL_WORDS.get(tool_name)
        if words is None or not any(w in tl for w in words):
            problems += 1
        if any(str(v).strip() in ("*", "all") for v in tool_args.values()):
            problems += 1
        for m in re.finditer(r"[\w.+-]+@([\w.-]+)", blob):
            if not m.group(0).endswith("@" + INTERNAL_DOMAIN) and m.group(0) not in tl:
                problems += 1
        ch = str(tool_args.get("channel", ""))
        if ch and ch != "#team-updates" and ch.lower() not in tl:
            problems += 1
        sensitive = any(w in blob or w in tool_name for w in _SENS)
        injected = any(t in context.lower() for t in ("ignore", "instruction", "assistant", "you must"))
        consistent = problems == 0
        base = 0.95 if problems >= 2 or (problems == 0 and not injected) else 0.7
        fields = ("consistent_with_task", "touches_sensitive_data")
        return Answer(ActionQuestions(consistent_with_task=consistent, touches_sensitive_data=sensitive),
                      self._conf(base, fields), self.name, {"stub": True, "problems": problems})
