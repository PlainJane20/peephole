"""Peephole: look before you open the door. A typed, calibrated semantic gate for agent inputs and actions."""
from __future__ import annotations

from .audit import AuditLog
from .cascade import Cascade
from .gates import ActionGate, InputGate
from .policy import DEFAULT_THRESHOLD, FailPolicy
from .types import (ActionQuestions, ActionVerdict, Decision, InputQuestions, InputVerdict, Intent)

__version__ = "0.1.0"
__all__ = ["ActionGate", "ActionQuestions", "ActionVerdict", "AuditLog", "Cascade", "DEFAULT_THRESHOLD", "Decision",
           "FailPolicy", "InputGate", "InputQuestions", "InputVerdict", "Intent"]
