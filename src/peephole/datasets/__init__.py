"""Datasets: JSONL files shipped with the package. All synthetic; written by one author (see THREAT_MODEL).

input_whetstone.jsonl  127 rows COPIED from agent-whetstone: 55 attacks (11 families) + 72 benign (36 hard); split dev
input_new.jsonl        138 rows hand-written for Peephole: 70 injections in 7 NEW families + 68 hard-benign; split heldout
actions.jsonl          270 hand-written (task, tool call, context) cases labelled allow / ask / deny

`split`: `dev` = families the rules were written for (Whetstone's) or ordinary action families; `heldout` = families
the rules were never written for. Report both; the held-out numbers are the ones allowed to disappoint.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional

HERE = Path(__file__).resolve().parent
INPUT_FILES = ("input_whetstone.jsonl", "input_new.jsonl")
ACTION_FILE = "actions.jsonl"


@dataclass(frozen=True)
class InputExample:
    id: str
    kind: str          # injection | benign-routine | benign-hard
    family: str
    label: str         # injection | benign
    split: str         # dev | heldout
    text: str
    context: str
    provenance: str


@dataclass(frozen=True)
class ActionExample:
    id: str
    kind: str          # consistent | injected-deviation | borderline-ambiguous | over-broad | sensitive-read | benign-unusual
    family: str
    label: str         # allow | ask | deny
    split: str
    task: str
    tool_name: str
    tool_args: Dict[str, Any] = field(compare=False)
    context: str = ""
    ambiguous: bool = False
    provenance: str = ""


def _rows(name: str) -> List[dict]:
    return [json.loads(line) for line in (HERE / name).read_text(encoding="utf-8").splitlines() if line.strip()]


def load_input_examples(split: Optional[str] = None) -> List[InputExample]:
    out = []
    for f in INPUT_FILES:
        for r in _rows(f):
            if split is None or r["split"] == split:
                out.append(InputExample(r["id"], r["kind"], r["family"], r["label"], r["split"], r["text"],
                                        r["context"], r["provenance"]))
    return out


def load_action_examples(split: Optional[str] = None) -> List[ActionExample]:
    out = []
    for r in _rows(ACTION_FILE):
        if split is None or r["split"] == split:
            out.append(ActionExample(r["id"], r["kind"], r["family"], r["label"], r["split"], r["task"],
                                     r["tool_name"], r["tool_args"], r["context"], bool(r["ambiguous"]),
                                     r["provenance"]))
    return out


# Action cases whose label is arguable (a second reviewer could reasonably disagree). Reported separately.
AMBIGUOUS_IDS: FrozenSet[str] = frozenset(r["id"] for r in _rows(ACTION_FILE) if r["ambiguous"])
