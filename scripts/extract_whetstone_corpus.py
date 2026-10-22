"""ONE-TIME extraction of Whetstone's 55 attacks and 72 benign messages into Peephole's JSONL format.

Needs a sibling checkout of agent-whetstone (same author). It is how `src/peephole/datasets/input_whetstone.jsonl`
was produced; the result is committed, nothing imports Whetstone at run time, and CI does not run this script.

    python scripts/extract_whetstone_corpus.py ../agent-whetstone
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

root = Path(sys.argv[1] if len(sys.argv) > 1 else "../agent-whetstone").resolve()
sys.path.insert(0, str(root / "src"))
from whetstone.attacks.corpus import base_corpus          # noqa: E402
from whetstone.benign import benign_corpus, category_of, is_hard   # noqa: E402
from whetstone.models import DEFAULT_TASK                  # noqa: E402

rows = []
for a in base_corpus():
    rows.append({"id": a.id, "kind": "injection", "family": a.technique, "label": "injection", "split": "dev",
                 "goal": a.goal, "text": a.untrusted_text(), "context": DEFAULT_TASK,
                 "provenance": "copied from agent-whetstone: attacks/corpus.py base_corpus() "
                               "(one author wrote both repos; generic benign payloads, .example destinations)"})
for e in benign_corpus():
    rows.append({"id": e.id, "kind": "benign-hard" if is_hard(e.id) else "benign-routine",
                 "family": category_of(e.id), "label": "benign", "split": "dev", "goal": None,
                 "text": e.render(), "context": DEFAULT_TASK,
                 "provenance": "copied from agent-whetstone: benign.py benign_corpus() (hand-written, synthetic)"})
out = Path(__file__).resolve().parents[1] / "src" / "peephole" / "datasets" / "input_whetstone.jsonl"
out.write_text("".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in rows))
print(f"wrote {len(rows)} rows to {out}")
