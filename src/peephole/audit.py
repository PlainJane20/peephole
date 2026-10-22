"""Hash-chained, append-only audit log of every gate decision (adapted from blast-door and agent-whetstone).

Each record stores the SHA-256 of the previous record, so editing, deleting or reordering a record breaks
verification at that point. JSONL file, or in memory when no path is given.

What goes in a record: decision, source, enums, numbers, rule ids, SHA-256 prefixes of the input. What never
goes in: the text, the tool arguments, the task, or an exception message (those can contain the very content a
gate exists to distrust). Callers use `fingerprint()` for correlation.

This detects tampering; it does not prevent it. Whoever can rewrite the whole file can rebuild a consistent
chain, and the head hash is not anchored anywhere.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

GENESIS = "0" * 64


def fingerprint(value: Any) -> str:
    """16 hex chars of SHA-256 over the canonical JSON of `value`. For correlation, not secrecy."""
    raw = json.dumps(value, sort_keys=True, default=str, ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()[:16]


def _digest(prev: str, body: dict) -> str:
    payload = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev + payload).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: Optional[Union[str, Path]] = None) -> None:
        self.path = Path(path) if path else None
        self._records: List[dict] = []
        if self.path and self.path.exists():
            self._records = [json.loads(line) for line in self.path.read_text().splitlines() if line]

    def append(self, event: str, data: Dict[str, Any]) -> dict:
        prev = self._records[-1]["hash"] if self._records else GENESIS
        body = {"seq": len(self._records), "event": event, "data": json.loads(json.dumps(data, default=str))}
        rec = {**body, "prev": prev, "hash": _digest(prev, body)}
        self._records.append(rec)
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a") as f:
                f.write(json.dumps(rec, sort_keys=True) + "\n")
        return rec

    def records(self) -> List[dict]:
        return list(self._records)

    def head(self) -> str:
        return self._records[-1]["hash"] if self._records else GENESIS

    def verify(self) -> Tuple[bool, Optional[int]]:
        return verify_records(self._records)


def verify_records(records: List[dict]) -> Tuple[bool, Optional[int]]:
    """Return (ok, index of the first bad record)."""
    prev = GENESIS
    for i, rec in enumerate(records):
        body = {k: rec.get(k) for k in ("seq", "event", "data")}
        if rec.get("seq") != i or rec.get("prev") != prev or rec.get("hash") != _digest(prev, body):
            return False, i
        prev = rec["hash"]
    return True, None


def load_and_verify(path: Union[str, Path]) -> Tuple[bool, Optional[int], int]:
    recs = [json.loads(line) for line in Path(path).read_text().splitlines() if line]
    ok, bad = verify_records(recs)
    return ok, bad, len(recs)
