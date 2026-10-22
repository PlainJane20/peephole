"""Statistics and metrics in the standard library only. Every function is pinned by a hand-computed test.

* `wilson`: 95% Wilson score interval (the Whetstone formula).
* `percentile`: linear interpolation between closest ranks.
* `reliability_table` / `ece`: equal-width confidence bins; ECE = sum_b (n_b / N) * |accuracy_b - confidence_b|.
* `risk_coverage`: as the confidence threshold rises, coverage (share of ALL items decided automatically, i.e.
  with confidence >= threshold) falls and the error rate among the auto-decided items should fall too.
  Items with no confidence are never auto-decided (they always escalate) but count in the coverage denominator.
* `aurc`: area under the risk-coverage curve, the mean selective risk over every prefix of the items ranked by
  confidence (lower is better), over items that HAVE a confidence.
"""
from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Sequence, Tuple

Item = Tuple[Optional[float], bool]      # (confidence or None, was the backend's answer correct?)


def wilson(k: int, n: int, z: float = 1.96) -> Tuple[float, float]:
    """95% Wilson score interval for k successes of n. (0, 1) when n == 0."""
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def rate(k: int, n: int) -> Dict[str, Any]:
    lo, hi = wilson(k, n)
    return {"k": k, "n": n, "rate": round(k / n, 4) if n else None, "wilson95": [round(lo, 4), round(hi, 4)]}


def percentile(values: Sequence[float], q: float) -> float:
    """q in [0, 100]; linear interpolation (the numpy default). Raises on an empty sequence."""
    if not values:
        raise ValueError("percentile of an empty sequence")
    xs = sorted(values)
    pos = (len(xs) - 1) * q / 100.0
    lo, hi = int(math.floor(pos)), int(math.ceil(pos))
    return xs[lo] + (xs[hi] - xs[lo]) * (pos - lo)


def latency_summary(ms: Sequence[float]) -> Dict[str, Any]:
    if not ms:
        return {"n": 0, "p50_ms": None, "p95_ms": None}
    return {"n": len(ms), "p50_ms": round(percentile(ms, 50), 4), "p95_ms": round(percentile(ms, 95), 4)}


def reliability_table(items: Sequence[Item], bins: int = 10) -> List[Dict[str, Any]]:
    """Rows for every bin (empty bins included, with n = 0). Items with no confidence are skipped."""
    rows = [{"bin_lo": b / bins, "bin_hi": (b + 1) / bins, "n": 0, "_c": 0.0, "_ok": 0} for b in range(bins)]
    for conf, ok in items:
        if conf is None:
            continue
        b = min(int(conf * bins), bins - 1)
        rows[b]["n"] += 1
        rows[b]["_c"] += conf
        rows[b]["_ok"] += 1 if ok else 0
    out = []
    for r in rows:
        n = r["n"]
        mc = r["_c"] / n if n else None
        acc = r["_ok"] / n if n else None
        out.append({"bin_lo": round(r["bin_lo"], 4), "bin_hi": round(r["bin_hi"], 4), "n": n,
                    "mean_confidence": None if mc is None else round(mc, 4),
                    "accuracy": None if acc is None else round(acc, 4),
                    "gap": None if mc is None else round(abs(acc - mc), 4)})
    return out


def ece(items: Sequence[Item], bins: int = 10) -> Optional[float]:
    """Expected calibration error over the items that have a confidence. None if there are none."""
    have = [(c, ok) for c, ok in items if c is not None]
    if not have:
        return None
    total = 0.0
    for r in reliability_table(have, bins):
        if r["n"]:
            total += r["n"] / len(have) * r["gap"]
    return round(total, 6)


def risk_coverage(items: Sequence[Item], thresholds: Optional[Sequence[float]] = None) -> List[Dict[str, Any]]:
    """One point per threshold (default: each distinct confidence, ascending), highest coverage first."""
    n_all = len(items)
    have = [(c, ok) for c, ok in items if c is not None]
    ts = sorted(set(thresholds)) if thresholds is not None else sorted({c for c, _ in have})
    pts = []
    for t in ts:
        auto = [ok for c, ok in have if c >= t]
        n_auto = len(auto)
        errors = sum(1 for ok in auto if not ok)
        pts.append({"threshold": round(t, 4), "n_auto": n_auto,
                    "coverage": round(n_auto / n_all, 4) if n_all else None,
                    "errors": errors,
                    "error_rate": round(errors / n_auto, 4) if n_auto else None})
    return pts


def aurc(items: Sequence[Item]) -> Optional[float]:
    have = [(c, ok) for c, ok in items if c is not None]
    if not have:
        return None
    ranked = sorted(have, key=lambda x: -x[0])      # stable: ties keep input order
    errors, total = 0, 0.0
    for i, (_, ok) in enumerate(ranked, 1):
        errors += 0 if ok else 1
        total += errors / i
    return round(total / len(ranked), 6)


def confusion(pairs: Sequence[Tuple[str, str]], rows: Sequence[str], cols: Sequence[str]) -> Dict[str, Dict[str, int]]:
    """rows = true label, cols = decision. Unlisted values are an error, not silently dropped."""
    m = {r: {c: 0 for c in cols} for r in rows}
    for t, d in pairs:
        m[t][d] += 1
    return m
