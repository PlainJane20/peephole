"""The guarded LIVE evaluation runner (logic). The CLI entry is `scripts/run_live_eval.py`.

STATUS: BUILT AND OFFLINE-TESTED WITH STUB BACKENDS ONLY. IT HAS NEVER BEEN RUN AGAINST JEV OR CLAUDE HAIKU.

What it does when run for real: pushes ALL datasets (input and action) through the rules baseline, Jev and Claude
Haiku, N repeats each (rules once: deterministic), and writes `evals/results/live/<run_id>/` with `summary.json`,
`state.json` (answers and confidences, never text) and a hash-chained `audit.jsonl`.

Guards (all tested with stubs): keys from the ENVIRONMENT ONLY (there is no key flag); refuses without --live and
--yes; --dry-run prints the exact plan and makes zero calls and writes nothing; hard per-backend call cap
(--max-calls); kill switch (file or env); transient errors retried with backoff (copied design from
agent-whetstone), permanent ones stop the run with a key-redacted record; state saved atomically after every batch;
resumable with --resume. The guards count calls, not money: set a provider spend limit first.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import random
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from . import __version__
from .audit import AuditLog, fingerprint
from .backends.base import Answer, Backend, action_state, input_state
from .backends.rules import RulesBackend
from .cascade import Cascade
from .datasets import ActionExample, InputExample, load_action_examples, load_input_examples
from .evaluation import (action_verdict_from_answer, calibration, input_verdict_from_answer, run_action,
                         run_input, summarise_action, summarise_input)
from .policy import ACTION_INSTRUCTIONS, DEFAULT_THRESHOLD, INPUT_INSTRUCTIONS
from .retry import (CallFailed, DEFAULT_BASE_S, DEFAULT_CAP_S, DEFAULT_MAX_ATTEMPTS, DEFAULT_MAX_TOTAL_RETRIES,
                    Retrier, RetryPolicy, clip_redacted)
from .types import ActionQuestions, InputQuestions

EXIT_OK, EXIT_REFUSED, EXIT_BUDGET, EXIT_KILL, EXIT_ERROR = 0, 2, 3, 4, 5
BACKENDS = ("rules", "jev", "haiku")
MODEL_BACKENDS = ("jev", "haiku")
DATASETS = ("input", "action")
KEY_ENV = {"jev": "TYPESAFE_API_KEY", "haiku": "ANTHROPIC_API_KEY"}
DEFAULT_JEV_MODEL = "jev-latest"
DEFAULT_HAIKU_MODEL = "anthropic:claude-haiku-4-5-20251001"
DEFAULT_REPEATS = 3
DEFAULT_BATCH = 10
KILL_FILE = "PEEPHOLE_KILL"
KILL_ENV = "PEEPHOLE_KILL_SWITCH"
RESULTS_DIR = Path(__file__).resolve().parents[2] / "evals" / "results" / "live"
SCHEMA_VERSION = 1
PROMPT_OVERHEAD_TOKENS = 400          # tool/output schema and framing, a deliberately generous guess (NOT measured)
OUTPUT_TOKENS_UPPER = {"jev": 50, "haiku": 300}   # haiku: the max_tokens set in LLMBackend; jev: decisions, no text
CHARS_PER_TOKEN = 3.0                 # conservative (real text is nearer 4): over-counts tokens on purpose
INVALID_OUTPUT_NAMES = ("UnexpectedModelBehavior", "ValidationError")
THRESHOLDS = [0.5, 0.6, 0.7, 0.8, 0.9, 0.95]


# ---- kill switch ---------------------------------------------------------------------------------------------
class KillSwitch:
    def __init__(self, path: str = KILL_FILE, environ: Optional[Mapping[str, str]] = None) -> None:
        self.path = path
        self.environ = os.environ if environ is None else environ

    def reason(self) -> str:
        if str(self.environ.get(KILL_ENV, "")).lower() in ("1", "true", "yes"):
            return f"{KILL_ENV} is set"
        if self.path and Path(self.path).exists():
            return f"kill file {self.path} exists"
        return ""


# ---- plan ------------------------------------------------------------------------------------------------------------
@dataclass
class Config:
    backends: Tuple[str, ...] = BACKENDS
    datasets: Tuple[str, ...] = DATASETS
    repeats: int = DEFAULT_REPEATS
    seed: int = 0
    limit: Optional[int] = None
    max_calls: Optional[int] = None             # per model backend, THIS invocation
    batch_size: int = DEFAULT_BATCH
    jev_model: str = DEFAULT_JEV_MODEL
    haiku_model: str = DEFAULT_HAIKU_MODEL
    threshold: float = DEFAULT_THRESHOLD
    retry_max_attempts: int = DEFAULT_MAX_ATTEMPTS
    retry_base_s: float = DEFAULT_BASE_S
    retry_cap_s: float = DEFAULT_CAP_S
    max_total_retries: int = DEFAULT_MAX_TOTAL_RETRIES
    out_dir: str = str(RESULTS_DIR)
    kill_file: str = KILL_FILE

    def validate(self) -> None:
        for b in self.backends:
            if b not in BACKENDS:
                raise ValueError(f"unknown backend {b!r}; choose from {BACKENDS}")
        for d in self.datasets:
            if d not in DATASETS:
                raise ValueError(f"unknown dataset {d!r}; choose from {DATASETS}")
        if self.repeats < 1 or self.batch_size < 1:
            raise ValueError("--repeats and --batch-size must be at least 1")
        if self.limit is not None and self.limit < 1:
            raise ValueError("--limit must be at least 1")
        if self.max_calls is not None and self.max_calls < 0:
            raise ValueError("--max-calls cannot be negative")
        RetryPolicy(self.retry_max_attempts, self.retry_base_s, self.retry_cap_s, self.max_total_retries).validate()

    def identity(self) -> Dict[str, Any]:
        """What must match for a resume to be the same run (budgets and retry settings may differ)."""
        return {"backends": list(self.backends), "datasets": list(self.datasets), "repeats": self.repeats,
                "seed": self.seed, "limit": self.limit, "jev_model": self.jev_model, "haiku_model": self.haiku_model,
                "dataset_fingerprint": dataset_fingerprint(self.limit, self.datasets)}


def _load(limit: Optional[int], datasets: Sequence[str]) -> Dict[str, list]:
    out: Dict[str, list] = {}
    if "input" in datasets:
        out["input"] = load_input_examples()
    if "action" in datasets:
        out["action"] = load_action_examples()
    if limit is not None:
        out = {k: _sample(v, limit, 0) for k, v in out.items()}
    return out


def _sample(items: list, n: int, seed: int) -> list:
    """A seeded sample (not the first n: the files are grouped by family)."""
    idx = sorted(random.Random(seed).sample(range(len(items)), min(n, len(items))))
    return [items[i] for i in idx]


def dataset_fingerprint(limit: Optional[int], datasets: Sequence[str]) -> str:
    d = _load(limit, datasets)
    return fingerprint({k: [e.id for e in v] for k, v in d.items()})


def _order(items: list, seed: int, repeat: int, dataset: str) -> list:
    rng = random.Random(f"{seed}|{repeat}|{dataset}")
    out = list(items)
    rng.shuffle(out)
    return out


def _state_text(dataset: str, ex: Any) -> Tuple[str, str]:
    if dataset == "input":
        st, _ = input_state(ex.text, ex.context)
        return st, INPUT_INSTRUCTIONS
    st, _ = action_state(ex.task, ex.tool_name, ex.tool_args, ex.context)
    return st, ACTION_INSTRUCTIONS


def plan(cfg: Config) -> Dict[str, Any]:
    """Exact call counts per backend and an UPPER BOUND on tokens. Calls nothing, reads no key."""
    data = _load(cfg.limit, cfg.datasets)
    per_backend: Dict[str, Any] = {}
    for b in cfg.backends:
        if b == "rules":
            per_backend[b] = {"model_calls": 0, "repeats": 1, "note": "deterministic, no model, no key",
                              "examples": {k: len(v) for k, v in data.items()}}
            continue
        total = sum(len(v) for v in data.values()) * cfg.repeats
        in_tok = 0
        for ds, items in data.items():
            for ex in items:
                st, instr = _state_text(ds, ex)
                in_tok += math.ceil((len(st) + len(instr)) / CHARS_PER_TOKEN) + PROMPT_OVERHEAD_TOKENS
        in_tok *= cfg.repeats
        capped = total if cfg.max_calls is None else min(total, cfg.max_calls)
        worst_attempts = capped + min(cfg.max_total_retries, capped * (cfg.retry_max_attempts - 1))
        per_backend[b] = {"model_calls_planned": total, "model_calls_allowed_by_cap": capped,
                          "cap_truncates_run": capped < total, "repeats": cfg.repeats,
                          "examples": {k: len(v) for k, v in data.items()},
                          "worst_case_http_attempts_with_retries": worst_attempts,
                          "input_tokens_upper_bound": in_tok if capped == total else math.ceil(in_tok * capped / total),
                          "output_tokens_upper_bound": capped * OUTPUT_TOKENS_UPPER[b],
                          "model": cfg.jev_model if b == "jev" else cfg.haiku_model}
    return {"backends": per_backend, "seed": cfg.seed,
            "token_bounds_note": ("input tokens = ceil(chars / 3) + 400 per call, a conservative GUESS, not measured; "
                                  "output bound = 50 (Jev) / max_tokens 300 (Haiku). Cost is NOT computed: no "
                                  "price is assumed. Set a provider spend limit first.")}


def format_plan(p: Dict[str, Any]) -> str:
    lines = ["Live evaluation PLAN (nothing has been called):"]
    for b, v in p["backends"].items():
        if b == "rules":
            lines.append(f"  rules : 0 model calls (deterministic baseline over {v['examples']})")
        else:
            lines.append(f"  {b:5s} : {v['model_calls_planned']} calls planned ({v['examples']} x {v['repeats']} repeats)"
                         f"; cap allows {v['model_calls_allowed_by_cap']}"
                         f"; worst-case HTTP attempts incl. retries {v['worst_case_http_attempts_with_retries']}"
                         f"; tokens <= {v['input_tokens_upper_bound']} in / {v['output_tokens_upper_bound']} out"
                         f" ({v['model']})")
    lines.append("  " + p["token_bounds_note"])
    return "\n".join(lines)


# ---- replay (offline cascade from recorded answers) ----------------------------------------------------------------------
class ReplayBackend:
    """Serves recorded typed answers, keyed by a fingerprint of the example, so the cascade can be evaluated at
    many thresholds from ONE set of live calls with no new calls."""
    deterministic = False

    def __init__(self, name: str, reports_confidence: bool, input_answers: Dict[str, dict],
                 action_answers: Dict[str, dict]) -> None:
        self.name, self.reports_confidence = name, reports_confidence
        self._in, self._act = input_answers, action_answers

    def answer_input(self, text: str, task_context: str) -> Answer:
        rec = self._in[fingerprint([text, task_context])]
        return Answer(InputQuestions(addresses_assistant=rec["addresses_assistant"], intent=rec["intent"],
                                     risk=rec["risk"]), dict(rec["confidences"]), self.name, {"replay": True})

    def answer_action(self, task: str, tool_name: str, tool_args: Mapping[str, Any], context: str) -> Answer:
        rec = self._act[fingerprint([task, tool_name, dict(tool_args), context])]
        return Answer(ActionQuestions(consistent_with_task=rec["consistent_with_task"],
                                      touches_sensitive_data=rec["touches_sensitive_data"]),
                      dict(rec["confidences"]), self.name, {"replay": True})


def _fp_input(ex: InputExample) -> str:
    return fingerprint([ex.text, ex.context])


def _fp_action(ex: ActionExample) -> str:
    return fingerprint([ex.task, ex.tool_name, dict(ex.tool_args), ex.context])


# ---- state ---------------------------------------------------------------------------------------------------------------
def _atomic_write(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n")
    os.replace(str(tmp), str(path))


def _git_commit() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=str(Path(__file__).resolve().parents[2]),
                              capture_output=True, text=True, timeout=10).stdout.strip()
    except Exception:
        return ""


def _versions() -> Dict[str, str]:
    out = {"python": sys.version.split()[0], "platform": platform.platform(terse=True), "peephole": __version__}
    for mod in ("pydantic", "pydantic_ai", "anthropic"):
        try:
            out[mod] = __import__(mod).__version__
        except Exception:
            out[mod] = "not installed"
    return out


def _key(backend: str, dataset: str, repeat: int, ex_id: str) -> str:
    return f"{backend}|{dataset}|{repeat}|{ex_id}"


# ---- the runner -----------------------------------------------------------------------------------------------------------
@dataclass
class Outcome:
    run_dir: Path
    exit_code: int
    summary: Dict[str, Any]


class _Stop(Exception):
    def __init__(self, code: int, reason: str, info: Optional[dict] = None) -> None:
        super().__init__(reason)
        self.code, self.reason, self.info = code, reason, info or {}


def _record_for(backend: Backend, dataset: str, ex: Any, call: Callable[[], Answer]) -> Dict[str, Any]:
    t0 = time.perf_counter()
    ans = call()
    ms = (time.perf_counter() - t0) * 1000.0
    if dataset == "input":
        rec = run_input(lambda e: input_verdict_from_answer(ans, backend.name), [ex], clock=lambda: 0.0)[0]
    else:
        rec = run_action(lambda e: action_verdict_from_answer(ans, backend.name), [ex], clock=lambda: 0.0)[0]
    rec["latency_ms"] = round(ms, 3)
    rec["meta"] = {k: v for k, v in ans.meta.items() if isinstance(v, (int, bool))}
    rec["fp"] = _fp_input(ex) if dataset == "input" else _fp_action(ex)
    return rec


def run(cfg: Config, run_dir: Path, factories: Mapping[str, Callable[[], Backend]], kill: KillSwitch,
        retrier: Retrier, say: Callable[[str], None], state: Optional[Dict[str, Any]] = None,
        clock: Callable[[], float] = time.time) -> Outcome:
    data = _load(cfg.limit, cfg.datasets)
    audit = AuditLog(run_dir / "audit.jsonl")
    if state is None:
        state = {"schema_version": SCHEMA_VERSION, "run_id": run_dir.name, "identity": cfg.identity(),
                 "meta": {"started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(clock())),
                          "git_commit": _git_commit(), "versions": _versions(),
                          "models": {"jev": cfg.jev_model, "haiku": cfg.haiku_model}, "seed": cfg.seed,
                          "config": {"repeats": cfg.repeats, "limit": cfg.limit, "max_calls": cfg.max_calls,
                                     "threshold": cfg.threshold}},
                 "records": {}, "failures": [], "status": "running", "calls_made": {}}
        audit.append("run_start", {"run_id": run_dir.name, "identity": state["identity"], "seed": cfg.seed})
    else:
        audit.append("run_resume", {"run_id": run_dir.name, "records_so_far": len(state["records"])})
    records: Dict[str, dict] = state["records"]
    calls_this_run: Dict[str, int] = {b: 0 for b in cfg.backends}
    code, reason = EXIT_OK, ""

    def save(status: str) -> None:
        state["status"] = status
        state["calls_made"] = {b: state["calls_made"].get(b, 0) for b in cfg.backends}
        _atomic_write(run_dir / "state.json", state)

    try:
        for b in cfg.backends:
            backend = factories[b]()
            repeats = 1 if b == "rules" else cfg.repeats
            pending: List[Tuple[str, int, Any]] = []
            for r in range(repeats):
                for ds, items in data.items():
                    for ex in _order(items, cfg.seed, r, ds):
                        if _key(b, ds, r, ex.id) not in records:
                            pending.append((ds, r, ex))
            say(f"  {b}: {len(pending)} call(s) to do")
            done_in_batch = 0
            for ds, r, ex in pending:
                why = kill.reason()
                if why:
                    raise _Stop(EXIT_KILL, f"kill switch: {why}")
                if b in MODEL_BACKENDS and cfg.max_calls is not None and calls_this_run[b] >= cfg.max_calls:
                    raise _Stop(EXIT_BUDGET, f"--max-calls {cfg.max_calls} reached for {b}")
                fn = (lambda: backend.answer_input(ex.text, ex.context)) if ds == "input" else \
                     (lambda: backend.answer_action(ex.task, ex.tool_name, ex.tool_args, ex.context))
                calls_this_run[b] += 1
                state["calls_made"][b] = state["calls_made"].get(b, 0) + 1
                try:
                    rec = _record_for(backend, ds, ex, (lambda: fn()) if b == "rules" else
                                      (lambda: retrier.call(fn, label=f"{b}:{ds}:{ex.id}", kill=kill)))
                except CallFailed as cf:
                    if cf.reason == "kill_switch":
                        raise _Stop(EXIT_KILL, cf.detail, cf.info)
                    names = cf.info.get("exception_chain", [])
                    if cf.reason == "api_permanent" and any(n in INVALID_OUTPUT_NAMES for n in names):
                        # the model answered but not with a valid typed object: a recorded miss, not a reason to stop
                        failure = {"key": _key(b, ds, r, ex.id), "kind": "invalid_output", "info": cf.info}
                        state["failures"].append(failure)
                        audit.append("call_failed", {"key": failure["key"], "kind": "invalid_output",
                                                     "classification": cf.info.get("classification")})
                        continue
                    raise _Stop(EXIT_ERROR, f"{cf.reason}: {cf.detail}", cf.info)
                except Exception as exc:                       # a bug or a rules failure: stop, never guess
                    raise _Stop(EXIT_ERROR, "unexpected: " + clip_redacted(f"{type(exc).__name__}: {exc}", 200))
                rec.update({"backend": b, "dataset": ds, "repeat": r})
                records[_key(b, ds, r, ex.id)] = rec
                done_in_batch += 1
                if done_in_batch >= cfg.batch_size:
                    audit.append("batch_done", {"backend": b, "records": len(records), "calls": dict(calls_this_run)})
                    save("running")
                    done_in_batch = 0
            audit.append("backend_done", {"backend": b, "records": len(records)})
            save("running")
    except _Stop as stop:
        code, reason = stop.code, stop.reason
        audit.append({EXIT_KILL: "kill_switch", EXIT_BUDGET: "budget_reached", EXIT_ERROR: "aborted"}[stop.code],
                     {"reason": clip_redacted(stop.reason, 300),
                      "error": {k: stop.info.get(k) for k in ("classification", "classification_reason",
                                                              "status_code", "attempts", "exception_chain")}})
        if stop.info:
            state["failures"].append({"kind": "abort", "reason": clip_redacted(stop.reason, 300),
                                      "info": {k: v for k, v in stop.info.items() if k != "body"}})
    status = {EXIT_OK: "complete", EXIT_KILL: "partial_kill_switch", EXIT_BUDGET: "partial_budget_reached",
              EXIT_ERROR: "partial_error"}[code]
    summary = summarise(cfg, state, data, retrier, calls_this_run, status, reason)
    audit.append("run_end", {"status": status, "records": len(records), "retries": retrier.total_retries})
    summary["audit"] = {"records": len(audit.records()), "head": audit.head(), "chain_ok": audit.verify()[0]}
    save(status)
    _atomic_write(run_dir / "summary.json", summary)
    return Outcome(run_dir, code, summary)


# ---- summary ---------------------------------------------------------------------------------------------------------------
def summarise(cfg: Config, state: Dict[str, Any], data: Dict[str, list], retrier: Retrier,
              calls_this_run: Dict[str, int], status: str, reason: str) -> Dict[str, Any]:
    recs = state["records"]
    out: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION, "run_id": state["run_id"], "status": status, "stop_reason": reason,
        "meta": state["meta"],
        "label": ("LIVE run: real model calls (Jev and/or Claude Haiku) over author-written synthetic data. One "
                  "author wrote data and rules; this is not real traffic. Repeat 0 is the headline (independent "
                  "examples); repeats measure run-to-run consistency, they are NOT extra independent samples."),
        "calls_made_total": state["calls_made"], "calls_made_this_invocation": calls_this_run,
        "transient_retries": retrier.total_retries, "failures": len(state["failures"]),
        "failure_kinds": sorted({f["kind"] for f in state["failures"]}), "backends": {}}
    for b in cfg.backends:
        block: Dict[str, Any] = {}
        for ds in cfg.datasets:
            by_rep: Dict[int, List[dict]] = {}
            for r in recs.values():
                if r["backend"] == b and r["dataset"] == ds:
                    by_rep.setdefault(r["repeat"], []).append(r)
            if not by_rep:
                continue
            first = sorted(by_rep[min(by_rep)], key=lambda r: r["id"])
            summ = summarise_input(first) if ds == "input" else summarise_action(first)
            expected = len(data.get(ds, []))
            block[ds] = {"examples_answered_in_repeat_0": len(first), "examples_expected": expected,
                         "repeats_present": sorted(by_rep), "headline_repeat_0": summ,
                         "calibration_repeat_0": calibration(first, thresholds=THRESHOLDS),
                         "decision_agreement_across_repeats": _agreement(by_rep)}
        out["backends"][b] = block
    out["cascade_replay"] = _cascade_replay(cfg, recs, data)
    return out


def _agreement(by_rep: Dict[int, List[dict]]) -> Optional[Dict[str, Any]]:
    if len(by_rep) < 2:
        return None
    ids: Dict[str, List[str]] = {}
    for rep in by_rep.values():
        for r in rep:
            ids.setdefault(r["id"], []).append(r["decision"])
    full = [v for v in ids.values() if len(v) == len(by_rep)]
    same = sum(1 for v in full if len(set(v)) == 1)
    return {"examples_with_all_repeats": len(full), "identical_decision_in_every_repeat": same,
            "rate": round(same / len(full), 4) if full else None}


def _cascade_replay(cfg: Config, recs: Dict[str, dict], data: Dict[str, list]) -> Optional[Dict[str, Any]]:
    """Cascade [jev, haiku] -> rules fallback at several thresholds from recorded repeat-0 answers. No new calls."""
    if "jev" not in cfg.backends or "input" not in data and "action" not in data:
        return None
    tiers = []
    for name, reports in (("jev", True), ("haiku", False)):
        if name not in cfg.backends:
            continue
        ia = {r["fp"]: r for r in recs.values() if r["backend"] == name and r["dataset"] == "input" and r["repeat"] == 0}
        aa = {r["fp"]: r for r in recs.values() if r["backend"] == name and r["dataset"] == "action" and r["repeat"] == 0}
        tiers.append(ReplayBackend(name, reports, ia, aa))
    if not tiers:
        return None
    out: Dict[str, Any] = {"note": "replayed from recorded repeat-0 answers; the rules tier and hard deny run live "
                                   "(deterministic). Examples without a recorded answer count as backend errors "
                                   "(fail-closed).", "thresholds": {}}
    for thr in THRESHOLDS:
        row: Dict[str, Any] = {}
        if "input" in data:
            casc = Cascade(tiers, threshold=thr)
            rin = run_input(lambda ex: _safe_input(casc, ex), data["input"])
            row["input"] = summarise_input(rin)["overall"]
        if "action" in data:
            casc = Cascade(tiers, threshold=thr)
            rac = run_action(lambda ex: _safe_action(casc, ex), data["action"])
            hb = summarise_action(rac)["headline_firm_labels_only"]
            row["action"] = {k: hb[k] for k in ("exact_match", "under_block", "deny_to_allow", "over_block")}
        out["thresholds"][f"{thr:.2f}"] = row
    return out


def _safe_input(casc: Cascade, ex: InputExample):
    return casc.check_input(ex.text, ex.context)


def _safe_action(casc: Cascade, ex: ActionExample):
    return casc.check_action(ex.task, ex.tool_name, ex.tool_args, ex.context)


# ---- CLI --------------------------------------------------------------------------------------------------------------------
def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="Guarded live evaluation of Peephole backends (Jev, Haiku, rules). "
                                 "NEEDS KEYS IN THE ENVIRONMENT AND MAKES PAID CALLS. NOT RUN YET.", allow_abbrev=False)
    ap.add_argument("--live", action="store_true", help="really call the models")
    ap.add_argument("--yes", action="store_true", help="confirm the printed plan and spend")
    ap.add_argument("--dry-run", action="store_true", help="print the plan and exact call counts; call nothing")
    ap.add_argument("--resume", metavar="RUN_ID", help="continue a saved run (same identity), skipping done calls")
    ap.add_argument("--backends", default=",".join(BACKENDS))
    ap.add_argument("--datasets", default=",".join(DATASETS))
    ap.add_argument("--repeats", type=int, default=DEFAULT_REPEATS, help="repeats per model backend (rules: 1)")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--limit", type=int, help="seeded sample of N examples per dataset (a cheap first run)")
    ap.add_argument("--max-calls", type=int, help="hard cap on model calls PER BACKEND in this invocation")
    ap.add_argument("--batch-size", type=int, default=DEFAULT_BATCH)
    ap.add_argument("--jev-model", default=DEFAULT_JEV_MODEL)
    ap.add_argument("--haiku-model", default=DEFAULT_HAIKU_MODEL)
    ap.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    ap.add_argument("--retry-max-attempts", type=int, default=DEFAULT_MAX_ATTEMPTS)
    ap.add_argument("--retry-base-s", type=float, default=DEFAULT_BASE_S)
    ap.add_argument("--retry-cap-s", type=float, default=DEFAULT_CAP_S)
    ap.add_argument("--max-total-retries", type=int, default=DEFAULT_MAX_TOTAL_RETRIES)
    ap.add_argument("--out-dir", default=str(RESULTS_DIR))
    ap.add_argument("--kill-file", default=KILL_FILE)
    return ap


def _default_factories(cfg: Config) -> Dict[str, Callable[[], Backend]]:
    def jev() -> Backend:
        from .backends.jev import JevBackend
        return JevBackend(cfg.jev_model)

    def haiku() -> Backend:
        from .backends.llm import LLMBackend
        return LLMBackend(cfg.haiku_model)

    return {"rules": RulesBackend, "jev": jev, "haiku": haiku}


def main(argv: Optional[Sequence[str]] = None, environ: Optional[Mapping[str, str]] = None, *,
         factories: Optional[Mapping[str, Callable[[], Backend]]] = None, kill: Optional[KillSwitch] = None,
         out: Callable[[str], None] = print, sleep: Callable[[float], None] = time.sleep,
         clock: Callable[[], float] = time.time) -> int:
    """`factories`, `kill`, `out`, `sleep` and `clock` exist so tests run the whole flow with stubs."""
    environ = os.environ if environ is None else environ
    args = _parser().parse_args(argv)
    try:
        backends = tuple(b for b in args.backends.split(",") if b)
        # haiku is optional: if it was not asked for explicitly, drop it when its key is absent
        raw = list(sys.argv[1:] if argv is None else argv)
        explicit_haiku = any(a == "--backends" or a.startswith("--backends=") for a in raw) and "haiku" in backends
        cfg = Config(backends=backends, datasets=tuple(d for d in args.datasets.split(",") if d),
                     repeats=args.repeats, seed=args.seed, limit=args.limit, max_calls=args.max_calls,
                     batch_size=args.batch_size, jev_model=args.jev_model, haiku_model=args.haiku_model,
                     threshold=args.threshold, retry_max_attempts=args.retry_max_attempts,
                     retry_base_s=args.retry_base_s, retry_cap_s=args.retry_cap_s,
                     max_total_retries=args.max_total_retries, out_dir=args.out_dir, kill_file=args.kill_file)
        if "haiku" in cfg.backends and not explicit_haiku and not environ.get(KEY_ENV["haiku"]) and not args.dry_run:
            cfg.backends = tuple(b for b in cfg.backends if b != "haiku")
            out("note: ANTHROPIC_API_KEY is not set, so Haiku is skipped (it is optional).")
        cfg.validate()
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_REFUSED

    kill = kill or KillSwitch(cfg.kill_file, environ)
    p = plan(cfg)
    out(format_plan(p))
    if args.dry_run:
        out("\nDry run: no model was called, no key was read, nothing was written.")
        return EXIT_OK
    if not args.live:
        print("\nrefusing: this makes real, paid model calls. Pass --live (and --yes), or --dry-run.", file=sys.stderr)
        return EXIT_REFUSED
    missing = [KEY_ENV[b] for b in cfg.backends if b in KEY_ENV and not environ.get(KEY_ENV[b])]
    if missing:
        print(f"\nrefusing: set {', '.join(missing)} in your environment (keys are never read from a flag or file).",
              file=sys.stderr)
        return EXIT_REFUSED
    if not args.yes:
        print("\nrefusing: review the plan above, set a provider spend limit, then re-run with --yes.", file=sys.stderr)
        return EXIT_REFUSED
    why = kill.reason()
    if why:
        print(f"\nrefusing: kill switch is set ({why}).", file=sys.stderr)
        return EXIT_KILL

    base = Path(cfg.out_dir)
    state = None
    if args.resume:
        run_dir = base / args.resume
        sp = run_dir / "state.json"
        if not sp.exists():
            print(f"error: no saved run at {run_dir}", file=sys.stderr)
            return EXIT_REFUSED
        state = json.loads(sp.read_text())
        if state["identity"] != cfg.identity():
            print("error: the saved run was made with a different configuration (backends, datasets, repeats, seed, "
                  "limit, models or data); refusing to mix them.", file=sys.stderr)
            return EXIT_REFUSED
    else:
        stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime(clock()))
        run_dir = base / f"{stamp}-seed{cfg.seed}"
        if run_dir.exists():
            print(f"error: {run_dir} already exists; use --resume {run_dir.name}", file=sys.stderr)
            return EXIT_REFUSED
    retrier = Retrier(RetryPolicy(cfg.retry_max_attempts, cfg.retry_base_s, cfg.retry_cap_s, cfg.max_total_retries),
                      sleep=sleep)
    out(f"\nRunning. State and the audit chain are saved every {cfg.batch_size} calls under {run_dir}.")
    outcome = run(cfg, run_dir, factories or _default_factories(cfg), kill, retrier, out, state, clock)
    out(f"\nstatus: {outcome.summary['status']}   saved: {run_dir}")
    if outcome.exit_code != EXIT_OK:
        out(f"stopped: {outcome.summary['stop_reason']}   resume with: --resume {run_dir.name}")
    return outcome.exit_code
