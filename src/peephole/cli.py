"""CLI: `python -m peephole check-input | check-action | eval | report`. Offline by default.

Backends: `rules` (default, deterministic), `mock` (a keyword STUB for plumbing, warned loudly), and, only with
`--live` plus keys in the environment, `jev`, `llm` or `cascade` (jev -> llm -> rules). The live backends are built
and offline-tested but have never been run.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, List, Optional, Sequence

from .audit import AuditLog, load_and_verify
from .backends import MockBackend
from .cascade import Cascade
from .gates import ActionGate, InputGate
from .policy import DEFAULT_THRESHOLD

EXIT_REFUSED = 2


def build_cascade(name: str, threshold: float, live: bool, environ: Any = None) -> Cascade:
    environ = os.environ if environ is None else environ
    if name == "rules":
        return Cascade(threshold=threshold)
    if name == "mock":
        print("note: 'mock' is a keyword STUB for plumbing tests, not a model.", file=sys.stderr)
        return Cascade([MockBackend()], threshold=threshold)
    if name in ("jev", "llm", "cascade"):
        if not live:
            raise SystemExit(f"refusing: backend {name!r} makes real paid calls; pass --live (and set the key in the environment)")
        need = {"jev": ["TYPESAFE_API_KEY"], "llm": ["ANTHROPIC_API_KEY"],
                "cascade": ["TYPESAFE_API_KEY", "ANTHROPIC_API_KEY"]}[name]
        miss = [k for k in need if not environ.get(k)]
        if miss:
            raise SystemExit(f"refusing: set {', '.join(miss)} in your environment (never as a flag)")
        from .backends import JevBackend, LLMBackend
        chain: List[Any] = []
        if name in ("jev", "cascade"):
            chain.append(JevBackend())
        if name in ("llm", "cascade"):
            chain.append(LLMBackend())
        return Cascade(chain, threshold=threshold)
    raise SystemExit(f"unknown backend {name!r}")


def _emit(verdict: Any, as_json: bool, out=print) -> None:
    d = json.loads(verdict.model_dump_json())
    if as_json:
        out(json.dumps(d, indent=2, sort_keys=True))
    else:
        out(f"{d['decision'].upper()}  source={d['source']} escalated={d['escalated']} reasons={','.join(d['reasons'])}")


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="peephole", description="Look before you open the door.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--backend", default="rules", choices=["rules", "mock", "jev", "llm", "cascade"])
        p.add_argument("--live", action="store_true", help="allow real model calls (keys from the environment)")
        p.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
        p.add_argument("--audit", help="append the decision to this hash-chained JSONL audit log")
        p.add_argument("--json", action="store_true")

    p = sub.add_parser("check-input", help="gate one piece of untrusted text")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--text")
    g.add_argument("--file")
    p.add_argument("--task", default="")
    common(p)
    p = sub.add_parser("check-action", help="gate one proposed tool call")
    p.add_argument("--task", required=True)
    p.add_argument("--tool", required=True)
    p.add_argument("--args", default="{}", help="tool arguments as a JSON object")
    p.add_argument("--context", default="")
    common(p)
    sub.add_parser("eval", help="run the offline evals (rules + mock stub only)")
    p = sub.add_parser("report", help="print the committed offline summary; verify an audit chain")
    p.add_argument("--audit", help="verify this audit log")
    p.add_argument("--results", default=None)
    return ap


def main(argv: Optional[Sequence[str]] = None, out=print) -> int:
    args = _parser().parse_args(argv)
    if args.cmd in ("check-input", "check-action"):
        try:
            cascade = build_cascade(args.backend, args.threshold, args.live)
        except SystemExit as exc:
            print(str(exc), file=sys.stderr)
            return EXIT_REFUSED
        audit = AuditLog(args.audit) if args.audit else None
        if args.cmd == "check-input":
            text = args.text if args.text is not None else Path(args.file).read_text()
            _emit(InputGate(cascade, audit).check(text, args.task), args.json, out)
        else:
            try:
                targs = json.loads(args.args)
                if not isinstance(targs, dict):
                    raise ValueError("not an object")
            except ValueError as exc:
                print(f"--args must be a JSON object ({exc})", file=sys.stderr)
                return EXIT_REFUSED
            _emit(ActionGate(cascade, audit).check(args.task, args.tool, targs, args.context), args.json, out)
        return 0
    if args.cmd == "eval":
        try:
            from evals.run_all import main as run_all
        except ImportError:
            print("the evals live in the repository (evals/); run from a source checkout: python -m evals.run_all",
                  file=sys.stderr)
            return EXIT_REFUSED
        return run_all()
    if args.cmd == "report":
        rc = 0
        res = Path(args.results) if args.results else Path(__file__).resolve().parents[2] / "evals" / "results" / "offline" / "summary.json"
        if res.exists():
            s = json.loads(res.read_text())
            out(s["label"])
            ri = s["rules_input"]["overall"]
            out(f"rules input : detection {ri['injections']['k']}/{ri['injections']['n']}, false-block "
                f"{ri['benign_false_block']['k']}/{ri['benign_false_block']['n']}")
            hb = s["rules_action"]["headline"]
            out(f"rules action: exact {hb['exact_match']['k']}/{hb['exact_match']['n']}")
        else:
            out(f"no offline summary at {res}; run `python -m evals.run_all`")
        if args.audit:
            ok, bad, n = load_and_verify(args.audit)
            out(f"audit chain: {n} records, {'OK' if ok else f'BROKEN at record {bad}'}")
            rc = 0 if ok else 1
        return rc
    return EXIT_REFUSED
