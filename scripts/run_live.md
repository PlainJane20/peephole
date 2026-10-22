# Running the live evaluation (not run yet)

**Status: built and offline-tested with stub backends only. Nothing here has been run against Jev or Claude Haiku, so no result exists.**

The runner is `scripts/run_live_eval.py` (logic in `src/peephole/live.py`, tests in `tests/test_live.py`). It pushes every example of both datasets (265 inputs, 270 actions) through the rules baseline, Jev and, optionally, Claude Haiku, `--repeats` times each (rules once, because it is deterministic).

```bash
pip install -e ".[jev,llm]"                       # Python 3.10+ (pydantic-ai); the offline core needs only 3.9+
python scripts/run_live_eval.py --dry-run         # exact call counts per backend, token upper bound; no key, no call, no file
export TYPESAFE_API_KEY=...                       # Jev. Environment only: there is no key flag.
export ANTHROPIC_API_KEY=...                      # Haiku, optional (skipped if absent)
python scripts/run_live_eval.py --live --limit 10 --repeats 1          # prints the plan, refuses without --yes
python scripts/run_live_eval.py --live --yes --limit 10 --repeats 1    # a cheap first run: 10 inputs + 10 actions per model
python scripts/run_live_eval.py --live --yes                           # everything, 3 repeats
python scripts/run_live_eval.py --live --yes --resume <run_id>         # continue a stopped run
```

**Set a provider spend limit first.** `--max-calls` (per backend, per invocation) counts calls, not money, and no price is assumed anywhere.

Stop early with `touch PEEPHOLE_KILL` (or `PEEPHOLE_KILL_SWITCH=1`). Exit codes: 0 done, 2 refused or bad usage, 3 `--max-calls` reached, 4 kill switch, 5 API error or retry cap. State is saved after every batch in every case.

## What a run writes (`evals/results/live/<run_id>/`)

- `state.json`: the typed answers and per-field confidences for every call (never the text), failures, run metadata (UTC start, model names, seed, library versions, git commit).
- `audit.jsonl`: a hash-chained log (`run_start`, `batch_done`, `call_failed`, `aborted`, `run_end`, ...).
- `summary.json`: per backend and dataset, repeat 0 as the headline (independent examples): detection and false-block with Wilson intervals, dev versus held-out, confusion matrices, calibration (reliability, ECE, AURC, risk-coverage; Jev only, Haiku reports none), agreement across repeats, plus a **cascade replay** (Jev then Haiku then rules at six thresholds) computed from the recorded answers with no extra calls.

Repeats measure run-to-run consistency; they are **not** extra independent samples, so intervals use repeat 0 only. Latency in a live record includes any retry backoff for that call.

## What to check before believing a result

1. Compare each model with the rules baseline on the **held-out** split, not the dev split.
2. Look at calibration before using the threshold: Jev's reported confidence for a bool field is, per the installed Pydantic AI docs, a distance from the decision threshold rescaled to 0..1, not a probability. 0.8 is this portfolio's default, not a tuned value.
3. Report failures and invalid outputs (`failure_kinds` in the summary) next to the headline.
4. The data is synthetic and author-written; do not publish a number without that sentence next to it.
