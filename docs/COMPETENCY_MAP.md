# Competency map

Each entry names the code or test that demonstrates it. Nothing here is claimed without evidence in the repository. **Peephole is built and offline-tested; it has never been run against Jev or Claude.** Competencies that depend on a live run are listed at the end as not demonstrated.

## Evaluation design under authorship bias

**Behavior:** Report a defense's performance on families it was never written for, next to the number that flatters it.

**Evidence:**
- Dev versus held-out split by family for both datasets; the rules were committed before any held-out data was written (`git log`: the first commit is the rules and the typed mapping); `datasets/__init__.py`, `tests/test_datasets.py`.
- Held-out gap is visible in the committed results: rules detect 90.9% of dev injections but 68.6% of held-out ones; held-out action `deny -> allow` is 16/37 against 0/72 on dev (`evals/results/offline/`).
- Arguable labels are flagged (`AMBIGUOUS_IDS`) and reported separately, never mixed into the headline; `test_action_eval_reports_ambiguous_separately`.

## Calibration and selective prediction

**Behavior:** Treat a model's confidence as something to measure, and use it only to decide when to escalate.

**Evidence:**
- Reliability table, expected calibration error and a risk-coverage curve in the standard library, each **pinned against hand-computed values**; `src/peephole/stats.py`, `tests/test_stats.py`.
- Missing confidence is "unsure", not "certain"; `test_missing_confidence_from_jev_is_unsure_and_escalates`.
- Defensive confidence extraction for a response shape that has been seen live only for one question; `backends/base.py::extract_confidences`, `tests/test_backends.py`.

## Systems design: cascade and failure policy

**Behavior:** Decide what a gate does when its model is wrong, absent or unsure, and prove it.

**Evidence:**
- Hard deny, then Jev, then an LLM, then a fail policy; one threshold and one decision table in one file (`policy.py`, `cascade.py`); [ADR 001](adr/001-typed-checks-assist-deterministic-verifiers.md), [ADR 002](adr/002-fail-closed-to-ask.md).
- Chaos test with a backend that raises on N% of calls; the fail-closed property has zero violations and the check is shown able to fail; `evals/chaos.py`, `test_run_all_fails_loudly_if_fail_closed_is_broken`.
- Exhaustive tests of the decision table against its documented rows; `tests/test_policy_types.py`.

## Safe live-run engineering

**Behavior:** Make an expensive, irreversible experiment hard to run by accident and cheap to resume.

**Evidence:**
- Keys from the environment only (no key flag exists), `--live` and `--yes` both required, `--dry-run` prints exact call counts and a token upper bound and makes zero calls, hard per-backend call cap, kill switch, transient-error retry with backoff (copied design from Whetstone), key-redacted error records, atomic saves after every batch, resumable; `src/peephole/live.py`, `scripts/run_live_eval.py`, `tests/test_live.py` (43 tests, stub backends only).

## Observability and privacy by construction

**Behavior:** Instrument a gate that sees sensitive text without ever exporting it.

**Evidence:**
- Hash-chained audit log of every decision, content-free, with tamper detection; `audit.py`, `tests/test_audit_tracing.py`.
- OpenTelemetry spans whose attribute keys are an allowlist and whose string values must match an identifier pattern; tests feed sensitive strings through text, tool arguments, task, tool name and exception messages and assert none reach any span or audit record.

## Honest scoping

**Behavior:** State what was not run, and keep stub numbers out of the results.

**Evidence:**
- "Built, offline-tested, not run live" in the README header, the banner, the diagram, every live module docstring and the live script's dry run.
- The MockBackend is documented as a test double in its module docstring, labelled in every output file that used it (`backend_is_stub`), and no README table contains a mock number; `tests/test_docs.py`.
- Defensive scope only; generic benign payloads; synthetic data; tests assert no real-looking secrets, no employer names and only reserved example domains in the data.

## Not demonstrated (not built or not run)

Any live Jev or Haiku result, measured Jev calibration, the Blast Door integration, adaptive attacks against the gate, cost or live latency measurement.
