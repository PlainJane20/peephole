# Threat model

Scope: what Peephole's gates do and do **not** protect against. **Status: built and offline-tested; no live Jev or LLM result exists.** Every statement about how a model behaves is therefore a limit or a design intent, not a result. Defensive use only: the example attacks are generic and benign (a fake tool call, a fake `CANARY-` string, reserved `.example` destinations) and exist for a sandbox with fake tools.

## Assets and actors

- **Asset:** an assistant's user: their mail, notes and the actions taken on their behalf.
- **Attacker:** whoever controls text the assistant reads (an email sender, a calendar-invite author, a web page) and wants the assistant to do something its user did not ask.
- **Agent / planner:** untrusted. It may propose any tool call, including one induced by hostile text.
- **Peephole gates:** `InputGate` (before the assistant reads text) and `ActionGate` (before a proposed call runs). Trusted code, calling an untrusted-but-useful model.
- **Deterministic verifiers** (for example [Blast Door](https://github.com/PlainJane20/blast-door)): decide structure. Peephole never replaces them ([ADR 001](adr/001-typed-checks-assist-deterministic-verifiers.md)).

## What is protected, and by what

| Threat | Control | Evidence |
|---|---|---|
| Obvious injection (override phrase, forged system block, tool-call syntax) | Rules backend (copied from Whetstone), hard-deny floor before any model | `tests/test_rules_mock.py`; rules catch 50/55 dev injections |
| A model outage or error silently disabling the gate | Fail policy, default closed: `allow` becomes `ask` | `test_all_backends_raise_fail_closed_never_allow`, `evals/chaos.py` (0 violations) |
| A model that is unsure | Single confidence threshold; below it, missing, or error: escalate, else fail policy | `tests/test_cascade.py` |
| A model overriding a deterministic denial | Hard deny runs first and never calls a model | `test_hard_deny_runs_before_any_model_and_never_calls_it` |
| The gate leaking what it judges | Audit and spans hold enums, numbers, rule ids and SHA-256 prefixes only; exception messages never recorded; unknown tool names recorded as `other` | `tests/test_audit_tracing.py` (sensitive strings fed through text, arguments, task, tool name, exception) |
| Silent edit of the decision history | Hash-chained audit log; verification reports the first bad record | `test_edit_is_detected_at_the_edited_record` |
| Accidental paid live run, a runaway run, a key in a log | Environment-only keys, `--live` and `--yes`, call caps, kill switch, redaction, atomic resumable state | `tests/test_live.py` |

## What is NOT protected

1. **A smarter, adaptive attacker.** All attacks here are static, written by one author, and generic. None was written against the gate after seeing its verdicts. An attacker who iterates against the gate, or who writes in the user's own voice with no trigger words, is the case this design is weakest on. Even the deterministic baseline misses 27 of the 125 injections (offline results), and misses most `paraphrased_no_triggers` examples (2/10 caught). A model may do better on these; **that has not been measured**. Adaptive attacks against the gate are not built.
2. **Model errors.** Jev and any LLM can be confidently wrong. Confidence decides only when to escalate; it is not evidence of correctness. Calibration is a thing to measure (the harness does), not a property assumed, and no calibration of a real model has been measured.
3. **Jev's fixed-answer design cannot explain itself.** Jev returns typed answers with confidence and no rationale. An approver who sees `ask` or `deny` gets the typed fields and rule ids, not an explanation. An LLM tier could be asked to explain; that is not built.
4. **The gate itself can be targeted.** Text can be written to get a confidently wrong answer from the model that judges it, to trip the hard-deny floor on legitimate mail (a denial-of-service on a mailbox: the rules already deny some benign security newsletters), or to flood the human `ask` queue until reviewers rubber-stamp. A prompt-injection **in the text being judged** is aimed at the judge as much as at the assistant. None of this is tested live.
5. **Labels are author-written.** One author wrote the datasets and the rules. The rules were committed before the held-out data was written and were not edited afterwards, which limits tuning but does not remove shared blind spots. 'Ambiguous' action labels are my judgement; a second reviewer might flip some. The data is not real traffic. Held-out means "families the rules were not written for", not "independent".
6. **Fail-closed costs availability.** A total outage holds every input the rules would allow (see ADR 002). If nobody watches the `ask` queue, `ask` degrades into a silent drop.
7. **Semantic mistakes inside a deterministically valid action.** The gate is not a substitute for blast-radius checks, allow-lists, rate limits, or human approval of irreversible writes. It adds a semantic opinion to those.
8. **Reads.** The action gate asks whether a read is consistent with the task and sensitive; it does not stop an agent from reading what it is allowed to read.
9. **Latency and cost in a real deployment.** The measured latency is the in-process deterministic layers only (no model). The live latency, and the cost of one Jev call or Haiku call per message, are not measured.
10. **Anyone with write access to the audit file.** The chain detects partial edits; whoever can rewrite the whole file can rebuild a consistent chain. The head hash is not anchored anywhere.
11. **The copied rules inherit Whetstone's known bypasses**, for example Greek homoglyphs (the fold table is Cyrillic-only), and a pattern screen cannot tell discussing an attack from carrying one: 4 of 10 security-awareness posts in the new data are held or denied.
12. **Unverified live behaviour.** The shape of `provider_details['confidence']` for a multi-field output, the behaviour of Pydantic AI's `Agent(TypeSafeModel(...), output_type=...)` with this policy text, and the real error classes of the Jev and Anthropic SDKs have been read from documentation and installed source, not observed. The code is written to degrade (to unsure, to a recorded failure) rather than guess.

## Misuse boundary

The repository contains example attack text. It is for testing a defense against your own sandbox with fake tools and fake secrets. Do not use it against a system you do not own, and do not treat the examples as a catalogue of effective attacks: they are simple on purpose.
