# ADR 002: Fail closed to `ask`

## Status
Accepted

## Context
A gate that lets everything through when it breaks is worse than no gate: it looks like protection. Peephole's model tiers will fail in ways that are boring and frequent: timeouts, overload, a malformed typed answer, a missing confidence field (the shape of `provider_details` for several fields has not been seen live), or simply an unsure answer. The question is what the gate does then.

Edge-sentinel's cascade chose "a failure in any model layer degrades to the rules, never to no decision". That is the starting point. It leaves one case open: the rules say `allow` while the model that should have double-checked is down.

## Decision
- **Per gate, an explicit policy** with two values, defined in `policy.py` and tested: `closed` and `open`. The default for **both** gates is `closed`. `open` exists, is opt-in, and is reported in every audit record (`fail_policy`).
- When no model tier is decisive (every tier raised, was below the threshold, or reported no confidence where it should have), the decision is the **rules' verdict**, with one change under `closed`: **`allow` becomes `ask`**. A rules `deny` stays `deny`; a rules `ask` stays `ask`.
- "Decisive" means: a confidence-reporting backend (Jev) with minimum confidence at or above the single threshold; a backend that reports no confidence (an LLM) when it is the tier reached; a deterministic backend (rules) always. A missing confidence from Jev counts as unsure, never as certain.
- `ask` means a human decides. It is a hold, not a refusal, which keeps fail-closed from silently dropping work.
- The rules layer itself failing (a bug) is treated the same way: `ask`, never `allow`.
- Exception **messages are never stored or traced**; the audit record keeps the exception class name only (`backend_error:jev:TimeoutError`), because a message can contain the very content the gate distrusts.

## Consequences
- A total model outage costs availability: every input that the rules would allow is held for a human. The offline chaos eval measures this cost with a stub backend (with the backend raising on 100% of calls, all 140 benign inputs are held under fail-closed, versus 18 under fail-open, which are the rules' own false blocks). That is the price of the property, stated rather than hidden, and a human queue that nobody watches turns `ask` into a silent drop in practice.
- A regression test (and the chaos eval, which exits non-zero) checks the property directly: no verdict whose model tier failed is `allow` under `closed`. `test_run_all_fails_loudly_if_fail_closed_is_broken` proves the check can fail.
- Fail-open remains available for a deployment that prefers availability and accepts the risk. Choosing it is an explicit, auditable act, per gate.
- This ADR says nothing about adversaries who can force the model to be confidently wrong. That is the "gate can be targeted" row in the threat model.
