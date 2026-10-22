# Pairing Peephole with Blast Door (design note, NOT BUILT)

**Status: a design note. This integration is not built, not tested and not run.** Nothing in this repository imports
Blast Door, and the two repositories share no code. What follows is how I would wire them, and where the seam is.

## The division of labour

[Blast Door](https://github.com/PlainJane20/blast-door) is a deterministic verifier for write operations: it computes
the blast radius of a proposed action from a dry-run and maps `(plan, policy, now, writes so far)` to `allow`,
`needs_approval` or `deny`, with no model in the loop. It checks **structure**: what would change, how far it spreads,
whether the actor may touch it.

Peephole checks **meaning**: is this call consistent with the task the user gave, and is the text that prompted it
trying to instruct the assistant. It cannot compute a blast radius, and Blast Door cannot tell that a perfectly
valid, low-radius action was asked for by an instruction hidden in an email.

Peephole never replaces the verifier ([ADR 001](../docs/adr/001-typed-checks-assist-deterministic-verifiers.md)).

## Where the semantic verdict would enter

```
planner proposes step ──► Peephole ActionGate ──► verdict (typed, with confidence)
                                  │
                                  ▼
        Blast Door verifier(plan, policy, now, writes, semantic=verdict)
                                  │
              allow / needs_approval / deny   (the verifier still decides)
```

The semantic verdict is an extra, **untrusted-by-default** input to the verifier's policy, never a way around it:

| Peephole verdict | Effect on Blast Door's decision |
|---|---|
| `deny` (not consistent with the task) | Can only make the result stricter: force `needs_approval` or `deny`. Never loosens. |
| `ask` (sensitive, or the gate was unsure or failed closed) | Force `needs_approval`, with the typed reasons shown to the approver. |
| `allow` | **No effect.** The verifier's own verdict stands. A semantic `allow` is never evidence that an action is safe. |

Properties this design needs, none of them built yet:

1. **Monotone**: the semantic verdict can raise the required approval level, never lower it. Test: for every verifier
   verdict and every Peephole verdict, `combined >= verifier_alone` in the order allow < needs_approval < deny.
2. **Bound into the approval**: the typed verdict (decision, source, confidences, reasons) would be hashed into the
   plan hash Blast Door already binds approvals to, so an approver sees what the gate said and a changed verdict
   invalidates the approval.
3. **Fail closed**: if Peephole is down or unsure, the combined result is at least `needs_approval`
   ([ADR 002](../docs/adr/002-fail-closed-to-ask.md)).
4. **Audit**: both hash chains record the other's head hash at each decision, so the two logs can be cross-checked.
   Peephole's chain never contains the tool arguments or the text.

## What this does not solve

- Both layers can be wrong at once; a smart attacker who stays inside every deterministic limit and writes in the
  user's own voice is exactly the case neither covers well. See [THREAT_MODEL](../docs/THREAT_MODEL.md).
- It adds a model call (or a Jev call) to the approval path. Latency and cost are **not measured** (nothing has run live).
- The mapping from `ask` to Blast Door's `needs_approval` assumes an approver who can judge the typed reasons; Jev's
  fixed-answer design cannot explain itself beyond the typed fields.
