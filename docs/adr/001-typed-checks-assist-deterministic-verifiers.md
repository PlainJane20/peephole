# ADR 001: Typed semantic checks assist deterministic verifiers and never replace them

## Status
Accepted

## Context
Two earlier projects in this portfolio settled one rule from opposite sides. [Blast Door](https://github.com/PlainJane20/blast-door) ([ADR 001](https://github.com/PlainJane20/blast-door/blob/main/docs/adr/001-model-proposes-verifier-decides.md)): the model proposes, a deterministic verifier decides. [Whetstone](https://github.com/PlainJane20/agent-whetstone) ([ADR 001](https://github.com/PlainJane20/agent-whetstone/blob/main/docs/adr/001-deterministic-oracles-not-llm-judges.md)): the thing that scores a defense is deterministic, never an LLM judge.

Peephole adds a model-shaped component, Jev (or an LLM), to the path. Its value is that it reads **meaning**: it can tell that a polite sentence in an email is trying to instruct an assistant, which no regex over trigger words will do reliably. Its risk is the same as any model's: it can be wrong, it can be targeted, and Jev's fixed-answer design cannot explain itself beyond the typed fields.

## Decision
- A semantic verdict is an **additional input** to a decision, never the decision procedure for anything a deterministic check can settle. Structure (what changes, how far, who may) belongs to a verifier such as Blast Door. Peephole answers only what a verifier cannot: is this text trying to instruct the assistant, is this call consistent with the task.
- Nothing in Peephole can loosen a deterministic verdict. In the pairing design (`examples/blast_door_pairing.md`, not built) a semantic `deny` or `ask` can only raise the approval level, and a semantic `allow` has **no effect**.
- Inside Peephole the same rule holds: the hard-deny floor (deterministic, no model) runs **before** any model and can only deny. A model can never override it.
- The mapping from typed answers to allow/ask/deny is **one table in code** (`policy.py`), not a prompt. The model answers typed questions; it does not choose the decision. This is the Blast Door split inside a single repo: the model proposes typed fields, a deterministic table decides.
- The deterministic rules backend stays in the product, as the floor, as the fail-closed fallback, and as the baseline every model backend must be compared with.

## Consequences
- A model that is wrong, jailbroken, or unavailable cannot widen what is allowed. It can add friction (`ask`, `deny`) and can fail to add friction (a missed injection). The second is a real limit: see the threat model. Peephole reduces risk; it is not a boundary.
- Every claim about the model backends has to be a comparison against the rules baseline on the same data, with held-out families, because "the model scored well" is meaningless without it.
- Rigidity is the cost: a genuinely new situation needs a table or policy-text change, not a cleverer prompt. The policy text the models receive is generated from the same constants the rules use, so the two cannot drift.
- It forbids using a model's own confidence as authority. Confidence only decides whether to **escalate**, never whether to trust a model over a deterministic check.
