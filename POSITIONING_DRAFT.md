# Positioning — decision-support draft (W-25)

**Status: DRAFT for a founder/PM decision. Not a committed position.** This
distils the Principal Review's Rec #6 into a one-page statement and a claims
policy so the decision can be made deliberately. Two things must happen before
it is adopted, and neither can be done from inside the codebase:

1. **Independently verify the competitive premise.** The claim that "AI inside
   Burp is no longer differentiated because PortSwigger ships Burp AT" comes from
   the review that did **not** run anything. Confirm Burp AT's actual
   capabilities and availability first-hand before letting it drive
   repositioning. Everything below is contingent on that check.
2. **Ground the efficacy claims in the eval program.** No product claim may ship
   above what the repeated/blind evaluation (W-23) supports at the
   "real-corpus-efficacious" bar (AB-08). The ablation (W-22), evidence ledger
   (W-24), and repeated eval (W-23) scaffolding now exist to inform this; the
   runs themselves are still owed.

---

## Proposed position (for decision, not asserted)

> **The local-first, operator-controlled, evidence-grade validation and
> investigation layer for Burp** — not "the Burp extension with 36 AI agents."

Why this framing follows from the code as it stands:

- **Local-first / operator-controlled** is real and enforced, not aspirational:
  active testing is off by default, mutating replay is a separate opt-in, scope
  fails closed in active mode (W-17), a single gate/scope backstop guards every
  validator (W-1/W-2), and the server rejects untrusted Host headers (W-4). The
  one cloud-reasoning seam is explicit and off by default.
- **Evidence-grade** is the differentiator worth leaning on: deterministic
  confirmation legs, an explicit CONFIRMED/SUSPECTED/LEAD lifecycle (W-7), a
  structural finding identity (W-9), a reproducibility fingerprint (W-20), and
  the evidence ledger (W-24) that reconstructs why a finding was reached. This is
  what a scanner bolting on an LLM does not have.
- **"36 AI agents"** is explicitly **not** a claim to lead with: the agent count
  is an unproven assumption until the A–F ablation (W-22) runs. Marketing the
  count before the ablation answers it would be a claim above the evidence.

## Claims policy

1. Nothing enters product/marketing coverage below the "real-corpus-efficacious"
   bar: a class is only claimed as detected/confirmed when the repeated eval
   (W-23) shows it, across ≥5 runs, above the recall **and** precision floors,
   with the variance reported (not a single lucky run).
2. "Confirmed" in any external material means a deterministic leg proved it
   (lifecycle CONFIRMED), never an agent hypothesis. SUSPECTED/LEAD findings are
   never presented as confirmed.
3. No competitive claim ships until its premise is first-hand verified (see #1
   at the top).
4. The agent-count and architecture story waits on the W-22 ablation result.

## What this draft is not

It is not a decision, and it does not verify the Burp AT premise — doing so from
here would be exactly the "assert a confident, unverifiable claim" failure this
project exists to avoid. It is the input to that decision, now that the
discovery (W-21), ablation (W-22), evaluation (W-23), and evidence-ledger (W-24)
groundwork it depends on is in place.
