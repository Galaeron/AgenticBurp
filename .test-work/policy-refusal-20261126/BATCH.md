# Batch: refusals framed as harness policy (2026-11-26)

## Problem
The iterative agent (`harness/iterative_agent.py`) shows the model why an action did not reach
the target, using the same history field as target responses: `blocked: <host> out of scope`
(`:655`), `blocked by safety gate: ...` (`:657`), rejected proposals (`:941`, `:958`), duplicate
blocks (`:984`), rendered through the step history (`:469`, `:808`). A model can read a harness
refusal as a target defence (WAF/403) and spend steps trying to get around it.

## Idea (from ARTEX, not its text)
ARTEX prefixes every policy block with a statement that it comes from the platform, is not the
target's protection, and the action class is forbidden, so the agent changes approach instead of
re-encoding the payload.

## Requirements
1. Every model-facing refusal that originates in the harness (scope, safety gate, budget,
   duplicate, rejected proposal) is framed as harness policy, distinct from a target response,
   and tells the model not to retry a variant of the same action. Write the wording yourself.
2. Raw reasons in logs, telemetry, stop reasons, counters and the evidence ledger stay as they are.
3. A real target response (403, 429, WAF page) is never framed as policy.
4. Find any other LLM loop that shows harness refusals to a model (grep the agents, the
   worklist investigator, the coordinator) and apply the same rule there, or list it in HANDOFF.
5. Optional, only if cheap: a telemetry count of proposals that repeat a policy-blocked action.

## Tests (caller-level with a fake model, each with a negative control)
- The prompt the fake model receives after a scope block and after a gate block carries the
  policy framing; after a target 403 it does not.
- Telemetry and stop-reason values are unchanged by the framing.
