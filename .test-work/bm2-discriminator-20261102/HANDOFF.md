# BM-2 handoff — 2026-11-02

Branch `claude/bm2-discriminator-afa402` (base `9b02511`). Not pushed.
- `628cdb0` code + tests. Docs commit (backlog Result + this batch dir) follows it.
- No corpus labels, answer keys, blind labels or blind targets read. No live target, no Ollama, no
  config default changed. Test temp dirs go under `<repo>/.test-work/bm2_*` and are removed.

## Root cause per class
Only a validator leg sets `finding.confirmed` (`orchestrator_confirm.py` ~726). The confirmation
gate never accepts a model assertion. So the active-tier false positives come from leg oracles.
- **command_injection** (`validators/command_injection_validator.py`): the in-band check confirmed
  whenever the joined nonce marker appeared. The Ticket-6 control existed but was "never a verdict
  input". A sanitiser that strips `^`/`&` and echoes the rest returns the joined marker.
  **Fix:** `_INBAND_CONTROL` gives each template its pieces without a command separator. The
  marker confirms only when that control is answered without the marker. The same control is the
  proof control. If the control is refused, the result is incomplete. The out-of-band callback path
  is unchanged (it was already sound).
- **path_traversal** (`validators/path_traversal_validator.py`): `root:.*:0:0:` / win.ini text in
  any probe response confirmed, with no baseline. A default page quoting a passwd line confirmed.
  **Fix:** the captured `response_body` is the baseline. A probe confirms only with a signature
  match the baseline lacks. Echoes are counted in the not_confirmed evidence.
- **sqli** (`validators/sqlmap.py` `_boolean_probe_fallback`, also used by sqlmap reproduction): one
  tautology request, then one contradiction request. Any status or length delta confirmed.
  Order-dependent state (a notice or lockout after the first call) confirmed.
  **Fix:** when the pair differs (and the two answers are not both DB errors), send contradiction
  then tautology again. It confirms only if each repeat matches its first answer and the repeats
  still differ. Cost: +2 requests, only on a differential.
- **xss**: no defect. browser_xss/stored_xss confirm only on the product of fresh operands, which
  the payload never contains. The twin test passes on the base (it is regression coverage).
- **idor**: not the same mechanism. `idor_read_validator` never confirms (RV-D2 V2). `cross_identity`
  confirms against `authz.owners` with a second identity (owner decision), not a same-endpoint
  baseline. Unchanged.

## Tests
- New `harness/test_bm2_secure_twin_callers.py`: an own loopback twin server, per class, through
  `Orchestrator._validate_findings`. The vulnerable twin must confirm and the secure twin must not.
  On the base, cmdi, path_traversal and sqli fail ("secure twin confirmed"):
  `logs/base-twin-tests.log`, exit 1, 3 failures. The xss test passes on the base.
- Updated to the new oracle:
  - `test_proof_artifacts` (the cmdi "joins without a shell" case now asserts not-confirmed; it had
    pinned the defect as a confirmed candidate);
  - `test_sqlmap_validator`, `test_sqlmap_points` and `test_issue_accounting` (the mocks and request
    counts include the reverse repeat).
- PR collision note: #8 touches `command_injection_validator.py` and #11 touches `sqlmap.py`. The
  hunks are small: one new constant plus the in-band confirm branch, and the probe send block in
  `_boolean_probe_fallback`.

## Gates (PYTHONPATH=worktree; status files py312.status / py314.status)
| gate | venv 3.12.14 | system 3.14.7 |
|---|---|---|
| precondition | 0 | 0 |
| smoke | 0 (149 OK) | 0 |
| full | 0: harness 5060 OK, native 38, evaluation 440 / 17 skips, integrity 59 | 0: same counts |
| `git diff --check` | 0 | |

## Still open / next step
- The benchmark's `fp_on_tested_negative_control` counts **unconfirmed passive** hypotheses:
  strict_benchmark runs no active legs. This batch does not change that number. Lowering it means
  surfacing such hypotheses as leads: the FR-4/quarantine gates are OFF by default. Enabling them is
  an owner decision and needs a strict_benchmark re-measure.
- Residuals:
  - path traversal with an empty captured body has no baseline (behaves as before);
  - a WAF that blocks only the literal tautology text still passes the sqli repeat (a second,
    differently-spelled predicate pair would close it);
  - a vulnerable viewer whose default page already quotes the identical root line is missed.
