"""AR-10 part B: the frozen `acceptance.json` of one run (spec 3.3).

Each hard criterion the sealed scorer takes from acceptance.json (L1-L5, L7, L9,
L10; L8 the scorer computes from the replay audit itself) is computed here from the
run directory's own artifacts. Nothing is asserted: a criterion whose input is
missing, or not exported at all, is written as "unknown" with the reason, and the
scorer never counts unknown as a pass. An artifact that is present but violates the
criterion is "fail".

Run-directory layout read (the part-B live run writes it):

- job-status.json, result-integrity.json, result.json, replay-audit.json (the AR-08c
  `replay_audit.py` output);
- the L2 pins: live-settings.json, effective-config.json, loaded-package.txt and
  enabled-features.json (the enabled-feature manifest of spec 3.2).

`*-private.json` and other credential files are never opened implicitly. The L10
canary scan uses only a canary file the operator names (`--canaries`): every string
of 8+ characters under a secret field name in it is a canary. The output names
criteria, file names and counts, never a canary, a value or an offset.

Output: {"schema": "ar10-acceptance/1", "L1": "pass"|"fail"|"unknown", ...,
"reasons": {"L1": "..."}}. Offline only: it never contacts a target or a model.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from harness import ar10_scorer, security
from harness.assessment_health import _ORPHAN_REASONS

SCHEMA = "ar10-acceptance/1"
CRITERIA = ("L1", "L2", "L3", "L4", "L5", "L7", "L9", "L10")
PIN_FILES = ("live-settings.json", "effective-config.json", "loaded-package.txt",
             "enabled-features.json")
EXPORT_FILES = ("result.json", "replay-audit.json")   # what the freeze copies, so what L10 scans
AUDIT_STATES = ("audited", "not_audited", "unsupported_audit")
_REDACTED = frozenset({security.REDACTED_PLACEHOLDER, security.SECRET_VALUE_PLACEHOLDER})
_MIN_CANARY = 8

PASS, FAIL, UNKNOWN = "pass", "fail", "unknown"


class _Run:
    """Lazy, read-once access to one run directory's artifacts."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self._json: dict = {}

    def bytes(self, name: str) -> bytes | None:
        try:
            return (self.root / name).read_bytes()
        except OSError:
            return None

    def json(self, name: str):
        """(value, problem): problem is None, "missing" or "unparseable"."""
        if name not in self._json:
            data = self.bytes(name)
            if data is None:
                self._json[name] = (None, "missing")
            else:
                try:
                    self._json[name] = (json.loads(data), None)
                except ValueError:
                    self._json[name] = (None, "unparseable")
        return self._json[name]


def _int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


# ---------------------------------------------------------------- criteria

def l1_done_and_integrity(run: _Run):
    status, problem = run.json("job-status.json")
    if problem:
        return UNKNOWN, f"job-status.json {problem}"
    if not isinstance(status, dict) or status.get("status") != "done":
        return FAIL, "the job did not reach done"
    data = run.bytes("result.json")
    integrity, problem = run.json("result-integrity.json")
    if data is None or problem:
        return UNKNOWN, "result.json or result-integrity.json missing or unparseable"
    integrity = integrity if isinstance(integrity, dict) else {}
    digests = [d for d in (integrity.get("sha256"), status.get("result_sha256")) if d]
    sizes = [s for s in (integrity.get("bytes"), status.get("result_size_bytes")) if s is not None]
    if not digests:
        return UNKNOWN, "no recorded result digest to check the export against"
    if any(d != hashlib.sha256(data).hexdigest() for d in digests):
        return FAIL, "result.json does not match its recorded sha256"
    if any(s != len(data) for s in sizes):
        return FAIL, "result.json does not match its recorded size"
    return PASS, f"done; result.json matches {len(digests)} recorded digest(s)"


def l2_pins(run: _Run):
    absent = []
    for name in PIN_FILES:
        data = run.bytes(name)
        if data is None or not data.strip():
            absent.append(name)
        elif name.endswith(".json"):
            value, problem = run.json(name)
            if problem or not value:
                absent.append(name)
    if absent:
        return FAIL, "missing, empty or unparseable: " + ", ".join(absent)
    return PASS, f"{len(PIN_FILES)} pins present"


def l3_dispositions(result: dict):
    if "experiment_preflight" not in result:
        return UNKNOWN, "result.json has no experiment_preflight (task dispositions)"
    block = result["experiment_preflight"]
    if not isinstance(block, dict) or block.get("schema_version") != 2:
        return FAIL, "task dispositions are not schema 2"
    tasks = block.get("tasks")
    if not isinstance(tasks, list):
        return FAIL, "task dispositions list no tasks"
    untyped = advisory = 0
    for t in tasks:
        status = t.get("status") if isinstance(t, dict) else None
        if status == "advisory":
            advisory += 1
        if status != "completed":
            blocked = t.get("blocked_on") if isinstance(t, dict) else None
            if not (isinstance(blocked, dict) and isinstance(blocked.get("category"), str)
                    and blocked["category"] and isinstance(blocked.get("inputs"), list)
                    and blocked["inputs"]):
                untyped += 1
    if advisory or untyped:
        return FAIL, (f"{advisory} ready task(s) left advisory, "
                      f"{untyped} uncompleted task(s) without a typed blocked_on")
    return PASS, f"{len(tasks)} task(s) with a final disposition"


def l4_final_pass(result: dict):
    if "experiment_final_pass" not in result:
        return UNKNOWN, "result.json has no experiment_final_pass"
    final = result["experiment_final_pass"]
    if isinstance(final, dict):
        if _int(final.get("runs")):
            return PASS, f"final pass ran ({final['runs']} run(s))"
        return FAIL, "experiment_final_pass has no run count"
    if final is not None:
        return FAIL, "experiment_final_pass is malformed"
    preflight = result.get("experiment_preflight")
    if isinstance(preflight, dict) and preflight.get("enabled") is False:
        return PASS, "final pass not run: engagement experiments disabled"
    if any(isinstance(e, dict) and e.get("phase") == "experiments_final"
           for e in result.get("errors") or []):
        return PASS, "final pass failed; its error is recorded"
    return FAIL, "final pass did not run and no reason is recorded"


def l5_proof_links(result: dict):
    block = result.get("issue_accounting")
    if block is None:
        return UNKNOWN, "result.json has no issue_accounting"
    if not isinstance(block, dict) or block.get("schema_version") != 1:
        return FAIL, "issue_accounting is not schema 1"
    known = {p.get("proof_id") for p in block.get("proof_instances") or [] if isinstance(p, dict)}
    dangling = sum(pid not in known for g in block.get("groups") or [] if isinstance(g, dict)
                   for pid in g.get("proof_ids") or [])
    listed = block.get("orphaned_proof_links")
    if not isinstance(listed, list):
        return FAIL, "issue_accounting does not list orphaned proof links"
    listed_keys = {(o.get("case_id"), o.get("proof_id"), o.get("reason"))
                   for o in listed if isinstance(o, dict) and o.get("repair")}
    orphans = [e for e in block.get("excluded") or []
               if isinstance(e, dict) and e.get("reason") in _ORPHAN_REASONS]
    dropped = sum((e.get("case_id"), e.get("proof_id"), e.get("reason")) not in listed_keys
                  for e in orphans)
    count = (block.get("counts") or {}).get("orphaned_proof_links")
    if dangling or dropped or count != len(listed):
        return FAIL, (f"{dangling} shown proof link(s) do not resolve, {dropped} orphaned link(s) "
                      "not listed for repair" + ("" if count == len(listed) else
                                                 ", orphan count disagrees with the list"))
    # Basis: the export. The store's proof_records are not part of a frozen export.
    return PASS, f"every shown proof link resolves; {len(listed)} orphan(s) listed for repair"


def _audit_state(verdict):
    if verdict in ar10_scorer.AUDITED_VERDICTS:
        return "audited"
    return "unsupported_audit" if verdict == "unsupported_audit" else "not_audited"


def l7_audit_states(run: _Run):
    audit, problem = run.json("replay-audit.json")
    if problem:
        return UNKNOWN, f"replay-audit.json {problem}"
    claims = audit.get("claims") if isinstance(audit, dict) else None
    if not isinstance(claims, list):
        return FAIL, "replay audit lists no claims"
    stateless = inconsistent = unreasoned = 0
    for c in claims:
        c = c if isinstance(c, dict) else {}
        state = c.get("audit_state")
        if state not in AUDIT_STATES:
            stateless += 1
        elif state != _audit_state(c.get("verdict")):
            inconsistent += 1
        elif state != "audited" and not c.get("reason"):
            unreasoned += 1
    audited = sum(_audit_state((c or {}).get("verdict")) == "audited" for c in claims)
    fps = sum((c or {}).get("verdict") == "false_positive" for c in claims)
    totals = audit.get("audit_totals")
    totals_ok = (isinstance(totals, dict) and totals.get("claims") == len(claims)
                 and totals.get("audited") == audited
                 and totals.get("false_positives") == (fps if audited else None))
    if stateless or inconsistent or unreasoned or not totals_ok:
        return FAIL, (f"{stateless} claim(s) without an audit state, {inconsistent} inconsistent "
                      f"with their verdict, {unreasoned} unaudited without a reason"
                      + ("" if totals_ok else "; audit_totals missing or disagree with the claims"))
    return PASS, f"{len(claims)} claim(s): {audited} audited, the rest with a reason"


def l9_seed_binding(result: dict):
    # engagement_builder reports an unbound capture only in the role crawl's own errors,
    # and the result exports no supplied/bound capture counts, so a silent drop cannot
    # be ruled out from the export (producer follow-up).
    return UNKNOWN, "result.json does not export seed-capture binding (supplied vs bound)"


def canaries_from(path: Path) -> list[str]:
    """Every string of 8+ characters under a secret field name in the operator's
    canary file; a cookie is split into its values and a bearer prefix dropped."""
    found: list[str] = []

    def add(value: str):
        value = value.strip()
        if value.lower().startswith("bearer "):
            value = value[7:].strip()
        parts = [p.partition("=")[2].strip() for p in value.split(";")] if "=" in value else []
        for v in [value, *parts]:
            if len(v) >= _MIN_CANARY and v not in found:
                found.append(v)

    def walk(node, secret=False):
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, secret or security._is_secret_field_name(str(k)))
        elif isinstance(node, list):
            for v in node:
                walk(v, secret)
        elif isinstance(node, str) and secret:
            add(node)

    walk(json.loads(Path(path).read_bytes()))
    return found


def _redacted_metrics(node) -> int:
    if isinstance(node, dict):
        return sum((1 if str(k).strip().lower().replace("-", "_").replace(" ", "_")
                    in security._METRIC_LABEL_SECRET_NAMES and v in _REDACTED else 0)
                   + _redacted_metrics(v) for k, v in node.items())
    if isinstance(node, list):
        return sum(_redacted_metrics(v) for v in node)
    return 0


def l10_no_secrets(run: _Run, canaries: list[str] | None):
    present = [n for n in EXPORT_FILES if run.bytes(n) is not None]
    if not present:
        return UNKNOWN, "no export file to scan"
    redacted = sum(_redacted_metrics(run.json(n)[0]) for n in present)
    leaking = [n for n in present
               if any(c.encode() in run.bytes(n) for c in canaries or [])]
    if leaking or redacted:
        return FAIL, (f"canary found in: {', '.join(leaking) or 'none'}; "
                      f"{redacted} auth/csrf metric count(s) redacted")
    if not canaries:
        return UNKNOWN, ("no canary source given; " if canaries is None else
                         "the canary file holds no secret value; ") + "metric counts not redacted"
    return PASS, f"{len(canaries)} canaries absent from {len(present)} export file(s); metrics intact"


# ---------------------------------------------------------------- evaluate

def evaluate(run_dir: Path, *, canaries: list[str] | None = None) -> dict:
    run = _Run(run_dir)
    result, problem = run.json("result.json")
    if problem or not isinstance(result, dict):
        result = None
    no_result = (UNKNOWN, "result.json missing or unparseable")
    checks = {
        "L1": lambda: l1_done_and_integrity(run),
        "L2": lambda: l2_pins(run),
        "L3": lambda: l3_dispositions(result) if result is not None else no_result,
        "L4": lambda: l4_final_pass(result) if result is not None else no_result,
        "L5": lambda: l5_proof_links(result) if result is not None else no_result,
        "L7": lambda: l7_audit_states(run),
        "L9": lambda: l9_seed_binding(result) if result is not None else no_result,
        "L10": lambda: l10_no_secrets(run, canaries),
    }
    out: dict = {"schema": SCHEMA}
    reasons = {}
    for name in CRITERIA:
        out[name], reasons[name] = checks[name]()
    out["reasons"] = reasons
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("run_dir", type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--canaries", type=Path, help="operator-named canary file (L10)")
    args = ap.parse_args(argv)
    canaries = canaries_from(args.canaries) if args.canaries else None
    doc = evaluate(args.run_dir, canaries=canaries)
    args.out.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({c: doc[c] for c in CRITERIA}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
