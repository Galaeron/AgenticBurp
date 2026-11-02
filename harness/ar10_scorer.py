"""AR-10 P3: the sealed scorer for the part-C model evaluation.

It reads the frozen exports of every repeat and the owner's sealed
expected-mechanism mapping (spec section 4.4), and writes per-repeat metrics,
per-arm medians and the pre-registered decision (section 4.5).

Order of operations is the seal:

1. The freeze manifest is checked first. Every repeat's export directory must hold
   exactly the files the manifest lists, each with its recorded sha256. A missing,
   changed or unlisted file refuses the run, and the mapping is never opened.
2. Only then are the mapping's bytes read, once. Their sha256 must equal the
   `mapping_sha256` the manifest pre-registered before repeat 1.
3. Output holds aggregate counts only. No mapping entry id, note, match field or
   route reaches the output file, stdout or stderr, and errors about the mapping
   never echo its content.

Inputs (all JSON):

- freeze manifest: {"schema": "ar10-freeze/1", "mapping_sha256": "<hex>",
  "repeats": [{"repeat_id": "A1", "arm": "A", "export_dir": "<dir, relative to the
  manifest>", "files": {"replay-audit.json": "<sha256>", "result.json": "<sha256>",
  ...}}]}. replay-audit.json (the AR-08c `replay_audit.py` output) and result.json
  are required in every repeat; acceptance.json ({"L1": "pass"|"fail", ...}, the
  part-B criteria) is optional.
- mapping: {"schema": "ar10-mapping/1", "challenges_total": <int, optional>,
  "mechanisms": [{"id": "...", "available": true, "match": {"validator": "...",
  "class": "...", "route": "/path"}, "equivalents": [{...match...}]}]}. A match field
  left out is a wildcard, but every match must name at least one field. A claim
  counts through `equivalents` only because the mapping records that equivalence.

Exit codes: 0 scored, 2 refused (nothing written), 3 bad input after the freeze check.
Offline only: it never contacts a target or a model.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import statistics
import sys
from pathlib import Path
from urllib.parse import urlsplit

MANIFEST_SCHEMA = "ar10-freeze/1"
MAPPING_SCHEMA = "ar10-mapping/1"
OUTPUT_SCHEMA = "ar10-scores/1"
REQUIRED_FILES = ("replay-audit.json", "result.json")
# A proof counts only when replay audit confirmed it (spec 4.4). Hardening and
# observation verdicts are not independently verified mechanisms.
VERIFIED_VERDICTS = frozenset({"confirmed"})
AUDITED_VERDICTS = frozenset({"confirmed", "confirmed_hardening", "confirmed_observation",
                              "false_positive", "not_applicable", "not_supported"})
# Part-B hard failures (spec 3.3); L6 and L11 are regressions, not hard failures.
HARD_CRITERIA = ("L1", "L2", "L3", "L4", "L5", "L7", "L8", "L9", "L10")
MATCH_FIELDS = ("validator", "class", "route")
DIAGNOSTIC_COUNTS = ("parse_errors", "refusals", "rejected_proposals",
                     "unavailable_selections", "duplicate_proposals", "blocked_attempts",
                     "useful_unique_actions", "evidence_attempts")
COST_KEYS = ("model_calls", "model_errors", "retries", "wall_seconds")
_HEX64 = re.compile(r"[0-9a-f]{64}")

EXIT_OK, EXIT_REFUSED, EXIT_BAD_INPUT = 0, 2, 3


class Refusal(Exception):
    """The seal is not satisfied; nothing may be read past this point or written."""


class BadInput(Exception):
    """An input is malformed after the freeze check. Messages never quote the mapping."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------- freeze check

def load_manifest(path: Path) -> dict:
    try:
        manifest = json.loads(path.read_bytes())
    except (OSError, ValueError) as exc:
        raise Refusal(f"freeze manifest unreadable: {type(exc).__name__}") from None
    if not isinstance(manifest, dict) or manifest.get("schema") != MANIFEST_SCHEMA:
        raise Refusal(f"freeze manifest schema is not {MANIFEST_SCHEMA}")
    if not _HEX64.fullmatch(str(manifest.get("mapping_sha256") or "")):
        raise Refusal("freeze manifest has no pre-registered mapping_sha256")
    repeats = manifest.get("repeats")
    if not isinstance(repeats, list) or not repeats:
        raise Refusal("freeze manifest lists no repeats")
    seen = set()
    for r in repeats:
        rid = r.get("repeat_id") if isinstance(r, dict) else None
        if not isinstance(rid, str) or not rid or rid in seen:
            raise Refusal("every repeat needs a unique repeat_id")
        seen.add(rid)
        if not isinstance(r.get("arm"), str) or not r["arm"]:
            raise Refusal(f"repeat {rid}: no arm")
        files = r.get("files")
        if not isinstance(files, dict) or not files:
            raise Refusal(f"repeat {rid}: no hashed files")
        for name in REQUIRED_FILES:
            if name not in files:
                raise Refusal(f"repeat {rid}: {name} is not in the frozen file set")
        for name, digest in files.items():
            if not _HEX64.fullmatch(str(digest)):
                raise Refusal(f"repeat {rid}: {name} has no sha256")
    return manifest


def verify_freeze(manifest: dict, base: Path) -> dict[str, dict[str, bytes]]:
    """Check every repeat's export against the manifest and return the verified bytes,
    so what is scored is exactly what was hashed (no re-read after the check)."""
    verified = {}
    for r in manifest["repeats"]:
        rid = r["repeat_id"]
        export = (base / str(r.get("export_dir") or "")).resolve()
        if not export.is_dir():
            raise Refusal(f"repeat {rid}: export directory missing")
        on_disk = {p.relative_to(export).as_posix() for p in export.rglob("*") if p.is_file()}
        unlisted = on_disk - set(r["files"])
        if unlisted:
            raise Refusal(f"repeat {rid}: {len(unlisted)} file(s) not in the freeze manifest")
        blobs = {}
        for name, digest in r["files"].items():
            target = (export / name).resolve()
            if export not in target.parents:
                raise Refusal(f"repeat {rid}: {name} is outside its export directory")
            try:
                data = target.read_bytes()
            except OSError:
                raise Refusal(f"repeat {rid}: {name} is missing") from None
            if sha256_bytes(data) != digest:
                raise Refusal(f"repeat {rid}: {name} does not match its frozen sha256")
            blobs[name] = data
        verified[rid] = {"export": export, "blobs": blobs}
    return verified


def read_sealed_mapping(path: Path, expected_sha: str) -> dict:
    """Called only after verify_freeze. The bytes are read once and hashed before
    parsing; error messages never include mapping content."""
    try:
        data = path.read_bytes()
    except OSError:
        raise Refusal("sealed mapping unreadable") from None
    if sha256_bytes(data) != expected_sha:
        raise Refusal("sealed mapping does not match the pre-registered mapping_sha256")
    try:
        mapping = json.loads(data)
    except ValueError:
        raise BadInput("sealed mapping is not valid JSON") from None
    if not isinstance(mapping, dict) or mapping.get("schema") != MAPPING_SCHEMA:
        raise BadInput(f"sealed mapping schema is not {MAPPING_SCHEMA}")
    entries = mapping.get("mechanisms")
    if not isinstance(entries, list) or not entries:
        raise BadInput("sealed mapping lists no mechanisms")
    for index, e in enumerate(entries):
        if not isinstance(e, dict) or not isinstance(e.get("available", True), bool):
            raise BadInput(f"sealed mapping entry #{index} is malformed")
        for spec in [e.get("match"), *(e.get("equivalents") or [])]:
            if not _valid_match(spec):
                raise BadInput(f"sealed mapping entry #{index} has an invalid match")
    total = mapping.get("challenges_total")
    if total is not None and (not isinstance(total, int) or isinstance(total, bool) or total < 1):
        raise BadInput("sealed mapping challenges_total must be a positive integer")
    return mapping


def _valid_match(spec) -> bool:
    return (isinstance(spec, dict) and bool(spec) and set(spec) <= set(MATCH_FIELDS)
            and all(isinstance(v, str) and v for v in spec.values()))


# ---------------------------------------------------------------- scoring

def _route(url) -> str:
    path = urlsplit(str(url or "")).path or ""
    return path.rstrip("/") or "/"


def _claim_matches(claim: dict, spec: dict) -> bool:
    if "validator" in spec and str(claim.get("validator") or "") != spec["validator"]:
        return False
    if "class" in spec:
        classes = {c.strip().lower() for c in str(claim.get("class") or "").split(" + ")}
        if spec["class"].lower() not in classes:
            return False
    if "route" in spec and _route(claim.get("url")) != _route(spec["route"]):
        return False
    return True


def _find_key(obj, key):
    """First value stored under `key` anywhere in a nested JSON value."""
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        children = obj.values()
    elif isinstance(obj, list):
        children = obj
    else:
        return None
    for child in children:
        found = _find_key(child, key)
        if found is not None:
            return found
    return None


def _parse_json(rid: str, name: str, data: bytes):
    try:
        return json.loads(data)
    except ValueError:
        raise BadInput(f"repeat {rid}: {name} is not valid JSON") from None


def score_repeat(rid: str, blobs: dict[str, bytes], mapping: dict) -> dict:
    audit = _parse_json(rid, "replay-audit.json", blobs["replay-audit.json"])
    result = _parse_json(rid, "result.json", blobs["result.json"])
    claims = audit.get("claims") if isinstance(audit, dict) else None
    if not isinstance(claims, list):
        raise BadInput(f"repeat {rid}: replay-audit.json has no claims list")
    claims = [c for c in claims if isinstance(c, dict)]
    verified = [c for c in claims if c.get("verdict") in VERIFIED_VERDICTS]

    entries = mapping["mechanisms"]
    available = [e for e in entries if e.get("available", True)]
    boundaries = {"no_matching_claim": 0, "claim_not_audited": 0, "audited_not_confirmed": 0}
    direct = via_equivalence = 0
    for e in available:
        if any(_claim_matches(c, e["match"]) for c in verified):
            direct += 1
            continue
        if any(_claim_matches(c, s) for s in e.get("equivalents") or [] for c in verified):
            via_equivalence += 1
            continue
        specs = [e["match"], *(e.get("equivalents") or [])]
        matched = [c for c in claims if any(_claim_matches(c, s) for s in specs)]
        if not matched:
            boundaries["no_matching_claim"] += 1
        elif any(c.get("verdict") in AUDITED_VERDICTS for c in matched):
            boundaries["audited_not_confirmed"] += 1
        else:
            boundaries["claim_not_audited"] += 1
    primary = direct + via_equivalence

    total = mapping.get("challenges_total")
    unavailable = len(entries) - len(available)
    if total is None:
        recall = {"value": None, "reason": "the mapping supplies no denominator"}
    elif total - unavailable < len(available) or total - unavailable < 1:
        raise BadInput("sealed mapping challenges_total is smaller than its available entries")
    else:
        recall = {"value": round(primary / (total - unavailable), 4),
                  "denominator": total - unavailable}

    audited = sum(c.get("verdict") in AUDITED_VERDICTS for c in claims)
    false_positives = sum(c.get("verdict") == "false_positive" for c in claims)
    return {
        "repeat_id": rid,
        "primary_verified_mechanisms": primary,
        "verified_directly": direct,
        "verified_via_recorded_equivalence": via_equivalence,
        "expected_available": len(available),
        "unavailable_excluded": unavailable,
        "recall": recall,
        "first_failing_boundary": boundaries,
        "audit": {"claims": len(claims), "audited": audited,
                  "confirmed": len(verified),
                  "false_positives": false_positives if audited else None},
        "secondary": _secondary(result),
        "hard_failures": _hard_failures(rid, blobs, false_positives if audited else None),
    }


def _secondary(result) -> dict:
    diag = _find_key(result, "iterative_diagnostics")
    totals = diag.get("totals") if isinstance(diag, dict) else None
    if not isinstance(totals, dict):
        return {"diagnostics_present": False}
    out = {"diagnostics_present": True,
           "probes": diag.get("probes"),
           "probes_without_diagnostics": diag.get("probes_without_diagnostics")}
    for k in DIAGNOSTIC_COUNTS:
        out[k] = totals.get(k)
    reasons = diag.get("by_stop_reason") or {}
    out["stop_reasons"] = {str(k): (v or {}).get("probes") for k, v in reasons.items()
                           if isinstance(v, dict)}
    steps = totals.get("steps")
    for name, num in (("duplicate_share", "duplicate_proposals"), ("parse_error_rate", "parse_errors")):
        out[name] = (round(totals.get(num, 0) / steps, 4)
                     if isinstance(steps, int) and steps > 0 else None)
    costs = result.get("costs") if isinstance(result, dict) else None
    costs = costs if isinstance(costs, dict) else {}
    for k in COST_KEYS:
        out[k] = costs.get(k)
    calls = costs.get("model_calls")
    useful = totals.get("useful_unique_actions")
    out["useful_unique_actions_per_model_call"] = (
        round(useful / calls, 4) if isinstance(calls, int) and calls > 0 and isinstance(useful, int)
        else None)
    return out


def _hard_failures(rid: str, blobs: dict, false_positives) -> dict:
    """Part-B hard criteria. L8 is computed from the replay audit; the rest come from the
    frozen acceptance.json. A criterion with no record is unknown, never a pass."""
    recorded = {}
    if "acceptance.json" in blobs:
        data = _parse_json(rid, "acceptance.json", blobs["acceptance.json"])
        if not isinstance(data, dict):
            raise BadInput(f"repeat {rid}: acceptance.json is not an object")
        recorded = data
    status = {}
    for c in HARD_CRITERIA:
        v = recorded.get(c)
        status[c] = v if v in ("pass", "fail") else "unknown"
    if false_positives is not None:
        if false_positives > 0:
            status["L8"] = "fail"
        elif status["L8"] == "unknown":
            status["L8"] = "pass"
    values = set(status.values())
    overall = "fail" if "fail" in values else ("unknown" if "unknown" in values else "pass")
    return {"criteria": status, "overall": overall}


# ---------------------------------------------------------------- decision (4.5)

def decide(baseline: list[float], candidate: list[float], *,
           baseline_hard_failure: bool, candidate_hard_failure: bool) -> str:
    """Pre-registered rule: the candidate is better only if its median exceeds the
    baseline's, its worst repeat is at least the baseline's median, and it had no hard
    part-B failure in any repeat. Worse is the mirror. Anything else: no difference
    shown. Pass hard_failure=True for an arm with any unknown criterion, too."""
    if not baseline or not candidate:
        raise ValueError("both arms need at least one repeat")
    med_a, med_b = statistics.median(baseline), statistics.median(candidate)
    if med_b > med_a and min(candidate) >= med_a and not candidate_hard_failure:
        return "better"
    if med_a > med_b and min(baseline) >= med_b and not baseline_hard_failure:
        return "worse"
    return "no_difference_shown"


def score(manifest_path: Path, mapping_path: Path, *, baseline: str = "A",
          candidate: str = "B", min_repeats: int = 3) -> dict:
    manifest = load_manifest(manifest_path)
    verified = verify_freeze(manifest, manifest_path.resolve().parent)
    arms = {}
    for r in manifest["repeats"]:
        arms.setdefault(r["arm"], []).append(r["repeat_id"])
    for arm in (baseline, candidate):
        if len(arms.get(arm, [])) < min_repeats:
            raise Refusal(f"arm {arm} has fewer than {min_repeats} frozen repeats")
    mapping_resolved = mapping_path.resolve()
    if any(v["export"] == mapping_resolved or v["export"] in mapping_resolved.parents
           for v in verified.values()):
        raise Refusal("the sealed mapping sits inside a run export")
    # The seal holds: only now is the mapping read.
    mapping = read_sealed_mapping(mapping_path, manifest["mapping_sha256"])
    repeats = []
    for r in manifest["repeats"]:
        row = score_repeat(r["repeat_id"], verified[r["repeat_id"]]["blobs"], mapping)
        row["arm"] = r["arm"]
        repeats.append(row)

    per_arm = {}
    for arm, ids in arms.items():
        rows = [x for x in repeats if x["arm"] == arm]
        values = [x["primary_verified_mechanisms"] for x in rows]
        per_arm[arm] = {"repeats": ids, "values": values,
                        "median": statistics.median(values),
                        "range": [min(values), max(values)],
                        "hard_failure_any": any(x["hard_failures"]["overall"] != "pass"
                                                for x in rows)}
    a, b = per_arm[baseline], per_arm[candidate]
    verdict = decide(a["values"], b["values"], baseline_hard_failure=a["hard_failure_any"],
                     candidate_hard_failure=b["hard_failure_any"])
    return {
        "schema": OUTPUT_SCHEMA,
        "freeze_manifest_sha256": sha256_bytes(manifest_path.read_bytes()),
        "mapping_sha256": manifest["mapping_sha256"],
        "repeats": repeats,
        "arms": per_arm,
        "decision": {"baseline": baseline, "candidate": candidate, "verdict": verdict,
                     "note": f"n={len(b['values'])}/{len(a['values'])} per arm: a screening "
                             "result, not a significance claim"},
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--manifest", required=True, type=Path, help="freeze manifest JSON")
    ap.add_argument("--mapping", required=True, type=Path, help="sealed mapping JSON")
    ap.add_argument("--out", required=True, type=Path, help="metrics JSON to write")
    ap.add_argument("--baseline", default="A")
    ap.add_argument("--candidate", default="B")
    ap.add_argument("--min-repeats", type=int, default=3)
    args = ap.parse_args(argv)
    try:
        manifest = load_manifest(args.manifest)
        out = args.out.resolve()
        base = args.manifest.resolve().parent
        for r in manifest["repeats"]:
            export = (base / str(r.get("export_dir") or "")).resolve()
            if out == export or export in out.parents:
                raise Refusal("the output path is inside a frozen export")
        report = score(args.manifest, args.mapping, baseline=args.baseline,
                       candidate=args.candidate, min_repeats=args.min_repeats)
    except Refusal as exc:
        print(f"ar10_scorer: refused: {exc}", file=sys.stderr)
        return EXIT_REFUSED
    except BadInput as exc:
        print(f"ar10_scorer: bad input: {exc}", file=sys.stderr)
        return EXIT_BAD_INPUT
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    d = report["decision"]
    print(f"ar10_scorer: scored {len(report['repeats'])} repeats; "
          f"{d['candidate']} vs {d['baseline']}: {d['verdict']}")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
