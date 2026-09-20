"""
score.py -- unified detection scorer (SESSION_4_PLAN.md T2.1).

Emits precision / recall / F1 PER OWASP category from a corpus of labeled
exchanges, on a pinned model, reproducibly -- the one number the field
comparison hinges on. Consolidates the ad-hoc runners (test-target/bench.py,
the blind-kit driver, blind-target-2, juiceshop) behind one output shape.

Scoring is at the EXCHANGE level, per category:
  recall(C)    = (TP-labeled exchanges in C that produced >=1 finding of C)
                 / (TP-labeled exchanges in C)
  precision(C) = (exchanges whose ground truth is C that produced a finding of C)
                 / (all exchanges that produced any finding of C)
  F1(C)        = harmonic mean of the two.

The heavy fixture read (real agent findings, cached by detection_fixture.py) is
an adapter kept OUT of the scoring math, so the math is unit-tested on synthetic
data with no model/GPU/fixture (testing/test_score.py). Producing the real
number needs the fixture built once on a machine with the local model:
    cd testing/test-target && python detection_fixture.py build   # ~2h, GPU
then:
    cd testing && python score.py --corpus test-target --from-cache

CLI:
  python score.py --corpus test-target --from-cache
  python score.py --corpus test-target --from-cache --fail-under-recall 0.80 --json out.json
"""
from __future__ import annotations
import argparse
import asyncio
import json
import sys
from pathlib import Path

# --- OWASP 2021 taxonomy -----------------------------------------------------
# Ordered most-specific -> most-general: classify() returns the FIRST category
# whose any keyword is a substring of the finding's vulnerability_class, so the
# broad "injection" bucket (A03) is matched last. This mapping is deliberately
# simple and TUNABLE -- calibrating it is part of finishing T2 (blind-target-2).
_CATEGORY_KEYWORDS: list[tuple[str, list[str]]] = [
    ("A10:SSRF", ["ssrf", "server-side request", "server side request", "request forgery"]),
    ("A01:Broken-Access-Control", ["idor", "insecure direct object", "object-level", "object level",
        "bola", "broken access control", "access control", "missing authorization", "unauthorized access",
        "authorization", "authz", "path traversal", "traversal",
        "directory traversal", "lfi", "file inclusion", "forced browsing", "privilege escalation"]),
    ("A07:Auth-Failures", ["jwt", "auth bypass", "authentication bypass", "session fixation",
        "weak password", "mfa", "alg none", "signature bypass", "credential stuffing"]),
    ("A04:Insecure-Design", ["business logic", "business-logic", "workflow abuse", "insecure design"]),
    ("A08:Integrity-Failures", ["deserialization", "insecure deserial", "supply chain", "integrity"]),
    ("A06:Vulnerable-Components", ["vulnerable component", "outdated component", "known vulnerability",
        "cve-", "ghsa-", "dependency"]),
    ("A02:Cryptographic-Failures", ["cryptographic", "weak cipher", "cleartext", "weak hash", "tls"]),
    ("A05:Security-Misconfiguration", ["misconfig", "cors", "csp", "security header", "default credential",
        "directory listing", "verbose error", "open redirect", "sensitive exposure", "information disclosure"]),
    ("A09:Logging-Failures", ["logging failure", "insufficient logging", "monitoring failure"]),
    ("A03:Injection", ["sql", "sqli", "xss", "cross-site script", "cross site script", "scripting",
        "command injection", "os command", "nosql", "ssti", "template injection", "ldap injection",
        "header injection", "injection"]),
]

# Ground-truth category per test-target label. Derived from bench.py's KEYWORDS
# plus an explicit OWASP assignment. TP8 excluded (race condition, not provable
# from one sequential exchange) -- matches bench.py. TN* labels are benign.
_LABEL_CATEGORY: dict[str, str] = {
    "TP1": "A03:Injection", "TP2": "A03:Injection",
    "TP3": "A01:Broken-Access-Control", "TP4": "A01:Broken-Access-Control",
    "TP5": "A03:Injection", "TP6": "A03:Injection",
    "TP7": "A04:Insecure-Design",
    "TP9": "A10:SSRF",
    "TP10": "A01:Broken-Access-Control",
    "TP11": "A07:Auth-Failures",
    "TP12": "A05:Security-Misconfiguration",
}


def _norm(s: str) -> str:
    """Lower-case and treat _ and - as spaces, so class names in any separator
    style (sql_injection, business-logic, "SQL injection") match one keyword."""
    return (s or "").lower().replace("_", " ").replace("-", " ")


def classify(vulnerability_class: str) -> str | None:
    """Map a finding's vulnerability_class to an OWASP category, or None."""
    c = _norm(vulnerability_class)
    for category, keywords in _CATEGORY_KEYWORDS:
        if any(_norm(k) in c for k in keywords):
            return category
    return None


# W-8/W-23: this scorer answers ONE question -- did the harness produce a
# finding of the right CLASS for a labeled exchange? It never looks at a
# proof_id/case_id, so it cannot tell a proof-backed confirmation from a bare
# vulnerability_class string. Its precision/recall is exchange-level raw
# detection, not verified-issue precision/recall (that would require each
# counted finding to resolve to matching evidence -- see
# evaluation_integrity/evidence_audit.py, which is the offline reader built
# for that distinct question). Every report this module produces is tagged
# with this constant so a consumer cannot mistake one metric for the other.
METRIC_SCOPE = "raw_detection"


def score(labeled_findings: dict[str, list[str]],
          label_category: dict[str, str] | None = None) -> dict:
    """Pure scoring. `labeled_findings` maps each exchange label to the list of
    vulnerability_class strings the harness produced for it (TN* labels are
    benign; a label absent from `label_category` and not TP-mapped is benign).
    Returns per-category precision/recall/F1 + a micro-averaged overall.

    These are RAW DETECTION metrics (label vs. vulnerability_class string
    only -- see METRIC_SCOPE). They are not, and must not be reported as,
    verified-issue precision/recall."""
    label_category = label_category or _LABEL_CATEGORY
    predicted = {lab: set(filter(None, (classify(c) for c in classes)))
                 for lab, classes in labeled_findings.items()}

    categories = sorted(set(label_category.values()) | {c for cats in predicted.values() for c in cats})
    tp = {c: 0 for c in categories}
    fp = {c: 0 for c in categories}
    fn = {c: 0 for c in categories}
    support = {c: 0 for c in categories}

    for label, pred_cats in predicted.items():
        truth = label_category.get(label)  # None => benign / excluded
        if truth is not None:
            support[truth] += 1
            if truth in pred_cats:
                tp[truth] += 1
            else:
                fn[truth] += 1
        for pc in pred_cats:
            if pc != truth:
                fp[pc] += 1

    def _row(c: str) -> dict:
        prec = tp[c] / (tp[c] + fp[c]) if (tp[c] + fp[c]) else None
        rec = tp[c] / support[c] if support[c] else None
        f1 = (2 * prec * rec / (prec + rec)) if (prec and rec) else (0.0 if (prec is not None and rec is not None) else None)
        return {"category": c, "support": support[c], "tp": tp[c], "fp": fp[c], "fn": fn[c],
                "precision": round(prec, 3) if prec is not None else None,
                "recall": round(rec, 3) if rec is not None else None,
                "f1": round(f1, 3) if f1 is not None else None}

    rows = [_row(c) for c in categories]
    TP, FP, FN = sum(tp.values()), sum(fp.values()), sum(fn.values())
    micro_p = TP / (TP + FP) if (TP + FP) else 0.0
    micro_r = TP / (TP + FN) if (TP + FN) else 0.0
    micro_f1 = 2 * micro_p * micro_r / (micro_p + micro_r) if (micro_p + micro_r) else 0.0
    return {
        "metric_scope": METRIC_SCOPE,
        "per_category": rows,
        "overall": {"precision": round(micro_p, 3), "recall": round(micro_r, 3),
                    "f1": round(micro_f1, 3), "tp": TP, "fp": FP, "fn": FN},
    }


def format_table(report: dict, corpus: str, model: str) -> str:
    lines = [f"# Detection scorecard ({report.get('metric_scope', METRIC_SCOPE)}, "
             f"NOT verified-issue) -- corpus={corpus} model={model}", "",
             f"{'category':<30}{'support':>8}{'prec':>7}{'recall':>8}{'f1':>7}"]
    for r in report["per_category"]:
        def s(x): return "  n/a" if x is None else f"{x:.3f}"
        lines.append(f"{r['category']:<30}{r['support']:>8}{s(r['precision']):>7}{s(r['recall']):>8}{s(r['f1']):>7}")
    o = report["overall"]
    lines += ["", f"OVERALL (micro): precision={o['precision']:.3f} recall={o['recall']:.3f} "
              f"f1={o['f1']:.3f}  (tp={o['tp']} fp={o['fp']} fn={o['fn']})"]
    return "\n".join(lines)


_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


async def _collect_from_fixture(labels, refresh: bool, corpus: str,
                                conf: float, min_severity: str) -> tuple[dict[str, list[str]], Path | None]:
    """Adapter over detection_fixture.py (the cached real-agent findings). Kept
    async + lazily imported so importing score.py stays cheap and GPU-free.
    The fixture module lives in the corpus subdir (e.g. testing/test-target/).

    Two operating-point gates model what the analyst actually acts on:
      `conf`         -- confidence floor (low-confidence "I'm guessing" gated out)
      `min_severity` -- severity floor (info/low/medium/high/critical); the
                        biggest FP source here is low-severity missing-header
                        noise, so severity is the more effective knob.

    Returns (label -> classes, the fixture's own CACHE_PATH or None) -- the
    cache path is the actual "inputs" this scoring run reads, so the caller
    can bind a provenance hash to it (R01/R05)."""
    sys.path.insert(0, str(Path(__file__).resolve().parent / corpus))
    import detection_fixture as fx
    from harness import access_control_gate as acg
    labs = labels or sorted(fx.EXCHANGES_BY_LABEL)
    sev_floor = _SEVERITY_RANK.get(min_severity, 0)
    out: dict[str, list[str]] = {}
    for lab in labs:
        # The real pipeline applies deterministic gates AFTER the agents; the
        # fixture stores RAW agent output, so replicate the access-control
        # response gate here (reusing its own predicates, no drift) or the
        # fixture score overstates access-control FPs the shipped pipeline caps.
        status = (fx.EXCHANGES_BY_LABEL.get(lab) or {}).get("response_status")
        denied = status in acg._DENIAL_STATUSES
        classes: list[str] = []
        for agent in sorted(fx.dispatch_for(lab)):
            for f in await fx.findings_for(agent, lab, refresh=refresh):
                c = f.get("confidence")
                sev_name = (f.get("severity") or "info").lower()
                if denied and acg._is_access_control_class(f["class"]):
                    c, sev_name = 0.15, "low"
                sev = _SEVERITY_RANK.get(sev_name, 0)
                if (conf <= 0.0 or (c is not None and c >= conf)) and sev >= sev_floor:
                    classes.append(f["class"])
        out[lab] = classes
    cache_path = getattr(fx, "CACHE_PATH", None)
    return out, (Path(cache_path) if cache_path else None)


def _model_from_config() -> str:
    try:
        import yaml
        cfg = yaml.safe_load(open(Path(__file__).resolve().parent.parent / "harness" / "config.yaml"))
        return (cfg.get("agent_defaults") or {}).get("model", "unknown")
    except Exception:
        return "unknown"


def freshness_label(refresh: bool) -> str:
    """W-8/W-23: neither of score.py's two paths carries an invocation/
    revision/artifact-hash manifest (see evaluation_integrity/provenance.py
    for that contract), so neither may claim to be a fresh end-to-end
    pipeline run -- only the honest label differs between them."""
    return "live_refresh_no_manifest_binding" if refresh else "historical_cache_rescore"


def _git_revision() -> str:
    """Best-effort current HEAD sha; "unknown" (never a fabricated value) if
    git is unavailable or this isn't a checkout -- score_provenance.py itself
    stays git-subprocess-free by design, so the CALLER (this script) is
    where a real revision gets resolved."""
    import subprocess
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(Path(__file__).resolve().parent),
                             capture_output=True, text=True, timeout=5)
        rev = out.stdout.strip()
        return rev if out.returncode == 0 and rev else "unknown"
    except Exception:
        return "unknown"


def _ensure_harness_importable() -> None:
    """score.py is deliberately harness-free at import time (kept cheap/GPU-
    free for callers like testing/test_score.py that only need the pure
    scoring math); the repo root is only added to sys.path lazily, right
    before the one thing that needs harness.score_provenance (R01)."""
    repo_root = str(Path(__file__).resolve().parent.parent)
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)


def _score_provenance(*, corpus: str, conf: float, min_severity: str,
                      n_exchanges: int, cache_path: Path | None, refresh: bool) -> dict:
    """R01/R05: bind this score artifact to an auditable ScoreProvenance
    record -- the actual production consumer of harness.score_provenance,
    replacing "a score file exists" with an explicit fresh/historical/invalid
    label. `complete` is n_exchanges > 0 (the run actually scored something);
    `inputs_hash` is over the fixture's own real cache file when resolvable,
    "" (an id field score_provenance.py then classifies as invalid) when not
    -- never a fabricated hash for a file that wasn't actually read."""
    import uuid
    _ensure_harness_importable()
    from harness.score_provenance import ScoreProvenance, freshness_label as _score_freshness

    run_id = uuid.uuid4().hex
    inputs_hash = ""
    if cache_path is not None and cache_path.exists():
        inputs_hash = compute_inputs_hash([cache_path])
    revision = _git_revision()
    corpus_id = f"{corpus}@conf{conf}_sev{min_severity}"
    prov = ScoreProvenance(git_revision=revision, run_id=run_id, corpus_id=corpus_id,
                           inputs_hash=inputs_hash, complete=n_exchanges > 0)
    label = _score_freshness(prov, revision, corpus_id, expected_run_id=run_id,
                             expected_inputs_hash=inputs_hash)
    return {**prov.to_dict(), "evaluation_integrity_label": label}


def compute_inputs_hash(paths):
    """Lazily delegates to harness.score_provenance -- imported here (not at
    module load) so score.py's own import stays GPU/harness-free for callers
    that only need the pure scoring math (e.g. testing/test_score.py)."""
    _ensure_harness_importable()
    from harness.score_provenance import compute_inputs_hash as _cih
    return _cih(paths)


def main() -> int:
    ap = argparse.ArgumentParser(description="Per-OWASP-category detection scorer.")
    ap.add_argument("--corpus", default="test-target", help="corpus name (provenance label)")
    ap.add_argument("--from-cache", action="store_true",
                    help="score from the detection_fixture cache (no model calls)")
    ap.add_argument("--refresh", action="store_true", help="force-refresh fixture entries")
    ap.add_argument("--conf", type=float, default=0.0,
                    help="confidence gate: only count findings at/above it (analyst operating point)")
    ap.add_argument("--min-severity", default="info", choices=list(_SEVERITY_RANK),
                    help="severity floor: only count findings at/above it (default info = no gate)")
    ap.add_argument("--json", metavar="PATH", help="also write the full report as JSON")
    ap.add_argument("--fail-under-recall", type=float, default=None,
                    help="exit non-zero if overall (micro) recall is below this (CI gate)")
    ap.add_argument("--fail-under-precision", type=float, default=None,
                    help="exit non-zero if overall (micro) precision is below this (CI gate). "
                         "The critique's core metric: on a blind corpus this is what collapses, "
                         "so a blind precision floor is the gate that actually guards quality.")
    args = ap.parse_args()

    if not args.from_cache:
        print("Only --from-cache is wired today. A live run needs the fixture built first:\n"
              "  cd testing/test-target && python detection_fixture.py build", file=sys.stderr)
        return 2

    model = _model_from_config()
    labeled, cache_path = asyncio.run(
        _collect_from_fixture(None, args.refresh, args.corpus, args.conf, args.min_severity))
    report = score(labeled)
    # W-8/W-23: `--from-cache` (the only wired mode) reads detection_fixture.py's
    # saved cache; `--refresh` forces a live re-run of every label through the
    # real agents, but even then this has no manifest binding (invocation id,
    # git revision, config fingerprint -- see evaluation_integrity/provenance.py
    # for that contract) tying the result to a specific build. Neither path may
    # be reported as a fresh end-to-end efficacy claim; only the honest label
    # differs.
    freshness = freshness_label(args.refresh)
    report["provenance"] = {"corpus": args.corpus, "model": model, "n_exchanges": len(labeled),
                            "conf_gate": args.conf, "min_severity": args.min_severity,
                            "freshness": freshness,
                            "freshness_note": "not a fresh end-to-end pipeline run; "
                                              "no invocation/revision/artifact-hash manifest is bound to this result"}
    # R01/R05: the auditable evaluation_integrity contract's own freshness
    # label, bound to a real git revision, a fresh run_id, and a content hash
    # of the fixture cache file this run actually read -- score_provenance.py's
    # real production consumer, not just a hermetically-tested helper.
    try:
        report["provenance"]["score_provenance"] = _score_provenance(
            corpus=args.corpus, conf=args.conf, min_severity=args.min_severity,
            n_exchanges=len(labeled), cache_path=cache_path, refresh=args.refresh)
    except Exception as e:  # provenance stamping must never sink the score itself
        report["provenance"]["score_provenance_error"] = f"{type(e).__name__}: {e}"

    print(format_table(report, args.corpus, f"{model} @conf>={args.conf},sev>={args.min_severity}"))
    if args.json:
        json.dump(report, open(args.json, "w"), indent=2)
        print(f"\n(wrote {args.json})")

    failed = False
    if args.fail_under_recall is not None and report["overall"]["recall"] < args.fail_under_recall:
        print(f"\nFAIL: overall RAW DETECTION recall {report['overall']['recall']:.3f} < floor "
              f"{args.fail_under_recall} ({freshness})", file=sys.stderr)
        failed = True
    if args.fail_under_precision is not None and report["overall"]["precision"] < args.fail_under_precision:
        print(f"\nFAIL: overall RAW DETECTION precision {report['overall']['precision']:.3f} < floor "
              f"{args.fail_under_precision} ({freshness})", file=sys.stderr)
        failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
