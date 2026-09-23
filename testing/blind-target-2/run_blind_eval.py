#!/usr/bin/env python3
"""
Blind-target-2 end-to-end eval harness.

Runs curated exchanges through the REAL orchestrator and produces a
scorecard: per-exchange results, aggregate timing/token cost, and a
`controls_clean` metric -- AND (RB-8 / INV-1 fix) actually exercises the
quarantine gate by calling harness.report_generator.generate_markdown_report
(the sole caller of confirmation_gate.should_quarantine_as_lead) over what
got persisted, so `reporting.quarantine_unverified_leads` is no longer a
no-op on this driver's output. The manifest records which findings were
quarantined-as-leads vs surfaced-as-findings.

RB-8 refactor: every module-level side effect from the prior version
(loading config.yaml, mutating harness.store._DB_PATH, constructing an
Orchestrator, calling asyncio.run) has been moved into functions. Importing
this module now runs nothing and touches no global store/cache state --
`if __name__ == "__main__":` guards the only place that still runs the live
default (fresh state+cache DBs under C:\\tmp, curated routing, live Ollama,
the real blind_eval_exchanges.json). This makes the module safely importable
for offline tests with a stubbed model and synthetic exchanges (see
testing/test_blind_eval_harness.py), which was previously impossible.

Ground truth for the real blind_eval_exchanges.json (derived by hand over
HTTP only, no app.py/answer-key read):
  - POSITIVE: IDOR + excessive data exposure on GET /api/tickets/{id}
    (bob reads ticket#1 he doesn't own; internal_notes leaked to a customer)
  - minor: client-controlled `department` on ticket create
  - CONTROLS (true negatives): comment authz 403, write methods 405,
    high-entropy tokens, own-ticket reads.
The question this run answers: does the harness independently flag the IDOR
on a target the model has never seen?

Measurement knobs (env vars, all default to the precision-measurement
setting), injected into the config dict at RUNTIME -- never baked into
harness/config.yaml, which stays at its committed safe defaults:
  HARNESS_FAIL_OPEN_MODE        curated | all           (default: curated)
  HARNESS_QUARANTINE_LEADS      1 | 0                   (default: 1)
  HARNESS_CROSS_IDENTITY_REJECT 1 | 0                   (default: 0)
    P4 (RB-8): turns on the cross-identity REJECT->downgrade path
    (validators.cross_identity.enabled) for the live run. cross_identity's
    own validator requires validators.active_enabled (see config.yaml's
    comment on that knob), so this ALSO turns active_enabled on -- there is
    no narrower toggle for "just the REJECT path" in this harness today.
    That means this knob sends live (scoped, GET-only unless
    allow_mutating_replay is separately set) requests at the target and
    must stay OFF for any offline/stubbed run. Default OFF here; the owner
    opts in explicitly for a live run.
"""
from __future__ import annotations

import asyncio
import copy
import dataclasses
import json
import os
import statistics
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
HARNESS_DIR = PROJECT_ROOT / "harness"
BLIND_DIR = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# --- Defaults for the live CLI path (unchanged from the pre-refactor script) -
DEFAULT_EXCHANGES_PATH = BLIND_DIR / "blind_eval_exchanges.json"
DEFAULT_STATE_DB = r"C:\tmp\blind_eval_state.db"
DEFAULT_CACHE_DB = r"C:\tmp\blind_eval_cache.db"
DEFAULT_OUT_PATH = r"C:\tmp\blind_eval_results.json"

# Ground-truth labels (case-insensitive) treated as negative controls for
# the controls_clean metric -- an exchange whose own findings leave a
# SURFACED (non-quarantined, non-chain) finding on its url counts as a dirty
# control. A quarantined lead is fine; it is, by definition, not reported.
# "confirmed_secure" is the label the real curated blind_eval_exchanges.json
# actually uses (verified by inspecting its ground_truth values -- that file
# is the hand-labeled curated corpus this driver has always read, distinct
# from the answer-key file HARD SAFEGUARDS forbid reading); the others cover
# synthetic/offline fixtures and any future corpus using different wording.
CONTROL_GROUND_TRUTH_LABELS = frozenset({
    "confirmed_secure", "control", "secure", "negative_control", "true_negative",
})

# B2-3 CORRECTIONS (item 4): a FIXED allow-set of ground-truth labels that
# count as a vuln for the issue-level fairness exclusion below -- NOT "any
# label that isn't a control". "confirmed_vuln" is the label the real
# curated blind_eval_exchanges.json actually uses for its two positive
# exchanges (verified by inspecting its ground_truth values, same as
# CONTROL_GROUND_TRUTH_LABELS above). Deliberately excludes "inconclusive"
# -- an inconclusive exchange sharing a (method,url) with a control must
# NOT remove that control from the fair denominator (see item 4 test).
_VULN_LABELS = frozenset({"confirmed_vuln"})


# ---------------------------------------------------------------------------
# Config / exchange loading -- pure functions, no side effects.
# ---------------------------------------------------------------------------

def build_eval_config(
    *,
    fail_open_mode: str = "curated",
    quarantine_leads: bool = True,
    cross_identity_reject: bool = False,
    base_config: dict | None = None,
) -> dict:
    """Load harness/config.yaml (or start from `base_config`) and inject the
    measurement overrides explicitly, so the exact mode used is provable
    from the manifest rather than depending on config.local.yaml reaching
    this runner. `base_config` is deep-copied before overrides are applied
    -- callers (including repeated test/multi-run invocations) never share
    or mutate a common dict.
    """
    if base_config is None:
        import yaml
        with open(HARNESS_DIR / "config.yaml") as f:
            base_config = yaml.safe_load(f)
    config = copy.deepcopy(base_config)
    config.setdefault("coordinator", {})["fail_open_mode"] = fail_open_mode
    config.setdefault("reporting", {})["quarantine_unverified_leads"] = quarantine_leads
    if cross_identity_reject:
        v = config.setdefault("validators", {})
        v["active_enabled"] = True
        v.setdefault("cross_identity", {})["enabled"] = True
    return config


def load_exchanges(path: Path | str = DEFAULT_EXCHANGES_PATH) -> list[dict]:
    with open(path) as f:
        return json.load(f)


def exchange_from_dict(e: dict):
    from harness.models import HttpExchange
    return HttpExchange(
        url=e["url"], method=e["method"], request_headers=e["request_headers"],
        request_body=e["request_body"], response_status=e["response_status"],
        response_headers=e["response_headers"], response_body=e["response_body"],
    )


def default_orchestrator_factory(config: dict):
    """The live/default orchestrator: a real, unstubbed harness.orchestrator.
    Orchestrator. Tests inject a different factory (real Orchestrator +
    stubbed model boundary, matching harness/test_pipeline_gate.py's
    _SilentModel pattern) instead of using this."""
    from harness.orchestrator import Orchestrator
    return Orchestrator(config)


# ---------------------------------------------------------------------------
# Running exchanges through the orchestrator.
# ---------------------------------------------------------------------------

@dataclass
class ExchangeOutcome:
    idx: int
    label: str
    ground_truth: str
    dispatched_agents: list[str]
    findings: list[dict]
    validation_reports: list[dict]
    elapsed_seconds: float
    tokens_spent: int
    error: Optional[str]


async def run_exchanges(
    exchanges: list[dict],
    orch,
    *,
    force_agents: list[str] | None = None,
    on_result: Callable[[ExchangeOutcome], None] | None = None,
) -> list[ExchangeOutcome]:
    """Run every exchange through orch.analyze(), sequentially (matches the
    original script's behavior; later exchanges' prior_context legitimately
    depends on earlier ones having already persisted). Does NOT itself
    persist or build a report -- orch.analyze() already persists surviving
    findings via harness.store.persist_findings as part of its normal
    pipeline (orchestrator_detect.py), which is what makes
    build_scorecard's store.all_host_findings/generate_markdown_report call
    see real, stored findings afterward, not a parallel hand-rolled copy of
    them.
    """
    outcomes: list[ExchangeOutcome] = []
    prev_tokens = 0
    for idx, e in enumerate(exchanges):
        ex = exchange_from_dict(e)
        t0 = time.monotonic()
        try:
            r = await orch.analyze(ex, force_agents=force_agents)
            el = time.monotonic() - t0
            findings = [f.model_dump() for rep in r.agent_reports for f in rep.findings]
            for f in findings:
                f.setdefault("url", ex.url)
            vrs = [v.model_dump() for v in r.validation_reports]
            spent = max(r.effort_spent_tokens - prev_tokens, 0)
            prev_tokens = r.effort_spent_tokens
            outcome = ExchangeOutcome(
                idx=idx, label=e.get("label", "") or "", ground_truth=e.get("ground_truth", "?") or "?",
                dispatched_agents=list(r.dispatched_agents), findings=findings,
                validation_reports=vrs, elapsed_seconds=round(el, 3),
                tokens_spent=spent, error=None,
            )
        except Exception as exc:
            el = time.monotonic() - t0
            outcome = ExchangeOutcome(
                idx=idx, label=e.get("label", "") or "", ground_truth=e.get("ground_truth", "?") or "?",
                dispatched_agents=[], findings=[], validation_reports=[],
                elapsed_seconds=round(el, 3), tokens_spent=0, error=repr(exc),
            )
        outcomes.append(outcome)
        if on_result is not None:
            on_result(outcome)
    return outcomes


# ---------------------------------------------------------------------------
# Scorecard: this is the INV-1 fix -- generate_markdown_report (the sole
# caller of confirmation_gate.should_quarantine_as_lead) is actually invoked
# over what got persisted, so quarantine_unverified_leads is no longer a
# no-op on this driver's output.
# ---------------------------------------------------------------------------

def build_scorecard(
    outcomes: list[ExchangeOutcome],
    exchanges: list[dict],
    *,
    quarantine_leads: bool,
    fail_open_mode: str,
    config_fingerprint_value: str,
    fail_open_stats_before: dict,
    fail_open_stats_final: dict,
    cross_identity_reject: bool = False,
    gate_low_confidence_generic: bool = False,
    generic_confidence_floor: float = 0.5,
) -> dict:
    from harness import store
    from harness.report_generator import generate_markdown_report
    from harness.confirmation_gate import should_quarantine_as_lead
    from harness.issues import group_findings_into_issues, _is_dependency_class

    hosts: list[str] = []
    for e in exchanges:
        h = store.host_of(e["url"])
        if h not in hosts:
            hosts.append(h)

    all_stored: list[dict] = []
    markdown_reports: dict[str, str] = {}
    for host in hosts:
        stored = store.all_host_findings(host)
        all_stored.extend(stored)
        markdown_reports[host] = generate_markdown_report(
            host, stored, quarantine_leads=quarantine_leads,
            gate_low_confidence_generic=gate_low_confidence_generic,
            generic_confidence_floor=generic_confidence_floor,
        )

    individual_stored = [f for f in all_stored
                          if not f["vulnerability_class"].startswith("potential-attack-chain:")]
    # Mirror generate_markdown_report's own branch exactly (report_generator.py):
    # when quarantine_leads is False, NOTHING is routed to leads regardless of
    # should_quarantine_as_lead's verdict -- the knob must actually gate this,
    # not just be ignored by the scorecard's own counts.
    if quarantine_leads:
        quarantined = [f for f in individual_stored if should_quarantine_as_lead(f)]
        surfaced = [f for f in individual_stored if not should_quarantine_as_lead(f)]
    else:
        quarantined = []
        surfaced = list(individual_stored)

    control_urls = {e["url"] for e in exchanges
                     if (e.get("ground_truth") or "").lower() in CONTROL_GROUND_TRUTH_LABELS}
    dirty_controls = [f for f in surfaced if f.get("url") in control_urls]
    controls_clean = len(dirty_controls) == 0

    # --- B2-3: issue-level, per-exchange-fair controls_clean (ADDITIVE) ---
    # The raw metric above has known biases: (1) it counts RAW findings, so
    # N duplicate dependency/banner findings on one control URL inflate the
    # dirty count as N instead of 1 real issue; (2) it attributed a finding
    # to "the control" by URL string match alone, so a DELETE control could
    # be silently dropped from the denominator whenever its URL was also hit
    # by a GET vuln exchange, hiding a real false positive on the control
    # itself; (3) it treated ANY non-control ground-truth label (including
    # "inconclusive") as a vuln for that exclusion. Fixed below, without
    # touching the raw fields above (kept for comparability).
    #
    # Findings carry both a `url` AND a `method` (see harness/store.py's
    # all_host_findings), so attribution is keyed on the (method, url) pair,
    # not the url alone -- a GET vuln exchange and a DELETE control that
    # happen to share a URL are distinguishable, and only a control whose
    # OWN (method, url) exactly matches a vuln exchange's (method, url) is
    # excluded from the fair denominator (neither asserted clean nor blamed
    # on the control -- genuinely ambiguous attribution).
    # Method normalized to uppercase AT CONSTRUCTION (not just downstream at
    # finding-attribution time) -- otherwise a control record with
    # method="delete" and a vuln with method="DELETE" on the same url fail
    # to intersect, the control wrongly stays in the fair denominator, and
    # the vuln's (uppercased) finding then falsely dirties it: the exact
    # hidden-FP bug this correction exists to prevent, just reintroduced via
    # case mismatch instead of a bare-url match.
    control_pairs = {((e.get("method") or "").upper(), e["url"]) for e in exchanges
                      if (e.get("ground_truth") or "").lower() in CONTROL_GROUND_TRUTH_LABELS}
    vuln_pairs = {((e.get("method") or "").upper(), e["url"]) for e in exchanges
                  if (e.get("ground_truth") or "").lower() in _VULN_LABELS}
    ambiguous_control_pairs = control_pairs & vuln_pairs
    fair_control_pairs = control_pairs - ambiguous_control_pairs
    fair_control_urls = {u for _m, u in fair_control_pairs}

    def _pair(f: dict) -> tuple[str, str]:
        return ((f.get("method") or "").upper(), f.get("url") or "")

    # DESIGN DECISION (item 12): host-wide dependency/banner findings are
    # host+component scoped, not endpoint-scoped (see harness/issues.py's
    # _is_dependency_class / issue_key, which already groups this family by
    # host+class only, dropping the endpoint and method). They must not mark
    # a specific control "dirty" -- surfaced separately below instead.
    endpoint_scoped_surfaced = [f for f in surfaced if not _is_dependency_class(f.get("vulnerability_class", ""))]
    dependency_surfaced = [f for f in surfaced if _is_dependency_class(f.get("vulnerability_class", ""))]

    fair_control_findings = [f for f in endpoint_scoped_surfaced if _pair(f) in fair_control_pairs]
    dirty_control_issues = group_findings_into_issues(fair_control_findings)
    controls_clean_issue_level = len(dirty_control_issues) == 0

    # finding (by identity) -> the issue id it landed in, so the per-control
    # driver list below can report which issue(s) touch each dirty control.
    finding_issue_id: dict[int, str] = {}
    for iss in dirty_control_issues:
        for m in iss.members:
            finding_issue_id[id(m)] = iss.issue_id

    dirty_pairs_seen: list[tuple[str, str]] = []
    findings_by_pair: dict[tuple[str, str], list[dict]] = {}
    for f in fair_control_findings:
        pair = _pair(f)
        if pair not in findings_by_pair:
            findings_by_pair[pair] = []
            dirty_pairs_seen.append(pair)
        findings_by_pair[pair].append(f)

    # Item 7/9: ONE entry per dirty control (keyed by method+url), not per
    # issue -- a host-wide issue used to become one entry with only its
    # first url; now every dirty control gets its own entry listing the
    # issue id(s), vulnerability classes, and agents observed on it.
    per_control_drivers = [
        {
            "method": method,
            "url": url,
            "issue_ids": sorted({finding_issue_id.get(id(m)) for m in members} - {None}),
            "vulnerability_classes": sorted({m.get("vulnerability_class") or "" for m in members} - {""}),
            "agents": sorted({m.get("agent") or "" for m in members} - {""}),
            "finding_count": len(members),
        }
        for (method, url), members in ((p, findings_by_pair[p]) for p in dirty_pairs_seen)
    ]
    n_controls_issue_level = len(fair_control_pairs)
    n_controls_clean_issue_level = n_controls_issue_level - len(dirty_pairs_seen)

    # Item 12: dependency/banner findings observed on a (fair) control URL,
    # reported separately -- informational, never dirties a specific control.
    host_level_issues_on_controls = [
        {
            "issue_id": iss.issue_id,
            "vulnerability_class": iss.vulnerability_class,
            "affected_instances": iss.affected_instances,
            "agents": sorted({m.get("agent") or "" for m in iss.members} - {""}),
            "finding_count": len(iss.members),
        }
        for iss in group_findings_into_issues(
            [f for f in dependency_surfaced if (f.get("url") or "") in fair_control_urls]
        )
    ]

    elapsed = [o.elapsed_seconds for o in outcomes]
    tokens = [o.tokens_spent for o in outcomes]
    timing = {
        "total_elapsed_seconds": round(sum(elapsed), 3),
        "mean_elapsed_seconds": round(sum(elapsed) / len(elapsed), 3) if elapsed else 0.0,
        "max_elapsed_seconds": round(max(elapsed), 3) if elapsed else 0.0,
        "total_tokens_spent": sum(tokens),
    }

    return {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "config_fingerprint": config_fingerprint_value,
        "fail_open_mode": fail_open_mode,
        "quarantine_leads": quarantine_leads,
        # B2-5: informational, mirrors "quarantine_leads" above -- whether the
        # low-confidence generic-class gate was armed for the markdown report
        # this run produced (does not affect n_quarantined_leads/n_surfaced_
        # findings/controls_clean above, which stay on B2-3/B2-3b's existing
        # should_quarantine_as_lead-only accounting).
        "gate_low_confidence_generic": gate_low_confidence_generic,
        # B2-4: records whether the deterministic cross-identity REJECT/downgrade
        # path (harness/orchestrator_confirm.py's inline block, NOT gated by any
        # config flag) was even reachable this run -- i.e. whether the active
        # cross_identity validator was armed at all. "REJECT on" == the validator
        # ran and could downgrade a finding; "REJECT off" == it never appeared in
        # for_finding's output, so the block never fired. Makes a REJECT-on run
        # self-describing in its own manifest/scorecard.
        "cross_identity_reject": cross_identity_reject,
        "fail_open_stats_before": fail_open_stats_before,
        "fail_open_stats_final": fail_open_stats_final,
        "hosts": hosts,
        "n_exchanges": len(outcomes),
        "n_errors": sum(1 for o in outcomes if o.error),
        "n_findings_total": sum(len(o.findings) for o in outcomes),
        "n_quarantined_leads": len(quarantined),
        "n_surfaced_findings": len(surfaced),
        "quarantined_finding_ids": [f.get("finding_id") or f.get("fingerprint") for f in quarantined],
        "surfaced_finding_ids": [f.get("finding_id") or f.get("fingerprint") for f in surfaced],
        "n_controls": len(control_urls),
        "controls_clean": controls_clean,
        "dirty_controls": [{"url": f.get("url"), "vulnerability_class": f.get("vulnerability_class")}
                            for f in dirty_controls],
        # B2-3: fairer, issue-level view alongside the raw metric above --
        # keyed on (method, url) not url alone, deduped via
        # harness.issues.group_findings_into_issues, excluding (method, url)
        # pairs ambiguous with a labeled vuln exchange from the clean
        # denominator, and excluding host-wide dependency/banner findings
        # from the per-control dirty/clean decision entirely (item 12 --
        # see host_level_issues_on_controls below).
        "n_controls_issue_level": n_controls_issue_level,
        "n_controls_clean_issue_level": n_controls_clean_issue_level,
        "n_controls_excluded_ambiguous": len(ambiguous_control_pairs),
        "controls_clean_issue_level": controls_clean_issue_level,
        "per_control_drivers": per_control_drivers,
        "host_level_issues_on_controls": host_level_issues_on_controls,
        "timing": timing,
        "markdown_reports": markdown_reports,
        "results": [dataclasses.asdict(o) for o in outcomes],
    }


# ---------------------------------------------------------------------------
# One full pass (fresh state+cache DBs -> exchanges -> scorecard) and
# multi-run variance aggregation over N passes.
# ---------------------------------------------------------------------------

def run_once(
    exchanges: list[dict],
    *,
    config: dict,
    state_db: str | Path,
    cache_db: str | Path,
    orchestrator_factory: Callable[[dict], Any] = default_orchestrator_factory,
    force_agents: list[str] | None = None,
    on_result: Callable[[ExchangeOutcome], None] | None = None,
) -> dict:
    """One complete eval pass against fresh state+cache DBs: build (or
    receive) an orchestrator, run every exchange, then build the scorecard
    from what actually got persisted. DB paths, the orchestrator and the
    exchange source are all caller-supplied -- this is what makes the
    module importable/testable: nothing here runs or mutates global state
    until this function (or _live_main, guarded below) is actually called.
    """
    from harness import store
    from harness import cache as cache_mod
    from harness.coordinator import fail_open_stats, reset_fail_open_stats
    from harness.config_schema import config_fingerprint

    store._DB_PATH = str(state_db)
    cache_mod.init_cache(db_path=str(cache_db))

    fingerprint = config_fingerprint(config)
    reset_fail_open_stats()
    orch = orchestrator_factory(config)
    stats_before = fail_open_stats()

    outcomes = asyncio.run(run_exchanges(exchanges, orch, force_agents=force_agents, on_result=on_result))

    stats_final = fail_open_stats()
    validators_cfg = config.get("validators") or {}
    cross_identity_reject = bool(
        validators_cfg.get("active_enabled")
        and (validators_cfg.get("cross_identity") or {}).get("enabled")
    )
    reporting_cfg = config.get("reporting") or {}
    return build_scorecard(
        outcomes, exchanges,
        quarantine_leads=bool(reporting_cfg.get("quarantine_unverified_leads", False)),
        fail_open_mode=str((config.get("coordinator") or {}).get("fail_open_mode", "")),
        config_fingerprint_value=fingerprint,
        fail_open_stats_before=stats_before,
        fail_open_stats_final=stats_final,
        cross_identity_reject=cross_identity_reject,
        gate_low_confidence_generic=bool(reporting_cfg.get("gate_low_confidence_generic", False)),
        generic_confidence_floor=float(reporting_cfg.get("generic_confidence_floor", 0.5)),
    )


# Metrics aggregated across a multi-run variance pass (P3). Population
# variance (statistics.pvariance) is used so a single-run call (n=1) still
# returns a defined 0.0 rather than raising -- statistics.variance requires
# n>=2. With a deterministic stub model, variance across runs is expected to
# be ~0; the point of this aggregation is that the field exists and is
# computed correctly, not that a stub disagrees with itself.
_VARIANCE_METRICS: list[tuple[str, Callable[[dict], float]]] = [
    ("n_findings_total", lambda sc: float(sc["n_findings_total"])),
    ("n_quarantined_leads", lambda sc: float(sc["n_quarantined_leads"])),
    ("n_surfaced_findings", lambda sc: float(sc["n_surfaced_findings"])),
    ("controls_clean", lambda sc: 1.0 if sc["controls_clean"] else 0.0),
    # Item 5: the issue-level (fair) metric RB-2b's >=5-run variance pass
    # actually needs to depend on, alongside the raw one above.
    ("controls_clean_issue_level", lambda sc: 1.0 if sc["controls_clean_issue_level"] else 0.0),
    ("n_controls_clean_issue_level", lambda sc: float(sc["n_controls_clean_issue_level"])),
    ("total_elapsed_seconds", lambda sc: float(sc["timing"]["total_elapsed_seconds"])),
    ("total_tokens_spent", lambda sc: float(sc["timing"]["total_tokens_spent"])),
]


def aggregate_variance(scorecards: list[dict]) -> dict:
    per_metric = {}
    for name, getter in _VARIANCE_METRICS:
        values = [getter(sc) for sc in scorecards]
        per_metric[name] = {
            "values": values,
            "mean": statistics.fmean(values) if values else 0.0,
            "variance": statistics.pvariance(values) if values else 0.0,
        }
    return {"n_runs": len(scorecards), "variance": per_metric, "runs": scorecards}


def run_eval_n_times(
    exchanges: list[dict],
    *,
    config_builder: Callable[[], dict],
    db_dir: str | Path,
    n_runs: int = 5,
    orchestrator_factory: Callable[[dict], Any] = default_orchestrator_factory,
    force_agents: list[str] | None = None,
) -> dict:
    """Run `run_once` `n_runs` times, each against its own fresh state+cache
    DB (so runs are independent, not accumulating state into one another),
    and aggregate per-metric mean/variance (P3)."""
    scorecards = []
    for i in range(n_runs):
        run_dir = Path(db_dir) / f"run{i}"
        run_dir.mkdir(parents=True, exist_ok=True)
        scorecards.append(run_once(
            exchanges,
            config=config_builder(),
            state_db=run_dir / "state.db",
            cache_db=run_dir / "cache.db",
            orchestrator_factory=orchestrator_factory,
            force_agents=force_agents,
        ))
    return aggregate_variance(scorecards)


# ---------------------------------------------------------------------------
# Live entrypoint -- the ONLY code that runs on import of this module is
# below this guard. Default behavior matches the pre-refactor script: fresh
# state+cache DBs under C:\tmp, curated routing, quarantine on, live Ollama,
# the real curated blind_eval_exchanges.json, normal (unforced) agent
# routing.
# ---------------------------------------------------------------------------

def _live_main() -> None:
    fail_open_mode = os.environ.get("HARNESS_FAIL_OPEN_MODE", "curated")
    quarantine_leads = os.environ.get("HARNESS_QUARANTINE_LEADS", "1") not in ("0", "false", "no")
    cross_identity_reject = os.environ.get("HARNESS_CROSS_IDENTITY_REJECT", "0") not in ("0", "false", "no")

    config = build_eval_config(
        fail_open_mode=fail_open_mode, quarantine_leads=quarantine_leads,
        cross_identity_reject=cross_identity_reject,
    )

    from harness.config_schema import config_fingerprint
    fingerprint = config_fingerprint(config)
    print(f"[config] fail_open_mode={fail_open_mode!r}  quarantine_leads={quarantine_leads}  "
          f"cross_identity_reject={cross_identity_reject}  fingerprint={fingerprint[:16]}")

    exchanges = load_exchanges(DEFAULT_EXCHANGES_PATH)
    print(f"[*] {len(exchanges)} curated exchanges through REAL orchestrator (live Ollama)\n")

    def _print_progress(o: ExchangeOutcome) -> None:
        print(f"[{o.idx:2d}] {o.elapsed_seconds:6.1f}s  gt={o.ground_truth:16s} {o.label[:44]}")
        print(f"      agents: {', '.join(o.dispatched_agents) or 'none'}")
        for f in o.findings:
            print(f"        - {f['vulnerability_class']} (conf={f['confidence']}, sev={f['severity']})")
        for v in o.validation_reports:
            if v.get("confirmed"):
                print(f"        VALIDATOR {v['validator']} CONFIRMED {v.get('finding_class')}")
        if o.error:
            print(f"[{o.idx:2d}] ERROR {o.error}")

    scorecard = run_once(
        exchanges, config=config, state_db=DEFAULT_STATE_DB, cache_db=DEFAULT_CACHE_DB,
        on_result=_print_progress,
    )

    json.dump(scorecard, open(DEFAULT_OUT_PATH, "w"), indent=2)
    print("\n" + "=" * 68)
    print(f"exchanges: {scorecard['n_exchanges']} | total findings: {scorecard['n_findings_total']} | "
          f"errors: {scorecard['n_errors']}")
    print(f"surfaced: {scorecard['n_surfaced_findings']} | quarantined-as-leads: {scorecard['n_quarantined_leads']} "
          f"| controls_clean: {scorecard['controls_clean']} ({scorecard['n_controls']} control(s))")
    print(f"controls_clean_issue_level: {scorecard['controls_clean_issue_level']} "
          f"({scorecard['n_controls_clean_issue_level']}/{scorecard['n_controls_issue_level']} clean, "
          f"{scorecard['n_controls_excluded_ambiguous']} excluded ambiguous)")
    print(f"fail-open triggered: {scorecard['fail_open_stats_final']['count']} times  (mode={fail_open_mode!r})")
    print(f"cross_identity_reject: {scorecard['cross_identity_reject']}")
    print(f"timing: {scorecard['timing']}")
    print(f"results -> {DEFAULT_OUT_PATH}")


if __name__ == "__main__":
    _live_main()
