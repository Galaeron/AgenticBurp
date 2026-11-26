"""orchestrator_review.py -- the Phase-0 capture-review passes (ARC-9 split of
orchestrator_helpers.py): `review_captured_exchanges` (model review of the captured
exchanges, bounded by a count and a deadline) and `universal_header_audit` (the
deterministic header validators over every capture). Moved verbatim.
"""
from __future__ import annotations

import asyncio
import functools
import hashlib
import time

from harness.models import Finding, HttpExchange
from harness.orchestrator_helpers import log


def _prompt_fits(resp) -> list[dict]:
    """What was cut from the model prompts of one capture's analysis to fit the
    context window (harness/prompt_budget.py): one {agent or stage, fits, elided}
    per prompt that was fitted; [] when every prompt was sent whole."""
    fitted = []
    for report in getattr(resp, "agent_reports", None) or []:
        fit = getattr(report, "prompt_fit", None)
        if fit:
            fitted.append({"agent": getattr(report, "agent", "?"), "fits": fit.get("fits"),
                           "elided": list(fit.get("elided") or [])})
    for outcome in getattr(resp, "stage_outcomes", None) or []:
        fit = getattr(outcome, "prompt_fit", None)
        if fit:
            fitted.append({"stage": getattr(outcome, "name", "?"), "fits": fit.get("fits"),
                           "elided": list(fit.get("elided") or [])})
    return fitted


def _review_bookkeeping(captured, seen, *, errors, stats, stopped_by, reviewed,
                        produced, grouped, elided, tier_counts, outcome_out,
                        report_left: bool = True) -> None:
    """The end of one review_captured_exchanges call, however it ended: log it, report
    what a bound left unreviewed (unless `report_left` is False: a review that pauses
    and is taken up again later leaves nothing behind), and add its counts to `stats` /
    `outcome_out`."""
    from harness import assessment_health
    from harness.assessment_health import review_frontier
    if reviewed:
        log.info("review_captured_exchanges: reviewed %d captured 2xx exchanges, "
                 "%d produced findings", reviewed, produced)
    if elided:
        log.info("review_captured_exchanges: %d capture(s) had model prompts cut to fit "
                 "the context window (review_stats.elided)", len(elided))
    remaining = 0
    if stopped_by and report_left:
        remaining = sum(1 for _ in review_frontier(captured, seen=set(seen)))
        if remaining:
            log.info("review_captured_exchanges: %s reached, %d captured exchange(s) "
                     "not reviewed", stopped_by, remaining)
            if errors is not None:
                errors.append({"phase": "capture_review",
                               "error": f"{stopped_by} reached: {remaining} captured "
                                        "exchange(s) not reviewed"})
    if stats is not None:
        base = assessment_health.new_review_stats()
        for name, empty in base.items():
            stats.setdefault(name, empty)
        stats["reviewed"] += reviewed
        stats["grouped"].extend(grouped)
        stats["elided"].extend(elided)
        stats["unreviewed"] += remaining
        for name, count in tier_counts.items():
            stats["by_tier"][name] = stats["by_tier"].get(name, 0) + count
    if outcome_out is not None:
        outcome_out.update(stopped_by=stopped_by, reviewed=reviewed, produced=produced,
                           remaining=remaining)


async def review_captured_exchanges(orch, state, captured, *, max_reviews: int = 200,
                                    run_context=None, seen=None, errors=None,
                                    deadline: float | None = None, stats: dict | None = None,
                                    group_identical: bool = True,
                                    resumed: dict | None = None, on_review=None,
                                    summary_out: dict | None = None,
                                    model_failed: set | None = None,
                                    journal_key=None, should_stop=None,
                                    outcome_out: dict | None = None,
                                    groups: dict | None = None,
                                    report_left: bool = True) -> int:
    """Phase 0.1: route every substantive 2xx captured during discovery through
    full content-level review and fold its findings into `state`.

    `role_crawl` fetches these response bodies but the access-matrix lens only
    asks "does this differ across identities?". A response correctly scoped to
    its authorized identity that itself leaks (a secret, PII, an internal path)
    produced NO signal there and was dropped without ever becoming an analyzable
    exchange -- a recall hole independent of what any one response contains. Here
    each capture goes through the full `analyze()` pipeline (agents + the
    deterministic confidential-info scan + validators), the same content review a
    captured Burp exchange gets, and its findings fold into the engagement state.

    `_from_discovery=True`: a capture is itself a discovery product, so its own
    analysis must not cascade into another scope-discovery pass (that guard also
    keeps this bounded -- one analyze per capture, not a recursive fan-out).

    `max_reviews` and `deadline` (a `time.monotonic()` value) bound the phase so a
    slow model cannot hold back chaining and coverage driving indefinitely. The
    bounds are checked before a capture is taken from the frontier, so an
    unreviewed capture is never marked seen; any left over are reported in
    `errors` as truncation, keeping the assessment incomplete rather than clean.

    Order (E1): authenticated JSON/API and write captures first, then anonymous
    ones, other non-HTML, and HTML last (see assessment_health.review_frontier).
    With `group_identical`, captures whose response content, identity and security
    headers match one already taken -- and that carry no input or object id of their
    own -- are covered by that representative instead of being reviewed again: each
    is marked in `seen` and recorded in `stats["grouped"]` as {capture, method,
    identity, covered_by, reason}; it is never reported as reviewed or as a finding.

    `stats`, when given, is added to (so one dict can span several calls):
    reviewed, grouped (the entries above), unreviewed (left by a bound),
    by_tier (reviewed per tier name) and elided: one {capture, method, prompts}
    per capture whose model prompts were cut to fit the context window
    (`ollama.num_ctx`), each prompt as {agent or stage, fits, elided parts}.

    E7 resume: `resumed` maps a capture's observation key (review_frontier's) to the
    findings an earlier, interrupted run got from it; such a capture skips
    `orch.analyze` and contributes those findings. `on_review(key, {"findings": [...]})`
    is called for each capture analyzed here, so a journal can record it. `summary_out`
    gets the count of captures taken from `resumed` under "resumed". `journal_key(ex)`,
    when given, is the key `resumed` and `on_review` use instead (the journal's
    credential-free RunJournal.exchange_key); `seen` and `model_failed` keep the
    observation key.

    `model_failed`, when given a set, gets the observation key of each capture whose
    analysis raised, had an agent report a `raw_error` (a model call that failed or
    was cut short by the circuit breaker), or had a stage fail (a failed critique
    ships its findings unreviewed). The capture stays in `seen`; a retry round
    discards it from there to review it again.

    `should_stop()`, when given, is asked before each capture is taken; a reason it
    returns ends the review like a bound does (harness/review_overlap.py stops a
    background review this way). A cancellation is a bound too: the capture being
    analyzed when it lands, and the captures grouped under it, are put back as
    unreviewed (out of `seen`, out of the counts), the leftovers are reported as
    above, and the cancellation is re-raised. `outcome_out`, when given a dict, gets
    {stopped_by, reviewed, produced, remaining} for this call.

    `groups`, when given a dict, carries `group_identical` across calls that share it
    (harness/review_overlap.py's IdleReview and the capture_review pass after it): each
    representative whose review finished is kept under its content key, and a later
    call groups an unseen capture with that content under it, as one call over all the
    captures would, instead of reviewing the same content again. `report_left=False`
    (a review that will be taken up again) reports nothing as left unreviewed: no
    truncation error, no `unreviewed` count, `remaining` 0.

    Returns the count of captured exchanges that yielded >=1 finding."""
    from harness import run_handoff
    _handoff = run_handoff.for_run(run_context)
    if _handoff is None:
        return await _review_captured_exchanges(
            orch, state, captured, max_reviews=max_reviews, run_context=run_context, seen=seen,
            errors=errors, deadline=deadline, stats=stats, group_identical=group_identical,
            resumed=resumed, on_review=on_review, summary_out=summary_out,
            model_failed=model_failed, journal_key=journal_key,
            should_stop=should_stop, outcome_out=outcome_out, groups=groups,
            report_left=report_left)
    # HU-5: whatever ends the review (a bound, an error, a cancellation), the handoff
    # gets the captures it left unreviewed. Bookkeeping only.
    seen = seen if seen is not None else set()
    _handoff.attach_state(state)
    try:
        return await _review_captured_exchanges(
            orch, state, captured, max_reviews=max_reviews, run_context=run_context, seen=seen,
            errors=errors, deadline=deadline, stats=stats, group_identical=group_identical,
            resumed=resumed, on_review=on_review, summary_out=summary_out,
            model_failed=model_failed, journal_key=journal_key,
            should_stop=should_stop, outcome_out=outcome_out, groups=groups,
            report_left=report_left)
    finally:
        try:
            _handoff.note_captures(captured, seen)
        except Exception:
            log.debug("handoff capture bookkeeping failed", exc_info=True)


async def _review_captured_exchanges(orch, state, captured, *, max_reviews, run_context,
                                     seen, errors, deadline, stats, group_identical,
                                     resumed, on_review, summary_out, model_failed,
                                     journal_key=None, should_stop=None,
                                     outcome_out=None, groups=None,
                                     report_left=True) -> int:
    produced = 0
    reviewed = 0
    stopped_by = None
    from harness import assessment_health
    from harness.assessment_health import review_frontier
    seen = seen if seen is not None else set()
    grouped: list[dict] = []
    grouped_keys: list[str] = []   # observation_key of each grouped entry, in order
    tier_counts = dict.fromkeys(assessment_health.TIER_NAMES, 0)
    elided: list[dict] = []        # captures whose prompts were cut to fit the context

    def _grouped(member, representative):
        grouped_keys.append(assessment_health.observation_key(member))
        grouped.append({"capture": member.url, "method": member.method,
                        "identity": assessment_health.identity_kind(member),
                        "covered_by": representative.url,
                        "reason": "identical response content, no input"})

    if groups is not None and group_identical:
        # Content an earlier call sharing `groups` already reviewed: group it there.
        for cap in captured or []:
            try:
                ex = cap if isinstance(cap, HttpExchange) else HttpExchange(**cap)
            except Exception:
                continue
            key = assessment_health.observation_key(ex)
            if key in seen:
                continue
            content = assessment_health._group_key(ex)
            representative = groups.get(content) if content is not None else None
            if representative is not None and assessment_health.observation_key(representative) != key:
                seen.add(key)
                _grouped(ex, representative)
    frontier = review_frontier(captured, seen=seen, group_identical=group_identical,
                               on_grouped=_grouped)
    # The capture being analyzed: (its observation key, its tier name, where its
    # grouped followers start). A cancellation puts it back as unreviewed.
    in_flight = None
    try:
        while True:
            if reviewed >= max_reviews:
                stopped_by = "capture review limit"
                break
            if deadline is not None and time.monotonic() >= deadline:
                stopped_by = "capture review time budget"
                break
            if should_stop is not None:
                stopped_by = should_stop() or None
                if stopped_by:
                    break
            grouped_before = len(grouped)
            cap = next(frontier, None)
            if cap is None:
                break
            try:
                ex = cap if isinstance(cap, HttpExchange) else HttpExchange(**cap)
            except Exception:
                continue
            reviewed += 1
            tier = assessment_health.TIER_NAMES[assessment_health.capture_tier(ex)]
            tier_counts[tier] += 1
            # R05: record the captured request template on its endpoint so the graph +
            # coverage replay the real body/query/content-type/object-id, not an empty
            # fabricated shape. Cheap and additive; failure must not sink the review.
            try:
                state.record_template(ex.url, ex.method, ex)
            except Exception:
                pass
            key = assessment_health.observation_key(ex)
            unit_key = key
            if journal_key is not None and (resumed is not None or on_review is not None):
                try:
                    unit_key = journal_key(ex)
                except Exception:   # a key that cannot be built is a journal miss, never an error
                    unit_key = key
            if resumed is not None and unit_key in resumed:
                findings = list(resumed[unit_key].get("findings") or [])
                if summary_out is not None:
                    summary_out["resumed"] = summary_out.get("resumed", 0) + 1
            else:
                in_flight = (key, tier, grouped_before)
                try:
                    resp = await orch.analyze(ex, _from_discovery=True, run_context=run_context)
                except Exception as e:  # one capture's failure must not sink the rest
                    in_flight = None
                    # Captures grouped under this representative were not actually reviewed:
                    # unmark them, so a later review round (a chain round) can still take them.
                    for entry in grouped[grouped_before:]:
                        entry["representative_review"] = "failed"
                    for grouped_key in grouped_keys[grouped_before:]:
                        seen.discard(grouped_key)
                    if errors is not None:
                        errors.append({"phase": "capture_review", "error": type(e).__name__})
                    if model_failed is not None:
                        model_failed.add(key)
                    log.debug("review_captured_exchanges: analyze failed on %s: %s",
                              getattr(ex, "url", "?"), e)
                    continue
                in_flight = None
                # A failed stage (today: the critique, which then ships its findings
                # unreviewed) is a failed model call too, so a retry round reviews it again.
                if model_failed is not None and (
                        any(getattr(r, "raw_error", None) for r in resp.agent_reports)
                        or any(getattr(o, "status", None) == "failed"
                               for o in getattr(resp, "stage_outcomes", None) or ())):
                    model_failed.add(key)
                findings = [f.model_dump() for r in resp.agent_reports for f in r.findings]
                fitted = _prompt_fits(resp)
                if fitted:
                    elided.append({"capture": ex.url, "method": ex.method, "prompts": fitted})
                if on_review is not None:
                    on_review(unit_key, {"findings": findings})
            if groups is not None and group_identical:
                content = assessment_health._group_key(ex)
                if content is not None:
                    groups.setdefault(content, ex)
            if findings:
                state.ingest_findings(ex.url, ex.method, findings)
                produced += 1
    except asyncio.CancelledError:
        # Cancelled mid-analysis (a hard deadline, the engagement ending): the capture
        # in flight was not reviewed, nor were the captures grouped under it.
        if in_flight is not None:
            key, tier, grouped_before = in_flight
            seen.discard(key)
            for grouped_key in grouped_keys[grouped_before:]:
                seen.discard(grouped_key)
            del grouped[grouped_before:]
            del grouped_keys[grouped_before:]
            reviewed -= 1
            tier_counts[tier] -= 1
        stopped_by = ((should_stop() if should_stop is not None else None)
                      or ("capture review time budget"
                          if deadline is not None and time.monotonic() >= deadline
                          else "cancellation"))
        raise
    finally:
        _review_bookkeeping(captured, seen, errors=errors, stats=stats,
                            stopped_by=stopped_by, reviewed=reviewed, produced=produced,
                            grouped=grouped, elided=elided, tier_counts=tier_counts,
                            outcome_out=outcome_out, report_left=report_left)
    return produced


async def universal_header_audit(orch, state, captured, *, max_exchanges: int = 200,
                                 run_context=None) -> int:
    """Universal header audit: run CORS, CSP, and verbose-error validators
    against EVERY captured exchange regardless of agent findings. This closes
    the passive analysis gap where header-level issues (CORS misconfiguration,
    missing CSP/X-Frame-Options, verbose errors) are missed because no LLM
    agent labelled the matching vulnerability class.

    Also scans verbose-error responses for disclosed paths and feeds them
    back into the engagement state for re-discovery.

    Returns the count of exchanges that produced at least one confirmed finding."""
    if not hasattr(orch, 'validator_registry') or orch.validator_registry is None:
        return 0

    # HU-5: every capture starts out unreviewed in the run's handoff, so a run that
    # stops before capture review still names them. Bookkeeping only.
    try:
        from harness import run_handoff
        _handoff = run_handoff.for_run(run_context)
        if _handoff is not None:
            _handoff.attach_state(state)
            _handoff.note_captures(captured, ())
    except Exception:
        log.debug("handoff capture bookkeeping failed", exc_info=True)

    audit_validators = orch.validator_registry.header_audit_validators()
    if not audit_validators:
        return 0
    if run_context is not None:
        # I03: the audit's active probes spend the owning run's transport.
        audit_validators = orch.validator_registry.bind_run_context(audit_validators, run_context)

    from harness.validators.verbose_error_validator import (
        findings_from_exchange as _ve_findings,
        extract_disclosed_paths,
    )

    produced = 0
    from itertools import islice
    from harness.assessment_health import review_frontier
    # E2: the run's execution registry records each template/identity this audit
    # checked, so the model-review path does not fetch the same headers again.
    registry = getattr(run_context, "execution_registry", None)
    if not callable(getattr(registry, "run_audit", None)):
        registry = None
    for cap in islice(review_frontier(captured), max_exchanges):
        try:
            ex = cap if isinstance(cap, HttpExchange) else HttpExchange(**cap)
        except Exception:
            continue

        exchange_findings = []

        # Run the verbose-error detector (passive, no network)
        ve = _ve_findings(ex)
        if ve:
            exchange_findings.extend(ve)

        # Run active header-audit validators (CORS, CSP) if active mode is on
        for v in audit_validators:
            if v.name == "verbose_error_validator":
                continue  # already ran above
            try:
                # One case ref per exchange: a second exchange of the same route
                # template and identity is a "covered by" hit, not another fetch.
                case_ref = "header-audit:" + hashlib.sha256(
                    f"{ex.method} {ex.url}".encode("utf-8", errors="replace")).hexdigest()[:12]
                if callable(getattr(v, "audit", None)):
                    # A validator that decides each class by its own check (CSP
                    # vs framing) audits every class from ONE fetch of the
                    # exchange; set iteration order is not a choice of class.
                    classes = tuple(getattr(v, "audit_classes", None) or ())
                    if registry is None or not classes:
                        results = list((await v.audit(ex)).values())
                    else:
                        results = list((await registry.run_audit(
                            v, ex, classes, case_ref=case_ref,
                            call=functools.partial(v.audit, ex))).values())
                else:
                    dummy_finding = Finding(
                        vulnerability_class=next(iter(v.finding_classes)),
                        severity="medium", confidence=0.5,
                        summary=f"Universal header audit: {v.name}",
                        evidence="", suggested_test="", basis="derived",
                    )
                    if registry is None:
                        results = [await v.validate(dummy_finding, ex)]
                    else:
                        results = [await registry.run(
                            v, dummy_finding, ex, case_ref=case_ref,
                            call=functools.partial(v.validate, dummy_finding, ex))]
                for result in results:
                    if result.confirmed:
                        exchange_findings.append(Finding(
                            vulnerability_class=result.finding_class,
                            severity="medium",
                            confidence=result.confidence,
                            summary=result.summary,
                            evidence=result.evidence,
                            suggested_test="",
                            basis="derived",
                            confirmed=True,
                            confirmation_method=v.get_name(),
                            header_fingerprint=getattr(result, "header_fingerprint", "") or "",
                        ))
            except Exception as e:
                log.debug("universal_header_audit: %s failed on %s: %s",
                          v.get_name(), getattr(ex, "url", "?"), e)

        if exchange_findings:
            state.ingest_findings(
                ex.url, ex.method,
                [f.model_dump() for f in exchange_findings])
            produced += 1

        # Feed disclosed paths from verbose errors back into discovery
        disclosed = extract_disclosed_paths(ex)
        if disclosed:
            import harness.engagement as _eng
            for p in disclosed:
                state._ep("GET", _eng.normalize_path(p))

    if produced:
        log.info("universal_header_audit: %d of %d exchanges produced header/error findings",
                 produced, min(len(captured or []), max_exchanges))
    return produced
