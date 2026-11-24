"""Findings repository of the harness state store.

Finding identity (W-9 fingerprint), persistence, reads, suppressions and
issue merges.

Part of the ARC-9 split of harness.store. Import these names from harness.store, the facade,
not from this module. A function here reads every store-level name through the facade at
call time (`_store.<name>`), so a patch or assignment on harness.store (`store._DB_PATH = ...`,
`patch.object(store, "_connect")`) reaches it. The facade owns the mutable state; this
module defines functions and constants only.
"""
from __future__ import annotations
import sqlite3
import time
import hashlib
import json
from urllib.parse import urlparse

from harness.models import HttpExchange, Finding


# W-9: bump when finding_fingerprint's formula changes, so _connect re-fingerprints
# existing rows once (guarded by PRAGMA user_version).
_FINGERPRINT_ALGO_VERSION = 3


def _normalize_endpoint(url: str) -> str:
    """Endpoint identity with volatile query VALUES stripped but structure kept:
    scheme://netloc/path plus the sorted set of query PARAM NAMES. So ?id=1 and
    ?id=2 collapse to the same endpoint, while ?a= and ?b= stay distinct."""
    from urllib.parse import urlsplit, parse_qsl
    parts = urlsplit(url or "")
    names = sorted({k for k, _ in parse_qsl(parts.query, keep_blank_values=True)})
    query = ("?" + ",".join(names)) if names else ""
    return f"{parts.scheme}://{parts.netloc}{parts.path}{query}"


def finding_fingerprint(host: str, method: str, url: str, vulnerability_class: str,
                        *, parameter_location: str = "", parameter_name: str = "",
                        principal_id: str = "", engagement_id: str = "") -> str:
    """Stable STRUCTURAL identity for a finding (W-9).

    Keyed on canonical vulnerability class + host + normalized endpoint +
    parameter/object + identity context -- deliberately NOT the LLM-written
    summary. The old formula hashed `summary`, so re-running with differently
    worded prose for the same underlying issue produced a different
    fingerprint, defeating suppression and duplicating findings. Two runs that
    word the same issue differently now hash identically.
    """
    # legacy_canonicalize, not canonicalize: suppressions and observations key on this
    # hash, so the finding-dedup class readings (2026-11-03) live in issues.issue_key.
    from harness.categories import legacy_canonicalize
    check = legacy_canonicalize(vulnerability_class) or (vulnerability_class or "").lower()
    fingerprint = hashlib.sha256("\x1f".join([
        host or "",
        (method or "").upper(),
        _store._normalize_endpoint(url),
        check,
        (parameter_location or "").lower(),
        # W-9: parameter_name is a case-sensitive input identity (e.g. `userId`
        # vs `userid` are distinct fields on many APIs) -- do not fold its case,
        # unlike parameter_location which is a fixed, case-irrelevant enum.
        parameter_name or "",
        principal_id or "",
    ]).encode("utf-8")).hexdigest()
    if engagement_id:
        return hashlib.sha256(json.dumps([_store._engagement_partition(engagement_id), fingerprint]).encode()).hexdigest()
    return fingerprint


def host_of(url: str) -> str:
    try:
        return urlparse(url).netloc or url
    except Exception:
        return url


def persist_findings(exchange: HttpExchange, agent_name: str, findings: list[Finding],
                      model: str = "", prompt_version: str = "", *, engagement_id: str = "") -> None:
    if not findings:
        return
    host = _store.host_of(exchange.url)
    engagement_id = _store._engagement_partition(engagement_id)
    # I02-B: always record the captured principal. prior_findings_summary filters
    # by it in every partition, so storing "" for the default (host-wide) pile
    # made a site's earlier findings invisible to later analyses by the same
    # identity. The default-pile fingerprint is unchanged (dedupe/suppression).
    captured_principal = _store.captured_principal_id(exchange)
    now = time.time()
    # AR-3 (LOOP half): exact provenance. Prefer the capture driver's own id
    # (trusted transport field, not agent JSON); fall back to a stable content
    # hash of the exchange -- the same hash orchestrator_detect.py already uses
    # at :460/:944, so two exchanges with identical method+url but different
    # bodies/headers still get distinct ids even without an explicit capture_id.
    # I02-C: exchange_identity is shared with record_observation so the two
    # stay joinable; it returns the same id as before for legacy exchanges.
    exchange_id, _ = _store.exchange_identity(exchange)
    from harness import telemetry as _telemetry
    run_id = _telemetry.current_run_id() or ""
    conn = _store._connect()
    try:
        rows = []
        fingerprints = []
        for f in findings:
            fingerprint = _store.finding_fingerprint(
                host, exchange.method, exchange.url, f.vulnerability_class,
                parameter_location=getattr(f, "parameter_location", "") or "",
                parameter_name=getattr(f, "parameter_name", "") or "",
                principal_id=(captured_principal if engagement_id else getattr(f, "principal_id", "") or ""),
                engagement_id=engagement_id,
            )
            fingerprints.append(fingerprint)
            rows.append((host, exchange.url, exchange.method, agent_name, f.vulnerability_class,
                         f.severity, f.confidence, f.summary, f.basis, f.evidence, f.suggested_test,
                         f.owasp_category, f.review_verdict, int(f.confirmed), fingerprint,
                         model, prompt_version, f.finding_id, f.case_id, f.proof_id,
                         int(getattr(f, "oracle_verified", False)),
                         getattr(f, "verification_state", "candidate") or "candidate",
                         getattr(f, "oracle_capsule_id", "") or "", exchange_id, run_id, engagement_id, captured_principal, now))
        conn.executemany(
            """INSERT OR IGNORE INTO findings
               (host, url, method, agent, vulnerability_class, severity,
                confidence, summary, basis, evidence, suggested_test, owasp_category,
                review_verdict, confirmed, fingerprint, model, prompt_version,
                finding_id, case_id, proof_id, oracle_verified, verification_state,
                oracle_capsule_id, exchange_id, run_id, engagement_id, captured_principal_id, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", rows)
        # Finding dedup: the input each finding names, in its side table (see
        # _FINDING_INPUTS_SCHEMA). Keyed like the findings row, so a deduped
        # re-report is a no-op here too.
        conn.executemany(
            "INSERT OR IGNORE INTO finding_inputs (fingerprint, case_id, parameter_location, "
            "parameter_name, created_at) VALUES (?, ?, ?, ?, ?)",
            [(r[14], r[18] or "", getattr(f, "parameter_location", "") or "",
              getattr(f, "parameter_name", "") or "", now) for r, f in zip(rows, findings)])
        # AR-3: one observation row per (finding, exchange), regardless of
        # whether the findings INSERT above was a fresh row or an IGNOREd
        # duplicate -- a deduped finding still records this exchange as a
        # distinct sighting. INSERT OR IGNORE on the (fingerprint, run_id,
        # exchange_id) unique index makes this idempotent on retries.
        conn.executemany(
            """INSERT OR IGNORE INTO finding_observations
               (fingerprint, run_id, exchange_id, created_at)
               VALUES (?, ?, ?, ?)""",
            [(fp, run_id, exchange_id, now) for fp in fingerprints],
        )
        conn.commit()
    finally:
        conn.close()


def bind_confirmation_proof(exchange: HttpExchange, finding: Finding, agent_name: str, *,
                            engagement_id: str = "", principal_bound: bool = False,
                            accepts_class=None, proof_note: str = "") -> int:
    """Bind a persisted confirmation proof to the stored finding(s) it proves.

    The engagement graph loop confirms dict findings in engagement state; the
    findings table (findings API, report) never heard of those proofs (r5:
    sqlmap proved SQLi on POST /rest/user/login, the stored login rows stayed
    unconfirmed). This marks confirmed only the UNCONFIRMED rows on the same
    host, method and route (`_normalize_endpoint`: query values dropped, names
    kept, the endpoint the fingerprint keys on) whose class is the proof's own
    class (categories.finding_class, the reading the R11-1 class gate uses; EFF-2)
    and whose recorded parameter is the proven one, or is unnamed. A row of any
    other class or another parameter is never touched. When no row matches and
    none is already confirmed, the proven finding is persisted as its own row.
    `finding` must carry proof_id and case_id; a finding without them binds
    nothing. Returns the number of rows bound/added.

    The coverage drive's proofs were not dispatched for any stored row, so it
    narrows the match (r10: 143 confirmed coverage proofs, AV-EXPOSURE-01 among
    them, were never bound, so the report showed none of them):
    - principal_bound: the proof ran as one principal. Only rows recorded under
      the same captured principal (`captured_principal_id(exchange)`) are bound,
      and a row the proof creates records that principal.
    - accepts_class(vulnerability_class) -> bool: whether the proving validator
      speaks for a row of that class (its own `applies` routing). A broad class
      (info_disclosure, misconfig) covers unrelated claims; a row the validator
      would not have been routed stays as it was, and the proof gets its own row.
      Rows this agent already recorded always count as its own.
    - proof_note: what the proof showed, appended to each bound row's evidence.

    Review precedence: as before, a bound row's verdict becomes
    'validator-confirmed'. That is the PASS1 rule (orchestrator_confirm): a
    deterministic proof outranks a demoting review verdict. The findings table has
    no review_note column, so a superseded verdict is recorded in the row's
    evidence with the proof that superseded it, never dropped silently."""
    if not (finding.confirmed and finding.proof_id and finding.case_id):
        return 0
    from urllib.parse import urlsplit
    from harness.categories import finding_class

    def _check(cls: str) -> str:
        # EFF-2: the class reading the R11-1 gate uses, so a proof binds the rows
        # the gate would let it confirm ("potential_idor" beside "idor"). The
        # fingerprint keeps legacy_canonicalize; this only picks rows to bind.
        return finding_class(cls)

    def _accepts(cls: str) -> bool:
        try:
            return bool(accepts_class(cls))
        except Exception:
            return False

    check = _check(finding.vulnerability_class)
    param = finding.parameter_name or ""
    host = _store.host_of(exchange.url)
    route = _store._normalize_endpoint(exchange.url)
    parts = urlsplit(exchange.url or "")
    base = f"{parts.scheme}://{parts.netloc}{parts.path}"
    principal = _store.captured_principal_id(exchange) if principal_bound else None
    engagement_id = _store._engagement_partition(engagement_id)
    conn = _store._connect()
    try:
        rows = conn.execute(
            """SELECT f.id, f.vulnerability_class, f.confirmed,
                      COALESCE(fi.parameter_name, ''), f.fingerprint, f.url,
                      COALESCE(f.captured_principal_id, ''), COALESCE(f.review_verdict, ''),
                      f.agent FROM findings f
               LEFT JOIN finding_inputs fi ON fi.fingerprint = f.fingerprint
                                          AND fi.case_id = f.case_id
               WHERE f.host = ? AND f.method = ?
                 AND (f.url IN (?, ?) OR substr(f.url, 1, ?) = ?)
                 AND f.engagement_id IN (?, '')""",
            (host, (exchange.method or "").upper(), exchange.url, base, len(base) + 1, base + "?",
             engagement_id)).fetchall()
        same = [r for r in rows if _store._normalize_endpoint(r[5]) == route and _check(r[1]) == check
                and r[3] in (param, "") and (principal is None or r[6] == principal)]
        if accepts_class is not None:
            same = [r for r in same if r[8] == agent_name or _accepts(r[1])]
        # One row per fingerprint can carry the proof's case (the findings index is
        # unique on fingerprint + case_id): the oldest unconfirmed row takes it and a
        # same-identity duplicate stays as it was (it groups into the same issue).
        bound = []
        now = time.time()
        for r in sorted({r[0]: r for r in same if not r[2]}.values()):
            notes = []
            if r[7] and r[7] != "validator-confirmed":
                notes.append(f"prior review verdict '{r[7]}' superseded by "
                             f"{agent_name} proof {finding.proof_id}")
            if proof_note:
                notes.append(proof_note)
            try:
                conn.execute(
                    """UPDATE findings SET confirmed = 1, proof_id = ?, case_id = ?,
                            review_verdict = 'validator-confirmed',
                            confidence = MAX(confidence, ?),
                            evidence = COALESCE(evidence, '') || ?
                        WHERE id = ? AND confirmed = 0""",
                    (finding.proof_id, finding.case_id, float(finding.confidence or 0.0),
                     "".join(" || " + n for n in notes), r[0]))
            except sqlite3.IntegrityError:
                continue
            bound.append(r)
        if bound:
            # The row's recorded input is keyed by its case; re-key it to the proof's.
            conn.executemany(
                "INSERT OR IGNORE INTO finding_inputs (fingerprint, case_id, parameter_location, "
                "parameter_name, created_at) VALUES (?, ?, ?, ?, ?)",
                sorted({(r[4], finding.case_id, finding.parameter_location or "", param, now)
                        for r in bound}))
            conn.commit()
            return len(bound)
        if any(r[2] for r in same):
            return 0
    finally:
        conn.close()
    _store.persist_findings(exchange, agent_name, [finding], engagement_id=engagement_id)
    return 1


def finding_observations(fingerprints: list[str] | None = None) -> dict[str, list[str]]:
    """fingerprint -> the list of exchange_ids that produced it (AR-3 LOOP
    half), read from the finding_observations link table -- NOT from
    findings.exchange_id, which only keeps the first-seen exchange for a
    finding that dedup collapsed (see persist_findings). This is how a
    caller (e.g. testing/blind-target-2/run_blind_eval.py's build_scorecard)
    recovers exact per-exchange provenance even after dedup: a fingerprint
    observed via two different exchanges gets two entries here.

    Rows with an empty exchange_id (persisted before this column existed, on
    a DB migrated from a pre-AR-3 build) are excluded, so a caller can treat
    an empty/missing entry for a fingerprint as "no exchange-level provenance
    available -- fall back to legacy (method, url) attribution."
    With `fingerprints` given, restricts to those; otherwise returns every
    fingerprint with at least one recorded observation.
    """
    conn = _store._connect()
    try:
        if fingerprints:
            placeholders = ",".join("?" for _ in fingerprints)
            rows = conn.execute(
                f"SELECT fingerprint, exchange_id FROM finding_observations "
                f"WHERE fingerprint IN ({placeholders}) AND exchange_id != ''",
                list(fingerprints),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT fingerprint, exchange_id FROM finding_observations WHERE exchange_id != ''"
            ).fetchall()
    finally:
        conn.close()
    result: dict[str, list[str]] = {}
    for fp, exid in rows:
        result.setdefault(fp, []).append(exid)
    return result


def _strip_backticks(text: str) -> str:
    return text.replace("`", "'")


def prior_findings_summary(url: str, exclude_url: str | None = None, limit: int = 8,
                          *, engagement_id: str = "", captured_principal: str | None = None) -> str:
    """
    Compact, prompt-ready summary of what's already been found on this
    host, most recent first. Intentionally small and lossy (a prior, not
    a full record) -- its job is to let an agent notice "this finding is
    more significant given what else is on this host", not to
    reconstruct full history.
    """
    host = _store.host_of(url)
    conn = _store._connect()
    try:
        rows = conn.execute(
            """SELECT url, vulnerability_class, severity, confidence, summary
               FROM findings WHERE host = ? AND engagement_id = ?
               AND (? IS NULL OR captured_principal_id = ?) AND url != COALESCE(?, '')
               AND vulnerability_class NOT LIKE 'potential-attack-chain:%'
               ORDER BY created_at DESC LIMIT ?""",
            (host, _store._engagement_partition(engagement_id), captured_principal, captured_principal, exclude_url, limit),
        ).fetchall()
    finally:
        conn.close()

    if not rows:
        return ""
    # Found live, during this project's first real (non-substituted)
    # Ollama run: a model wrote a completely ordinary finding summary
    # using Markdown code-formatting for a path -- "The `/api/avatar`
    # endpoint returns potentially sensitive data..." -- which got
    # persisted, then fed back verbatim into every SUBSEQUENT exchange's
    # prompt for the same host via this function. prompt_validator.py's
    # backtick-command-substitution pattern (`` `[^`\n]{1,200}` ``,
    # deliberately broad -- see its own comment) matched the backtick-
    # quoted path, failing prompt validation for every agent on every
    # remaining exchange for that host for the rest of the run. Unlike
    # raw exchange data (genuinely untrusted, and validated for good
    # reason), this text is the harness's OWN prior model output; the
    # only value backticks add here is Markdown styling, which nothing
    # downstream renders anyway. Stripping them breaks the propagation
    # at its source rather than trying to special-case every blocked
    # pattern this text might one day happen to also contain.
    lines = [
        f"- [{sev}, confidence {conf:.2f}] {vclass} at {u}: {_store._strip_backticks(summary)}"
        for (u, vclass, sev, conf, summary) in rows
    ]
    return "\n".join(lines)


def all_host_findings(url: str, include_suppressed: bool = False, *, engagement_id: str = "",
                      captured_principal: str | None = None,
                      include_chains: bool = False, run_id: str | None = None) -> list[dict]:
    """
    Full (not summarized) finding records for a host, for chain detection
    and report generation.

    `include_chains`: speculative attack-chain hypotheses
    (vulnerability_class "potential-attack-chain:*") are rule-derived
    *relationships* between findings, not independently-detected host
    findings. They must not inflate the per-host finding count the eval
    scores, nor be fed back into agent prompts as "prior findings" (both
    read this function), so they are EXCLUDED by default. The report
    passes include_chains=True to surface them in their own section --
    they are still persisted and recorded, just kept out of the
    host-finding set every other consumer sees.

    `include_suppressed`: if False (the default), findings whose
    fingerprint has been suppressed (see `suppress_finding`) are left out
    entirely. Each returned dict always includes `fingerprint` and
    `suppressed` regardless of this flag, so a caller that DOES want to
    see suppressed findings (e.g. an "show dismissed findings" view) can
    still tell which ones they are -- this flag controls whether they're
    in the list at all, not whether the suppressed status is visible.
    """
    host = _store.host_of(url)
    conn = _store._connect()
    try:
        rows = conn.execute(
            """SELECT f.url, f.vulnerability_class, f.severity, f.confidence, f.summary,
                      f.evidence, f.suggested_test, f.owasp_category, f.basis, f.confirmed,
                      f.agent, f.fingerprint, f.finding_id, f.case_id, f.proof_id,
                      f.method, f.review_verdict,
                      COALESCE((SELECT parameter_location FROM proof_records WHERE case_id = f.case_id LIMIT 1),
                               fi.parameter_location),
                      COALESCE((SELECT parameter_name FROM proof_records WHERE case_id = f.case_id LIMIT 1),
                               fi.parameter_name),
                      (SELECT principal_id FROM proof_records WHERE case_id = f.case_id LIMIT 1),
                      s.fingerprint IS NOT NULL AS suppressed,
                      f.oracle_verified, f.verification_state, f.oracle_capsule_id,
                      f.exchange_id, f.run_id, f.captured_principal_id,
                      p.validator, p.workflow_state_id, i.policy_fingerprint, es.evidence_source,
                      p.observed_result
               FROM findings f
               LEFT JOIN finding_suppressions s ON s.fingerprint = f.fingerprint
               LEFT JOIN proof_records p ON p.proof_id = f.proof_id AND f.proof_id != ''
               LEFT JOIN proof_identity i ON i.proof_id = p.proof_id AND i.identity_version = ?
               LEFT JOIN proof_evidence_source es ON es.proof_id = p.proof_id
               LEFT JOIN finding_inputs fi ON fi.fingerprint = f.fingerprint AND fi.case_id = f.case_id
               WHERE f.host = ? AND f.engagement_id = ?
                 AND (? IS NULL OR f.captured_principal_id = ?)
                 AND (? IS NULL OR f.run_id = ?)
               ORDER BY f.created_at ASC""",
            (_store._PROOF_IDENTITY_VERSION, host, _store._engagement_partition(engagement_id),
             captured_principal, captured_principal, run_id, run_id),
        ).fetchall()
    finally:
        conn.close()
    # method + the finding's case coordinates (parameter_location/parameter_name/
    # principal_id, from its linked proof) are surfaced for T06 issue grouping and
    # export -- additive keys; existing consumers read by name and are unaffected.
    from harness import confirmation_gate, security
    results = [
        {"url": u, "vulnerability_class": vc, "severity": sev, "confidence": conf, "summary": s,
         "evidence": ev, "suggested_test": st, "owasp_category": oc, "basis": basis,
         "confirmed": bool(confirmed), "agent": agent, "fingerprint": fp,
         "finding_id": finding_id, "case_id": case_id, "proof_id": proof_id,
         "method": method or "", "review_verdict": rv or "",
         # W-7: explicit CONFIRMED/SUSPECTED/LEAD state so the findings API, the
         # report and the Burp tab can show status at a glance rather than a raw
         # confidence number.
         "lifecycle_state": confirmation_gate.lifecycle_state(bool(confirmed), rv),
         # EFF-5: why a LEAD is LEAD (refuted / untested / rejected / environment),
         # "" otherwise -- a refuted finding and an untested one are not the same.
         "lead_reason": confirmation_gate.lead_reason(bool(confirmed), rv),
         "parameter_location": ploc or "", "parameter_name": pname or "",
         # Finding dedup: False only for a row written before finding_inputs existed
         # (no side row, no proof record) -- issues.issue_key then keeps
         # input-bearing classes apart rather than assume no input.
         "input_recorded": ploc is not None or pname is not None,
         "principal_id": principal or "", "suppressed": bool(suppressed),
         "captured_principal_id": captured_principal_id or "",
         # P0.2-API: the oracle's verdict (item #1/#2) must be readable from the
         # SAME dict the report/API/Burp panel all consume -- previously this
         # query never selected these columns, so `oracle_verified` was always
         # absent here and `derive_verification_state()` silently defaulted
         # every finding to "candidate" regardless of what was persisted.
         "oracle_verified": bool(oracle_verified), "verification_state": vstate or "candidate",
         "oracle_capsule_id": capsule_id or "",
         # AR-3 (LOOP half): exact finding->exchange/run provenance. Additive
         # keys; '' for legacy rows persisted before this column existed.
         "exchange_id": exchange_id or "", "run_id": run_id or "", "engagement_id": engagement_id,
         # AR-08b: the linked proof's mechanism, workflow state and persisted policy
         # fingerprint (AR-08a), so issues.issue_key can group a route-independent
         # mechanism from the store alone. '' when unlinked or never fingerprinted.
         "validator": validator or "", "workflow_state_id": workflow_state_id or "",
         "policy_fingerprint": policy_fingerprint or "",
         # The linked proof's evidence source ("tool_reported"), only when it has one.
         **({"evidence_source": evidence_source} if evidence_source else {}),
         # What the linked proof observed (secret shapes masked), so issues.header_policy
         # can key a header-policy row on the policy its proof recorded. '' when unlinked.
         "proof_observed_result": security.sanitize_text(observed_result or "")}
        for (u, vc, sev, conf, s, ev, st, oc, basis, confirmed, agent, fp,
             finding_id, case_id, proof_id, method, rv, ploc, pname, principal, suppressed,
             oracle_verified, vstate, capsule_id, exchange_id, run_id, captured_principal_id,
             validator, workflow_state_id, policy_fingerprint, evidence_source, observed_result) in rows
    ]
    _store._resolve_confirmation_proofs(results)
    if not include_suppressed:
        results = [r for r in results if not r["suppressed"]]
    if not include_chains:
        results = [r for r in results
                   if not r["vulnerability_class"].startswith("potential-attack-chain:")]
    return results


def _resolve_confirmation_proofs(results: list[dict]) -> None:
    """I02-A: a stored confirmation that names a proof counts only while that exact
    proof -- same proof_id AND case_id, verdict confirmed -- is still on record.
    A missing, unresolvable or re-pointed proof is reported as proof unavailable,
    never as confirmed, on every surface that reads this function (findings API,
    Markdown report, issue/SARIF export). Rows with no proof pointer at all keep
    their legacy meaning (proof_status "none").

    R49: an oracle verdict is only stamped onto a confirmed finding, so it falls
    with the proof. A demoted row also loses oracle_verified/verification_state,
    which the report's VERIFIED badge and the lead quarantine read."""
    for r in results:
        r["proof_status"] = "none"
    pointed = [r for r in results
               if (r["confirmed"] or r["oracle_verified"] or r["verification_state"] == "verified")
               and (r["proof_id"] or r["case_id"])]
    if not pointed:
        return
    ids = sorted({r["proof_id"] for r in pointed if r["proof_id"]})
    resolved: set[tuple[str, str]] = set()
    if ids:
        conn = _store._connect()
        try:
            marks = ",".join("?" for _ in ids)
            resolved = {(pid, cid) for pid, cid in conn.execute(
                f"SELECT proof_id, case_id FROM proof_records "
                f"WHERE proof_id IN ({marks}) AND verdict = 'confirmed'", ids).fetchall()}
        finally:
            conn.close()
    from harness import confirmation_gate
    for r in pointed:
        if (r["proof_id"], r["case_id"]) in resolved:
            r["proof_status"] = "resolved"
        else:
            r["proof_status"] = "unavailable"
            r["confirmed"] = False
            r["lifecycle_state"] = confirmation_gate.lifecycle_state(False, r["review_verdict"])
            r["lead_reason"] = confirmation_gate.lead_reason(False, r["review_verdict"])
            r["oracle_verified"] = False
            r["verification_state"] = "candidate"


def suppress_finding(fingerprint: str, reason: str = "") -> None:
    """
    Marks a finding fingerprint as suppressed (a false positive, or
    otherwise not worth re-surfacing) so a future scan of the same host
    doesn't make the analyst re-triage it from scratch. This is the
    workflow gap named in this project's own milestones list: without
    it, re-running the harness against a target re-surfaces every
    previously-dismissed finding with no memory of the dismissal --
    undercutting the tool's whole point of not making the analyst
    re-verify things it's already told them about.

    Idempotent: suppressing an already-suppressed fingerprint just
    updates the reason/timestamp, via INSERT OR REPLACE, rather than
    erroring on the primary key collision.

    Known limitation, stated plainly rather than silently accepted:
    `fingerprint` (computed in `persist_findings`) includes the agent's
    free-text `summary`, not just host/method/url/category. If a re-run
    produces a differently-worded summary for the exact same underlying
    issue, its fingerprint won't match a previously-suppressed one, and
    it will resurface. This suppression feature is built on the
    fingerprint scheme that already existed for same-run deduplication,
    not a new, more stable cross-run identity scheme -- reworking
    fingerprint computation to be summary-independent would be a more
    invasive change to `persist_findings`'s existing behavior and is a
    separate, deliberately-not-bundled decision for a future session.
    """
    conn = _store._connect()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO finding_suppressions (fingerprint, reason, suppressed_at) VALUES (?, ?, ?)",
            (fingerprint, reason, time.time()),
        )
        conn.commit()
    finally:
        conn.close()


def unsuppress_finding(fingerprint: str) -> bool:
    """Removes a suppression. Returns True if a row was actually removed."""
    conn = _store._connect()
    try:
        cur = conn.execute("DELETE FROM finding_suppressions WHERE fingerprint = ?", (fingerprint,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def is_suppressed(fingerprint: str) -> bool:
    conn = _store._connect()
    try:
        row = conn.execute(
            "SELECT 1 FROM finding_suppressions WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def list_suppressions() -> list[dict]:
    """All active suppressions, most recently suppressed first."""
    conn = _store._connect()
    try:
        rows = conn.execute(
            "SELECT fingerprint, reason, suppressed_at FROM finding_suppressions ORDER BY suppressed_at DESC"
        ).fetchall()
    finally:
        conn.close()
    return [{"fingerprint": fp, "reason": reason, "suppressed_at": ts} for (fp, reason, ts) in rows]


def record_issue_merge(host: str, source_id: str, target_id: str) -> None:
    """Operator override (P1.8): fold issue `source_id` into `target_id` for
    `host`. Idempotent (INSERT OR REPLACE), like suppress_finding. Reversible
    by remove_issue_merge -- this is a separate override table, never a
    mutation of the underlying findings or the deterministic issue_key
    grouping, so removing the row exactly restores the automatic split."""
    if source_id == target_id:
        raise ValueError("cannot merge an issue into itself")
    conn = _store._connect()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO issue_merges (host, source_id, target_id, created_at) "
            "VALUES (?, ?, ?, ?)",
            (host, source_id, target_id, time.time()),
        )
        conn.commit()
    finally:
        conn.close()


def remove_issue_merge(host: str, source_id: str) -> bool:
    """Reverses a prior record_issue_merge. Returns True if a row was removed."""
    conn = _store._connect()
    try:
        cur = conn.execute(
            "DELETE FROM issue_merges WHERE host = ? AND source_id = ?", (host, source_id))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def all_issue_merges(host: str) -> dict[str, str]:
    """{source_id: target_id} for every active merge override on `host`."""
    conn = _store._connect()
    try:
        rows = conn.execute(
            "SELECT source_id, target_id FROM issue_merges WHERE host = ?", (host,)
        ).fetchall()
    finally:
        conn.close()
    return {source_id: target_id for (source_id, target_id) in rows}


# The facade, bound last: the functions above read harness.store names through it at call
# time, and binding it here lets this module be imported before harness.store.
from harness import store as _store  # noqa: E402
