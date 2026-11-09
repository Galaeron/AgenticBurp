"""HU-2: a ranked queue of unproven leads, each with a ready-to-send request.

Read-only. Nothing here sends traffic: every field is derived from what the
pipeline already recorded (stored findings, retained captures, the evidence
ledger, and optionally the newest investigation result for the host).

An unproven candidate is a stored, unsuppressed, non-chain finding that is
either unconfirmed and still open (evidence maturity ``unverified`` or
``unverified_no_leg``), or "confirmed" only by an external tool the harness
did not reproduce (``tool_reported``). A finding a reliable check already
refuted (controlled negative, review rejected) is not a lead. Experiment tasks
and identity prerequisites from the investigation result that never ran are
leads too.

JSON shape (``GET /engagement/{host}/leads``; schema_version 1, kept stable for
the Burp extension's leads table):

    {
      "schema_version": 1, "host": str, "engagement_id": str,
      "sends_traffic": false,
      "investigation": {"job_id": str | null, "used": bool, "note": str},
      "lead_count": int,
      "leads": [{
        "lead_id": str,            # stable: sha256 over kind + source id
        "rank": int,               # 1 = do first; see _rank_key
        "kind": "finding" | "experiment" | "prerequisite",
        "finding_id": str, "fingerprint": str,
        "vulnerability_class": str, "severity": str, "confidence": float,
        "evidence_maturity": str, "lifecycle_state": str,
        "method": str, "url": str,             # url secret-redacted
        "parameter": {"location": str, "name": str},
        "identity": {"captured_principal_id": str, "principal_id": str},
        "request": null | {
          "source": "captured_observation" | "ledger_execution",
          "source_ref": str,       # observation_id or request blob sha256
          "method": str, "url": str, "headers": {str: str}, "body": str | null,
          "raw": str,              # HTTP/1.1 text built from the fields above
          "truncated": bool, "redacted": true,
          "rehydration_required": true   # secrets are placeholders: fill the
                                         # session from the declared role
        },
        "no_request_reason": str | null,   # set exactly when request is null
        "change": str,                     # the one change to make
        "expected": {"positive": str, "negative": str},
        "blocked_on": null | "no_leg" | "identity_missing" | "operator_input"
                      | "budget" | "deadline" | "tool_reported",
        "blocked_facts": [{"category": str, "fact": str}],  # every recorded fact
        "suggested_test": str              # the detector's own text, unverified
      }]
    }

``blocked_on`` is the first category, in _BLOCKED_PRIORITY order, among the
recorded facts; null means nothing recorded blocks the lead (it is ready to
test). A fact is never inferred from the absence of one.

Every secret-bearing value is masked with the existing redactors
(``security.redact_headers``, ``issues.redact``, ``issues.redact_url``) even
though stored captures and blobs are already sanitized at write time.
"""
from __future__ import annotations

import hashlib
import json
from urllib.parse import urlsplit

SCHEMA_VERSION = 1

NO_LEG = "no_leg"
IDENTITY_MISSING = "identity_missing"
OPERATOR_INPUT = "operator_input"
BUDGET = "budget"
DEADLINE = "deadline"
TOOL_REPORTED = "tool_reported"
BLOCKED_CATEGORIES = (NO_LEG, IDENTITY_MISSING, OPERATOR_INPUT, BUDGET, DEADLINE, TOOL_REPORTED)
# Most specific / actionable first: a tool-reported detection needs only a
# reproduction; a missing identity or operator decision gates everything after.
_BLOCKED_PRIORITY = (TOOL_REPORTED, IDENTITY_MISSING, OPERATOR_INPUT, BUDGET, DEADLINE, NO_LEG)

_OPEN_MATURITIES = {"unverified", "unverified_no_leg"}
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
# Transport outcomes (run_context.TargetTransport) recorded as AUTHORIZATION_DECISION.
_IDENTITY_OUTCOMES = {"unknown_session", "session_expired", "credentials_require_session"}
_BUDGET_OUTCOMES = {"budget_exhausted"}
# worklist_investigator skip reasons.
_SKIP_CATEGORY = {"budget_exhausted": BUDGET, "time_budget": DEADLINE,
                  "policy_blocked": OPERATOR_INPUT}
_STAGE_DEADLINE = "stage deadline reached"   # experiment.STAGE_DEADLINE

NO_REQUEST_FINDING = ("no request recorded: neither the capture that produced this finding "
                      "nor any harness send for it was retained")
NO_REQUEST_EXPERIMENT = "no request recorded: this experiment was never sent"
NO_REQUEST_PREREQUISITE = "no request recorded as this identity"


# --------------------------------------------------------------------------- #
# The one change, and what each result looks like (generic per class family)
# --------------------------------------------------------------------------- #

def _target_phrase(location: str, name: str) -> str:
    if name:
        return f"the {location} parameter `{name}`" if location else f"the parameter `{name}`"
    return "the input the detector named (no parameter was recorded)"


_FAMILIES = (
    (("missing auth", "missing_auth", "unauthenticated", "authentication bypass", "auth_bypass"),
     lambda t: "resend the request with the session removed (no Cookie or Authorization header)",
     "the same protected data or action is returned without a session",
     "401/403, a redirect to sign-in, or a response without the protected data"),
    (("idor", "bola", "bfla", "access control", "access_control", "authorization", "authz",
      "privilege", "horizontal", "vertical", "tenant", "ownership"),
     lambda t: ("resend the request as a different declared identity (another owner or a lower "
                f"role), keeping {t} unchanged"),
     "the other identity receives the same object/data or the action succeeds (2xx, same shape)",
     "401/403/404, or a response that omits the first identity's data"),
    (("nosql",),
     lambda t: f"in {t}, replace the value with an operator object such as {{\"$ne\": null}}",
     "the response widens (more records, or authentication succeeds)",
     "the response matches the baseline or is rejected"),
    (("sql", "sqli"),
     lambda t: f"in {t}, send a boolean pair (append ' AND '1'='1 then ' AND '1'='2)",
     "the two variants differ consistently in status or size, or a quote yields a database error",
     "both variants match the baseline response"),
    (("xss", "cross-site scripting", "html injection"),
     lambda t: f"set {t} to a unique marker containing <\"'> characters",
     "the marker is reflected unencoded in an HTML or script context",
     "the marker is absent or HTML-encoded"),
    (("ssti", "template"),
     lambda t: f"set {t} to an arithmetic template expression such as {{{{7*7}}}}",
     "the response contains the evaluated result (49)",
     "the expression is returned literally or rejected"),
    (("command", "rce", "os injection"),
     lambda t: f"append a timing separator to {t} (e.g. ;sleep 5)",
     "the response is delayed by the injected interval, repeatably",
     "response time matches the baseline"),
    (("ssrf", "server-side request"),
     lambda t: f"set {t} to a URL on an interaction host you control",
     "the interaction host records a request from the target",
     "no interaction is recorded"),
    (("traversal", "lfi", "file inclusion"),
     lambda t: f"set {t} to a ../ sequence that names a known readable file",
     "the file's contents are returned",
     "an error, 404, or the baseline response"),
    (("redirect",),
     lambda t: f"set {t} to an external origin",
     "a 3xx whose Location points at that external origin",
     "no redirect, or a redirect that stays on the target origin"),
    (("xxe", "xml"),
     lambda t: "send the body as XML with an external entity that names a local file",
     "the entity is expanded in the response",
     "the entity is rejected or returned unexpanded"),
    (("csrf",),
     lambda t: "resend the state-changing request without its anti-CSRF token and with a "
               "cross-site Origin header",
     "the state change is accepted",
     "the request is rejected (403/400) or the change does not happen"),
    (("mass assignment", "mass_assignment", "overposting"),
     lambda t: "add one privileged field the response exposes (e.g. a role or owner field) to the body",
     "the stored object reflects the added field",
     "the field is ignored or rejected"),
    (("cors",),
     lambda t: "resend the request with an arbitrary Origin header",
     "Access-Control-Allow-Origin echoes that origin (with credentials allowed)",
     "the origin is not echoed"),
    (("jwt",),
     lambda t: "resend with the token's signature stripped or its algorithm set to none",
     "the altered token is accepted",
     "401/403"),
)


def _change_for(vulnerability_class: str, location: str, name: str,
                suggested_test: str) -> tuple[str, dict]:
    lowered = (vulnerability_class or "").lower()
    target = _target_phrase(location, name)
    for keys, change, positive, negative in _FAMILIES:
        if any(k in lowered for k in keys):
            return change(target), {"positive": positive, "negative": negative}
    if suggested_test:
        return (f"follow the detector's suggested test on {target}: {suggested_test}",
                {"positive": "the behaviour the detector predicts is observed",
                 "negative": "the response matches the recorded baseline"})
    return (f"inspect the recorded response; no single change is defined for class "
            f"{vulnerability_class!r}",
            {"positive": "the recorded response shows the reported condition",
             "negative": "the recorded response does not show it"})


# --------------------------------------------------------------------------- #
# Recorded request (never invented)
# --------------------------------------------------------------------------- #

def _redacted_request(method: str, url: str, headers: dict | None, body,
                      *, source: str, source_ref: str, truncated: bool) -> dict:
    from harness import issues, security
    clean_headers = {str(k): issues.redact(str(v))
                     for k, v in security.redact_headers(dict(headers or {})).items()}
    clean_body = None if body is None else issues.redact(str(body))
    clean_url = issues.redact_url(url or "")
    parts = urlsplit(clean_url)
    target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    lines = [f"{(method or 'GET').upper()} {target} HTTP/1.1"]
    if not any(k.lower() == "host" for k in clean_headers) and parts.netloc:
        lines.append(f"Host: {parts.netloc}")
    lines += [f"{k}: {v}" for k, v in clean_headers.items()]
    raw = "\r\n".join(lines) + "\r\n\r\n" + (clean_body or "")
    return {"source": source, "source_ref": source_ref, "method": (method or "GET").upper(),
            "url": clean_url, "headers": clean_headers, "body": clean_body, "raw": raw,
            "truncated": bool(truncated), "redacted": True, "rehydration_required": True}


def _observation_request(conn, finding: dict, engagement_id: str) -> dict | None:
    """The retained capture that produced this finding (same host, pile, exchange id)."""
    from harness import store
    exchange_id = finding.get("exchange_id") or ""
    if not exchange_id:
        return None
    host = urlsplit(finding.get("url") or "").netloc.rpartition("@")[2]
    row = conn.execute(
        "SELECT observation_id, evidence_sha256, evidence_truncated FROM exchange_observations "
        "WHERE host = ? AND engagement_id = ? AND exchange_id = ? AND status = 'active'",
        (host, engagement_id, exchange_id)).fetchone()
    if row is None or not row[1] or not store.evidence_blob_resolves(row[1], conn=conn):
        return None
    try:
        doc = json.loads(store.get_evidence_blob(row[1], conn=conn) or b"{}")
    except ValueError:
        return None
    if not doc.get("url") or not doc.get("method"):
        return None   # a truncated-to-nothing capture is not a request
    return _redacted_request(doc["method"], doc["url"], doc.get("request_headers"),
                             doc.get("request_body"), source="captured_observation",
                             source_ref=row[0],
                             truncated=bool(row[2]) or bool(doc.get("evidence_truncated")))


def _ledger_request(conn, events: list[dict]) -> dict | None:
    """The newest harness send for this finding whose request blob still resolves."""
    from harness import store
    for event in reversed(events):
        if event.get("event_type") != "execution":
            continue
        blob = (event.get("data") or {}).get("request_blob")
        if not blob or not store.evidence_blob_resolves(blob, conn=conn):
            continue
        try:
            doc = json.loads(store.get_evidence_blob(blob, conn=conn) or b"{}")
        except ValueError:
            continue
        if doc.get("url") and doc.get("method"):
            return _redacted_request(doc["method"], doc["url"], doc.get("headers"), doc.get("body"),
                                     source="ledger_execution", source_ref=blob, truncated=False)
    return None


# --------------------------------------------------------------------------- #
# blocked_on facts
# --------------------------------------------------------------------------- #

def _endpoint_key(method: str, url_or_path: str) -> tuple[str, list[str]]:
    path = urlsplit(url_or_path or "").path if "//" in (url_or_path or "") else (url_or_path or "")
    path = path.split("?", 1)[0]
    return (method or "GET").upper(), [s for s in path.split("/") if s]


def _same_endpoint(a: tuple[str, list[str]], b: tuple[str, list[str]]) -> bool:
    """Same method and path; a `{...}` / `:name` template segment matches any value."""
    if a[0] != b[0] or len(a[1]) != len(b[1]):
        return False
    for x, y in zip(a[1], b[1]):
        if x == y or (x.startswith("{") and x.endswith("}")) or (y.startswith("{") and y.endswith("}")) \
                or x.startswith(":") or y.startswith(":"):
            continue
        return False
    return True


def _finding_facts(finding: dict, events: list[dict], investigation: dict) -> list[dict]:
    from harness.confirmation_gate import leg_tier
    facts: list[dict] = []
    if finding.get("_tool_reported"):
        facts.append({"category": TOOL_REPORTED,
                      "fact": "the linked proof is an external tool's detection "
                              "(evidence_source=tool_reported), not reproduced by the harness"})
    for event in events:
        data = event.get("data") or {}
        if event.get("event_type") == "authorization_decision":
            outcome = data.get("outcome") or ""
            if outcome in _IDENTITY_OUTCOMES:
                facts.append({"category": IDENTITY_MISSING, "fact": f"send refused: {outcome}"})
            elif outcome in _BUDGET_OUTCOMES:
                facts.append({"category": BUDGET, "fact": f"send refused: {outcome}"})
        elif data.get("reason_code") == "no_applicable_leg":
            facts.append({"category": NO_LEG, "fact": data.get("not_tested") or "no applicable leg"})
    if leg_tier(finding.get("vulnerability_class")) == "none" and not any(
            f["category"] == NO_LEG for f in facts):
        facts.append({"category": NO_LEG,
                      "fact": "no deterministic confirmation leg exists for this class"})
    key = _endpoint_key(finding.get("method") or "GET", finding.get("url") or "")
    for block in investigation.get("prerequisite_blocks") or []:
        method, _, path = str(block.get("endpoint") or "").partition(" ")
        if _same_endpoint(key, _endpoint_key(method, path)):
            facts.append({"category": IDENTITY_MISSING,
                          "fact": f"{block.get('missing') or 'identity missing'} "
                                  f"({block.get('identity') or 'unknown identity'})"})
    for skip in ((investigation.get("worklist_summary") or {}).get("skipped") or []):
        category = _SKIP_CATEGORY.get(skip.get("reason") or "")
        if category and _same_endpoint(key, _endpoint_key(skip.get("method") or "GET",
                                                          skip.get("path") or "")):
            facts.append({"category": category, "fact": f"worklist skipped: {skip['reason']}"})
    return _dedupe(facts)


def _dedupe(facts: list[dict]) -> list[dict]:
    seen, out = set(), []
    for f in facts:
        k = (f["category"], f["fact"])
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out


def _primary(facts: list[dict]) -> str | None:
    present = {f["category"] for f in facts}
    return next((c for c in _BLOCKED_PRIORITY if c in present), None)


def _experiment_category(task: dict) -> tuple[str | None, str]:
    blocked = task.get("blocked_on") or {}
    category = blocked.get("category") or ""
    reason = task.get("reason") or ""
    detail = "; ".join(str(i) for i in (blocked.get("inputs") or [reason]) if i) or category
    if category == "operator_input":
        return OPERATOR_INPUT, detail
    if category == "disabled":
        return OPERATOR_INPUT, f"disabled: {detail} (the operator must enable it)"
    if category == "budget":
        return (DEADLINE if reason == _STAGE_DEADLINE else BUDGET), detail
    return None, f"{category or task.get('status') or 'unknown'}: {detail}"


# --------------------------------------------------------------------------- #
# Assembly
# --------------------------------------------------------------------------- #

def _lead_id(kind: str, ref: str) -> str:
    return hashlib.sha256(json.dumps([kind, ref]).encode()).hexdigest()[:20]


def _rank_key(lead: dict) -> tuple:
    """Deterministic: a lead with a request first, then severity, confidence
    (higher first), the blocker's priority (unblocked first), url, lead_id."""
    blocker = lead["blocked_on"]
    order = -1 if blocker is None else _BLOCKED_PRIORITY.index(blocker)
    return (0 if lead["request"] else 1, _SEVERITY_ORDER.get(lead["severity"], 9),
            -float(lead["confidence"] or 0.0), order, lead["url"], lead["lead_id"])


def _is_candidate(finding: dict) -> bool:
    from harness.confirmation_gate import finding_triage
    from harness.evidence import is_tool_reported
    if (finding.get("vulnerability_class") or "").startswith("potential-attack-chain:"):
        return False
    if finding.get("confirmed"):
        finding["_tool_reported"] = is_tool_reported(finding)
        return finding["_tool_reported"]
    return finding_triage(finding)["evidence_maturity"] in _OPEN_MATURITIES


def _finding_lead(conn, finding: dict, events: list[dict], investigation: dict,
                  engagement_id: str) -> dict:
    from harness import issues
    from harness.confirmation_gate import finding_triage
    request = _observation_request(conn, finding, engagement_id) or _ledger_request(conn, events)
    location = finding.get("parameter_location") or ""
    name = finding.get("parameter_name") or ""
    suggested = issues.redact(finding.get("suggested_test") or "")
    change, expected = _change_for(finding.get("vulnerability_class") or "", location, name, suggested)
    facts = _finding_facts(finding, events, investigation)
    ref = finding.get("finding_id") or finding.get("fingerprint") or ""
    return {
        "lead_id": _lead_id("finding", ref), "rank": 0, "kind": "finding",
        "finding_id": finding.get("finding_id") or "", "fingerprint": finding.get("fingerprint") or "",
        "vulnerability_class": finding.get("vulnerability_class") or "",
        "severity": finding.get("severity") or "info",
        "confidence": float(finding.get("confidence") or 0.0),
        "evidence_maturity": ("tool_reported" if finding.get("_tool_reported")
                              else finding_triage(finding)["evidence_maturity"]),
        "lifecycle_state": finding.get("lifecycle_state") or "",
        "method": (finding.get("method") or "").upper(),
        "url": issues.redact_url(finding.get("url") or ""),
        "parameter": {"location": location, "name": name},
        "identity": {"captured_principal_id": finding.get("captured_principal_id") or "",
                     "principal_id": finding.get("principal_id") or ""},
        "request": request,
        "no_request_reason": None if request else NO_REQUEST_FINDING,
        "change": change, "expected": expected,
        "blocked_on": _primary(facts), "blocked_facts": facts,
        "suggested_test": suggested,
    }


def _empty_lead(kind: str, ref: str, **fields) -> dict:
    lead = {"lead_id": _lead_id(kind, ref), "rank": 0, "kind": kind, "finding_id": "",
            "fingerprint": "", "vulnerability_class": "", "severity": "info", "confidence": 0.0,
            "evidence_maturity": "unverified", "lifecycle_state": "", "method": "", "url": "",
            "parameter": {"location": "", "name": ""},
            "identity": {"captured_principal_id": "", "principal_id": ""},
            "request": None, "no_request_reason": "", "change": "",
            "expected": {"positive": "", "negative": ""}, "blocked_on": None,
            "blocked_facts": [], "suggested_test": ""}
    lead.update(fields)
    return lead


def _investigation_leads(investigation: dict, finding_leads: list[dict]) -> list[dict]:
    from harness import issues
    out = []
    for task in ((investigation.get("experiment_preflight") or {}).get("tasks") or []):
        if task.get("status") == "completed" or not task.get("task_id"):
            continue
        category, detail = _experiment_category(task)
        facts = [{"category": category or "untyped", "fact": issues.redact(detail)}]
        out.append(_empty_lead(
            "experiment", str(task["task_id"]),
            vulnerability_class=f"experiment:{task.get('hypothesis_id') or task['task_id']}",
            no_request_reason=NO_REQUEST_EXPERIMENT,
            change=issues.redact(f"supply what blocks it, then run the experiment ({detail})"),
            expected={"positive": "the experiment's attack leg differs from its controls",
                      "negative": "attack and control legs match"},
            blocked_on=category, blocked_facts=facts))
    for block in investigation.get("prerequisite_blocks") or []:
        method, _, path = str(block.get("endpoint") or "").partition(" ")
        key = _endpoint_key(method, path)
        if any(_same_endpoint(key, _endpoint_key(l["method"], l["url"])) for l in finding_leads):
            continue   # already attached to that endpoint's finding lead
        out.append(_empty_lead(
            "prerequisite", f"{block.get('endpoint')}|{block.get('identity')}",
            method=(method or "").upper(), url=issues.redact_url(path),
            identity={"captured_principal_id": "", "principal_id": str(block.get("identity") or "")},
            no_request_reason=NO_REQUEST_PREREQUISITE,
            change=issues.redact(str(block.get("action") or "capture this request as the identity")),
            expected={"positive": "the captured request lets the blocked checks run",
                      "negative": "the request cannot be made as this identity"},
            blocked_on=IDENTITY_MISSING,
            blocked_facts=[{"category": IDENTITY_MISSING,
                            "fact": f"{block.get('missing') or 'identity missing'}; "
                                    f"{int(block.get('checks_affected') or 0)} check(s) blocked"}]))
    return out


def build_leads(url: str, *, engagement_id: str = "", captured_principal: str | None = None,
                investigation: dict | None = None) -> list[dict]:
    """Every lead for `url`'s host, ranked. `investigation` is an optional
    investigate_engagement result for the same host (its experiment_preflight,
    prerequisite_blocks and worklist_summary.skipped feed blocked_on)."""
    from harness import store
    investigation = investigation if isinstance(investigation, dict) else {}
    partition = store._engagement_partition(engagement_id)
    findings = [f for f in store.all_host_findings(url, engagement_id=engagement_id,
                                                   captured_principal=captured_principal)
                if _is_candidate(f)]
    events = store.ledger_events_for_many([f.get("finding_id") or "" for f in findings],
                                          engagement_id=engagement_id,
                                          captured_principal=captured_principal)
    conn = store._connect()
    try:
        leads = [_finding_lead(conn, f, events.get(f.get("finding_id") or "", []), investigation,
                               partition) for f in findings]
    finally:
        conn.close()
    leads += _investigation_leads(investigation, leads)
    leads.sort(key=_rank_key)
    for i, lead in enumerate(leads, 1):
        lead["rank"] = i
    return leads


# --------------------------------------------------------------------------- #
# Report: reproduction text (HU-2 c)
# --------------------------------------------------------------------------- #

NO_REPRO_TEXT = "no reproducible request recorded"


def report_repro_lines(finding_id: str, suggested_test: str = "") -> list[str]:
    """Markdown lines for one finding's reproduction: the evidence ledger's
    reproduction_recipe when it recorded a send, else the explicit
    "no reproducible request recorded". A detector's non-remediation
    `suggested_test` is kept as the step text. Never a generic replay hint."""
    from harness import evidence_ledger, issues
    steps = []
    if finding_id:
        try:
            steps = evidence_ledger.reproduction_recipe_persisted(finding_id).get("steps") or []
        except Exception:
            steps = []
    steps = [s for s in steps if s.get("request")]
    lines = []
    if suggested_test:
        lines.append(f"**Steps to reproduce:** {suggested_test}")
    elif steps:
        lines.append("**Steps to reproduce:** send the recorded request(s) below from the "
                     "evidence ledger's reproduction recipe.")
    else:
        lines.append(f"**Steps to reproduce:** {NO_REPRO_TEXT}.")
    if steps:
        lines.append("**Recorded request(s) (reproduction recipe):**")
        for step in steps:
            method = (step.get("method") or "").upper() or "(method not recorded)"
            state = ("replayable; secrets redacted, fill the session before sending"
                     if step.get("replayable") else "reference only, not replayable")
            response = step.get("response") or "no response recorded"
            lines.append(f"- `{method} {issues.redact_url(str(step['request']))}` -> "
                         f"{str(response).replace('`', chr(39))} ({state})")
    elif suggested_test:
        lines.append(f"_{NO_REPRO_TEXT[0].upper()}{NO_REPRO_TEXT[1:]}; the step above is the "
                     f"detector's suggestion._")
    lines.append("")
    return lines
