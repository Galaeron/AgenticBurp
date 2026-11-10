"""HU-6: draft write-ups for proven issues, bound to the proof facts.

Read-only; sends no target traffic. A write-up is drafted only for a
PROOF-BOUND issue: one whose export evidence_state is ``confirmed`` and that
links a recorded, executed, non-legacy, harness-reproduced (never
``tool_reported``) proof attempt with verdict ``confirmed`` whose attack
exchange still resolves from the evidence-blob store. Candidates, tool-reported
detections and unverified findings never get one.

Every statement is built from the proof facts (``_proof_facts``):

  - principals: the crossing principal and the owner/entitled principal named
    by the proof's own verdict text, plus the proof case's principal;
  - the object (the attack request's path) and the fields the attack response
    returned (JSON keys, flattened), with those whose values are redacted
    marked sensitive;
  - endpoints: the issue's method + endpoint family and each affected instance;
  - the redacted attack request/response, and the control outcome;
  - reproduction steps from ``evidence_ledger.reproduction_recipe``.

The default draft is a deterministic template (no model call). With
``writeups.model_phrasing`` on, a loopback model may rephrase the impact and the
specific remediation sentences only. ``fact_binding_violations`` rejects any
draft -- template or model -- that names a field, endpoint or principal absent
from the proof; a rejected model draft falls back to the template.

Config (``writeups``; everything SHIPPED OFF):
  export_markdown: attach ``writeup`` {filename, markdown, ...} to each
    proof-bound issue in report_generator.export_issues_for_host (one Markdown
    file per issue; ``write_files`` saves them). Off: the export is unchanged.
  model_phrasing: let the model rephrase (loopback Ollama only).
  model: model name; "" uses agent_defaults.model.
"""
from __future__ import annotations

import asyncio
import json
import re
from urllib.parse import urlsplit

TEMPLATE = "template"
MODEL = "model"

_BASELINE, _ATTACK, _CONTROL = "baseline", "attack", "control"
_MAX_BODY = 2000
_MAX_FIELDS = 25


def settings(config: dict | None) -> dict:
    raw = (config or {}).get("writeups") or {}
    return {"export_markdown": bool(raw.get("export_markdown", False)),
            "model_phrasing": bool(raw.get("model_phrasing", False)),
            "model": str(raw.get("model") or "")}


# --------------------------------------------------------------------------- #
# Proof facts
# --------------------------------------------------------------------------- #

# The harness's own validator verdict phrasings (cross_identity_validator), not
# anything application-specific: who crossed, and who was entitled.
_ACTOR_PATTERNS = (re.compile(r"Cross-identity \(([^)\s]+)\)"),
                   re.compile(r"does not entitle (?:the source principal )?'([^']+)'"),
                   re.compile(r"non-privileged identity '([^']+)'"),
                   re.compile(r"does not include '([^']+)'"))
_OWNER_PATTERNS = (re.compile(r"entitled principal '([^']+)'"),)
# Who the captured session belongs to, when the verdict says so.
_CAPTURED_BY_PATTERNS = (re.compile(r"the captured read by '([^']+)'"),)

# A captured session is a session reference ("captured") or an opaque captured
# auth context ("captured:<digest>"), never a principal. A write-up names the
# principal behind it when the run maps it to one, and this label otherwise.
UNMAPPED_CAPTURED = "a captured session (unmapped)"
_CAPTURED_LABEL = re.compile(r"^captured(?::[0-9a-f]+)?$")


def _is_captured(label: str) -> bool:
    return bool(_CAPTURED_LABEL.match(label or ""))


def _attributed_principal(captured_id: str, engagement_id: str) -> str:
    """The analyst-attributed principal of an opaque captured auth context: the
    one principal_ref every current attribution of its observations names, or ''."""
    from harness import store
    if not captured_id.startswith("captured:"):
        return ""
    conn = store._connect()
    try:
        rows = conn.execute(
            "SELECT a.principal_ref FROM observation_attributions a JOIN exchange_observations o "
            "ON o.observation_id = a.observation_id WHERE o.captured_principal_id = ? "
            "AND o.engagement_id = ? AND a.revision = (SELECT MAX(b.revision) FROM "
            "observation_attributions b WHERE b.observation_id = a.observation_id)",
            (captured_id, engagement_id or "")).fetchall()
    except Exception:
        return ""
    finally:
        conn.close()
    names = {r[0] for r in rows}
    return next(iter(names)) if len(names) == 1 and next(iter(names)) else ""


def _name_captured(label: str, *, texts, engagement_id: str, captured_principal: str | None) -> str:
    """`label` itself unless it is a captured session; then the principal the run
    maps it to, or UNMAPPED_CAPTURED."""
    if not _is_captured(label):
        return label
    named = _first(_CAPTURED_BY_PATTERNS, texts)
    if named and not _is_captured(named):
        return named
    context = label if label != "captured" else (captured_principal or "")
    return _attributed_principal(context, engagement_id) or UNMAPPED_CAPTURED


def _first(patterns, texts) -> str:
    for text in texts:
        for pat in patterns:
            m = pat.search(text or "")
            if m:
                return m.group(1)
    return ""


def _path_of(url: str) -> str:
    try:
        return urlsplit(url or "").path or "/"
    except ValueError:
        return "/"


def _load_blob(sha: str, conn) -> dict | None:
    from harness import store
    if not sha or not store.evidence_blob_resolves(sha, conn=conn):
        return None
    try:
        doc = json.loads(store.get_evidence_blob(sha, conn=conn) or b"{}")
    except ValueError:
        return None
    return doc if isinstance(doc, dict) else None


def _render_response(doc: dict) -> str:
    from harness import issues, security
    headers = {str(k): issues.redact(str(v))
               for k, v in security.redact_headers(dict(doc.get("headers") or {})).items()}
    body = doc.get("body")
    body = "" if body is None else issues.redact(str(security.redact_secrets_in_body(body)))
    truncated = len(body) > _MAX_BODY
    lines = [f"HTTP/1.1 {doc.get('status')}"] + [f"{k}: {v}" for k, v in headers.items()]
    return "\n".join(lines) + "\n\n" + body[:_MAX_BODY] + ("\n[... truncated]" if truncated else "")


def _flatten_keys(value, prefix: str = "", out: dict | None = None) -> dict:
    out = {} if out is None else out
    if isinstance(value, dict):
        for k, v in value.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, (dict, list)) and v:
                _flatten_keys(v, key, out)
            else:
                out.setdefault(key, v)
    elif isinstance(value, list):
        for item in value[:3]:
            _flatten_keys(item, prefix, out)
    return out


def _response_fields(doc: dict | None) -> dict:
    """Top-level-and-nested JSON keys of a (redacted) response body -> value."""
    if not doc:
        return {}
    from harness import security
    body = doc.get("body")
    try:
        parsed = json.loads(security.redact_secrets_in_body(body)) if isinstance(body, str) else body
    except (TypeError, ValueError):
        return {}
    return _flatten_keys(parsed) if isinstance(parsed, (dict, list)) else {}


def _is_redacted(value) -> bool:
    return isinstance(value, str) and "REDACTED" in value.upper()


def _executions(refs: list[str], *, engagement_id: str, captured_principal: str | None) -> dict:
    """artifact_id -> (ref, index-in-ref, event data) for every persisted send."""
    from harness import store
    events = store.ledger_events_for_many(refs, engagement_id=engagement_id or None,
                                          captured_principal=captured_principal)
    out = {}
    for ref in refs:
        executions = [e for e in events.get(ref, []) if e.get("event_type") == "execution"]
        for i, event in enumerate(executions):
            data = event.get("data") or {}
            if data.get("artifact_id"):
                out.setdefault(data["artifact_id"], (ref, i, data))
    return out


def _proof_for(export: dict, proofs_by_case: dict) -> dict | None:
    from harness.evidence import is_tool_reported
    for ref in export.get("proof_references") or []:
        if ref.get("verdict") != "confirmed" or not ref.get("proof_id"):
            continue
        attempts = proofs_by_case.get(ref.get("case_id")) or []
        attempts = [attempts] if isinstance(attempts, dict) else attempts
        for p in attempts:
            if (p.get("proof_id") == ref["proof_id"] and p.get("verdict") == "confirmed"
                    and p.get("executed") and not p.get("legacy") and not is_tool_reported(p)
                    and p.get("attack_artifact_id")):
                return p
    return None


def proof_bound(export: dict, proofs_by_case: dict | None) -> dict | None:
    """The confirmed proof attempt backing `export`, or None (not proof-bound)."""
    if export.get("evidence_state") != "confirmed" or not export.get("confirmed"):
        return None
    return _proof_for(export, proofs_by_case or {})


def _proof_facts(export: dict, proof: dict, *, engagement_id: str = "",
                 captured_principal: str | None = None) -> dict | None:
    """Everything a write-up may state, read from the proof and its artifacts.
    None when the attack exchange no longer resolves (then it is not proof-bound)."""
    from harness import evidence_ledger, issues, store
    from harness.leads import _redacted_request
    case = proof.get("case") or {}
    case_id, finding_ref = case.get("case_id") or "", case.get("finding_ref") or ""
    refs = [r for r in dict.fromkeys([case_id, finding_ref]) if r]
    sends = _executions(refs, engagement_id=engagement_id, captured_principal=captured_principal)
    roles = {proof.get("attack_artifact_id"): _ATTACK}
    if proof.get("baseline_artifact_id"):
        roles[proof["baseline_artifact_id"]] = _BASELINE
    for cid in proof.get("control_artifact_ids") or []:
        roles[cid] = _CONTROL
    conn = store._connect()
    try:
        legs: dict[str, list[dict]] = {_BASELINE: [], _ATTACK: [], _CONTROL: []}
        for artifact_id, role in roles.items():
            if artifact_id not in sends:
                continue
            data = sends[artifact_id][2]
            req = _load_blob(data.get("request_blob") or "", conn)
            resp = _load_blob(data.get("response_blob") or "", conn)
            if not req or not resp or not req.get("url"):
                continue
            legs[role].append({"artifact_id": artifact_id, "request": req, "response": resp})
    finally:
        conn.close()
    if not legs[_ATTACK]:
        return None
    attack = legs[_ATTACK][0]
    baseline = legs[_BASELINE][0] if legs[_BASELINE] else None

    # Verdict text the proof itself recorded (observed_result) and the ledger's
    # VALIDATION_DECISION evidence for the same case.
    texts = [proof.get("observed_result") or ""]
    for ref in refs:
        for e in store.ledger_events_for(ref, engagement_id=engagement_id or None,
                                         captured_principal=captured_principal):
            if e.get("event_type") == "validation_decision":
                texts.append(str((e.get("data") or {}).get("evidence") or ""))
    def name(label: str) -> str:
        return _name_captured(label, texts=texts, engagement_id=engagement_id,
                              captured_principal=captured_principal) if label else ""
    case_principal = name(case.get("principal_id") or "")
    actor = name(_first(_ACTOR_PATTERNS, texts))
    owner = name(_first(_OWNER_PATTERNS, texts)) or case_principal
    if owner == actor:
        owner = ""
    principals = {p for p in (actor, owner, case_principal) if p}

    attack_fields = _response_fields(attack["response"])
    base_fields = _response_fields(baseline["response"]) if baseline else {}
    shared = [k for k, v in attack_fields.items() if k in base_fields and base_fields[k] == v]
    fields = (shared or list(attack_fields))[:_MAX_FIELDS]
    sensitive = [k for k in fields if _is_redacted(attack_fields.get(k))]
    parameter = export.get("affected_input") or ""
    parameter = "" if parameter.startswith("(") else parameter

    method = (attack["request"].get("method") or export.get("method") or "GET").upper()
    attack_url = issues.redact_url(attack["request"]["url"])
    object_path = _path_of(attack_url)
    endpoint_family = export.get("endpoint_family") or object_path
    instances = [_path_of(u) for u in export.get("affected_instances") or []]
    endpoints = {(method, p) for p in (object_path, endpoint_family, *instances)}
    for leg in legs[_BASELINE] + legs[_ATTACK] + legs[_CONTROL]:
        endpoints.add(((leg["request"].get("method") or "GET").upper(),
                       _path_of(issues.redact_url(leg["request"]["url"]))))
    host = export.get("host") or ""

    controls = [{"status": c["response"].get("status"),
                 "principal": "unauthenticated" if not (c["request"].get("headers") or {}) else ""}
                for c in legs[_CONTROL]]

    # Reproduction recipe steps, each labelled with its proof role by matching
    # the ledger execution it was built from (same ref, same order).
    by_position = {(ref, i): roles.get(aid) for aid, (ref, i, _d) in sends.items()}
    steps = []
    for ref in refs:
        try:
            recipe = evidence_ledger.reproduction_recipe_persisted(
                ref, engagement_id=engagement_id or None, captured_principal=captured_principal)
        except Exception:
            continue
        for i, step in enumerate(recipe.get("steps") or []):
            if step.get("request"):
                steps.append({**step, "role": by_position.get((ref, i)) or ""})
        if steps:
            break
    for step in steps:
        endpoints.add(((step.get("method") or "GET").upper(),
                       _path_of(issues.redact_url(str(step["request"])))))

    return {
        "issue_id": export.get("issue_id") or "", "proof_id": proof.get("proof_id") or "",
        "case_id": case_id, "validator": proof.get("validator") or "",
        "vulnerability_class": export.get("vulnerability_class") or "",
        "severity": export.get("severity") or "", "host": host,
        "method": method, "endpoint_family": endpoint_family, "object": object_path,
        "paths": sorted({p for _m, p in endpoints}),
        "endpoints": sorted(f"{m} {p}" for m, p in endpoints), "instances": export.get("affected_instances") or [],
        "attack_url": attack_url, "actor": actor, "owner": owner,
        "principals": sorted(principals), "fields": fields, "sensitive_fields": sensitive,
        "parameter": parameter, "controls": controls,
        "attack_status": attack["response"].get("status"),
        "baseline_status": baseline["response"].get("status") if baseline else None,
        "observed": issues.redact(proof.get("observed_result") or "")[:600],
        "request_raw": _redacted_request(
            method, attack["request"]["url"], attack["request"].get("headers"),
            attack["request"].get("body"), source="proof_attack",
            source_ref=attack["artifact_id"], truncated=False)["raw"].replace("\r\n", "\n"),
        "response_raw": _render_response(attack["response"]),
        "steps": steps,
    }


# --------------------------------------------------------------------------- #
# Template
# --------------------------------------------------------------------------- #

_ACCESS_KEYS = ("idor", "bola", "bfla", "access control", "access_control", "authorization",
                "authz", "privilege", "horizontal", "vertical", "tenant", "ownership")
# (class keys, the missing check, what a successful exploit enables) -- generic per family.
_CHECKS = (
    (("sql", "sqli"), "parameterized queries: bind {target} as data, never as SQL text",
     "read or alter database records through the injected input"),
    (("nosql",), "type and operator validation of {target} before it reaches the query",
     "widen the query to records or logins it should not match"),
    (("xss", "cross-site scripting", "html injection"),
     "context-aware output encoding of {target} where the response renders it",
     "run script in another user's session on this origin"),
    (("ssti", "template"), "keeping {target} out of template source (render it as data)",
     "evaluate expressions on the server"),
    (("command", "rce", "os injection"), "never passing {target} to a shell (fixed argv, allow-list)",
     "run commands on the server"),
    (("ssrf", "server-side request"), "an allow-list of destinations for {target}",
     "make the server send requests to internal or chosen hosts"),
    (("traversal", "lfi", "file inclusion"), "canonicalizing {target} and confining it to the allowed directory",
     "read files outside the intended directory"),
    (("redirect",), "an allow-list of redirect targets for {target}",
     "send users to an attacker-chosen site from a trusted link"),
    (("csrf",), "an anti-CSRF token or same-site check on the state-changing request",
     "make a signed-in user perform the action unknowingly"),
    (("mass assignment", "mass_assignment", "overposting"), "an allow-list of client-writable fields",
     "set fields the client should not control"),
)


def _code(x) -> str:
    # The unmapped-captured label is prose, not a principal name to quote.
    return x if x == UNMAPPED_CAPTURED else f"`{x}`"


def _object_of(owner: str) -> str:
    """'`alice`'s object', or for the unmapped captured label 'an object of a
    captured session (unmapped)'."""
    if owner == UNMAPPED_CAPTURED:
        return f"an object of {UNMAPPED_CAPTURED}"
    return f"{_code(owner)}'s object"


def _join(items) -> str:
    items = [_code(i) for i in items]
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def _is_access(facts: dict) -> bool:
    lowered = (facts["vulnerability_class"] or "").lower()
    return facts["validator"] == "cross_identity" or any(k in lowered for k in _ACCESS_KEYS)


def _is_function_level(facts: dict) -> bool:
    lowered = (facts["vulnerability_class"] + " " + facts["observed"]).lower()
    return "function-level" in lowered or "bfla" in lowered or "function level" in lowered


def _control_phrase(facts: dict) -> str:
    denied = [c for c in facts["controls"] if c.get("status") is not None]
    if not denied:
        return ""
    c = denied[0]
    who = "the unauthenticated control" if c.get("principal") == "unauthenticated" else "the control request"
    return f", while {who} got HTTP {c['status']}"


def _impact(facts: dict) -> str:
    endpoint = _code(f"{facts['method']} {facts['object']}")
    fields = facts["fields"]
    field_phrase = (f"the fields {_join(fields)}" if fields
                    else f"an HTTP {facts['attack_status']} response")
    if _is_access(facts) and facts["actor"]:
        whose = _object_of(facts["owner"]) if facts["owner"] else "another principal's object"
        sensitive = (f", including {_join(facts['sensitive_fields'])} (values redacted here)"
                     if facts["sensitive_fields"] else "")
        if _is_function_level(facts):
            return (f"{_code(facts['actor'])}, a principal not entitled to the function, called "
                    f"{endpoint} and received {field_phrase}, the same privileged response "
                    f"{_code(facts['owner']) if facts['owner'] else 'a privileged principal'} gets"
                    f"{_control_phrase(facts)}. This lets {_code(facts['actor'])} use a privileged "
                    f"function its role should not reach{sensitive}.")
        return (f"{_code(facts['actor'])} read {whose} at {endpoint} and received "
                f"{field_phrase}{_control_phrase(facts)}. This lets {_code(facts['actor'])} read "
                f"objects that belong to other principals{sensitive} by requesting their reference "
                f"directly.")
    principal = facts["actor"] or (facts["principals"][0] if facts["principals"] else "")
    who = _code(principal) if principal else "the tester"
    target = f", varying {_code(facts['parameter'])}" if facts["parameter"] else ""
    enables = next((e for keys, _c, e in _CHECKS
                    if any(k in facts["vulnerability_class"].lower() for k in keys)), "")
    return (f"A request by {who} to {endpoint}{target} confirmed "
            f"{_code(facts['vulnerability_class'])} and returned {field_phrase}"
            f"{_control_phrase(facts)}." + (f" This lets an attacker {enables}." if enables else ""))


def _specific_remediation(facts: dict) -> str:
    endpoint = _code(f"{facts['method']} {facts['endpoint_family']}")
    if _is_access(facts):
        if _is_function_level(facts):
            check = ("a server-side function-level authorization check: verify the requesting "
                     "principal's role is entitled to this function before running it")
        else:
            check = ("a server-side object-level authorization check: before returning the object, "
                     "verify the requesting principal owns it or is explicitly entitled to it")
        deny = ""
        if facts["actor"]:
            whose = _object_of(facts["owner"]) if facts["owner"] else "the object"
            deny = f" {_code(facts['actor'])} must get a denial (403 or 404) for {whose}"
            if facts["sensitive_fields"]:
                deny += f", and never its {_join(facts['sensitive_fields'])}"
            deny += "."
        return f"On {endpoint}, add {check}.{deny}"
    target = _code(facts["parameter"]) if facts["parameter"] else "the request input"
    check = next((c for keys, c, _e in _CHECKS
                  if any(k in facts["vulnerability_class"].lower() for k in keys)),
                 "a fix for the condition the proof shows for {target}")
    return f"On {endpoint}, the missing check is {check.format(target=target)}."


def _steps_lines(facts: dict) -> list[str]:
    from harness import issues
    labels = {_ATTACK: f"as {_code(facts['actor'])} (the proof's attack request)" if facts["actor"]
              else "(the proof's attack request)",
              _BASELINE: f"as {_code(facts['owner'])} (baseline)" if facts["owner"] else "(baseline)",
              _CONTROL: "without a session (control)"}
    lines = []
    if not facts["steps"]:
        return ["1. no reproducible request recorded."]
    n = 1
    if facts["actor"]:
        lines.append(f"{n}. Establish a session for {_code(facts['actor'])}"
                     + (f" and for {_code(facts['owner'])}" if facts["owner"] else "")
                     + "; the recorded requests carry placeholders, not live secrets.")
        n += 1
    for step in facts["steps"]:
        method = (step.get("method") or "").upper() or "(method not recorded)"
        url = issues.redact_url(str(step.get("request") or ""))
        who = labels.get(step.get("role") or "", "")
        expected = step.get("response") or "no response recorded"
        state = "" if step.get("replayable") else " (reference only, not replayable)"
        lines.append(f"{n}. Send {_code(f'{method} {_path_of(url)}')} {who} and expect "
                     f"{str(expected).replace('`', chr(39))}{state}.".replace("  ", " "))
        n += 1
    return lines


def render(facts: dict, *, impact: str | None = None, remediation: str | None = None) -> str:
    """The Markdown write-up. `impact`/`remediation` replace the template sentences
    (the model's rephrasing); everything else is always the template."""
    from harness.report_generator import _remediation_for
    title = (f"{facts['vulnerability_class']} on "
             f"{_code(facts['method'] + ' ' + facts['endpoint_family'])}")
    lines = [f"# {title}", "",
             f"- Issue: {_code(facts['issue_id'])}; severity {facts['severity'] or 'unrated'}; "
             f"proof {_code(facts['proof_id'])} (validator {_code(facts['validator'])})",
             f"- Host: {facts['host']}",
             f"- Endpoints: " + ", ".join(_code(e) for e in facts["endpoints"]),
             f"- Principals: " + (_join(facts["principals"]) or "none recorded"),
             "", "## Impact", "", impact or _impact(facts), "",
             "## Proof", "", "Attack request (secrets redacted; fill the session before sending):",
             "", "```http", facts["request_raw"].rstrip(), "```", "",
             "Attack response (secrets redacted):", "", "```http", facts["response_raw"].rstrip(),
             "```", ""]
    if facts["observed"]:
        lines += [f"Recorded verdict: {facts['observed']}", ""]
    lines += ["## Steps to reproduce", "", *_steps_lines(facts), "",
              "## Remediation", "", remediation or _specific_remediation(facts), "",
              f"General guidance: {_remediation_for(facts['vulnerability_class'])}", ""]
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Fact binding
# --------------------------------------------------------------------------- #

_FENCE = re.compile(r"```.*?```", re.S)
_BACKTICK = re.compile(r"`([^`\n]+)`")
_QUOTED = re.compile(r"(?<![\w])['\"]([^'\"\n]{1,80})['\"](?![\w])")
_URL = re.compile(r"https?://[^\s`'\")<>]+")
_PATH = re.compile(r"(?<![\w/:.`-])(/[A-Za-z0-9_{}\-.~%:/]+)")
_IDENT = re.compile(r"\b(?:[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)+|[a-z]+[A-Z][A-Za-z0-9]*"
                    r"|[A-Za-z][A-Za-z0-9]*(?:\.[A-Za-z][A-Za-z0-9]*)+)\b")
_PRINCIPAL = re.compile(r"(?i)\b(?:principal|identity|user|account)\s+[`'\"]?([A-Za-z0-9_.@-]+)")
_PRINCIPAL_STOP = frozenset("""a an the that this who whose which with of is was must can may
    to in on and or not it its any every each other another same role roles session sessions
    named called id ids b a1 b1 not-entitled like as by for from has had have be owns own
    owned sees saw gets got receives received reads read requests requested requesting sends
    sent should could would will cannot does did gets must also only then here there their
    level levels data object objects function functions types type""".split())
_GENERIC_IDENTS = frozenset({"e.g", "i.e"})
_METHODS = ("GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "TRACE")


def _fact_tokens(facts: dict) -> set[str]:
    tokens = {facts["issue_id"], facts["proof_id"], facts["case_id"], facts["validator"],
              facts["vulnerability_class"], facts["method"], facts["host"], facts["attack_url"],
              facts["parameter"], *facts["principals"], *facts["fields"], *facts["paths"],
              *facts["instances"]}
    for field in facts["fields"]:
        tokens.update(field.split("."))
    tokens.update(facts["endpoints"])
    host_path = urlsplit(facts["host"] or "").netloc
    if host_path:
        tokens.add(host_path)
    return {t for t in tokens if t}


def _known_path(path: str, facts: dict, method: str = "") -> bool:
    """A recorded endpoint's path (any method, or exactly `method`); a `{...}`
    template segment matches any value."""
    from harness.leads import _endpoint_key, _same_endpoint
    path = path.rstrip(".,;:)")
    for endpoint in facts["endpoints"]:
        m, _, p = endpoint.partition(" ")
        if (not method or m == method) and _same_endpoint(_endpoint_key("GET", path), _endpoint_key("GET", p)):
            return True
    return False


def _span_ok(span: str, tokens: set[str], facts: dict) -> bool:
    span = span.strip()
    if span in tokens or "REDACTED" in span.upper():
        return True
    method, _, rest = span.partition(" ")
    if method in _METHODS and rest.startswith("/"):
        return _known_path(rest, facts, method)
    if span.startswith("/"):
        return _known_path(span, facts)
    if span.startswith(("http://", "https://")):
        return _url_ok(span, facts)
    return False


def _url_ok(url: str, facts: dict) -> bool:
    url = url.rstrip(".,;:)")
    host = facts["host"].rstrip("/")
    return bool(host) and (url == host or url.startswith(host + "/") and _known_path(_path_of(url), facts))


def fact_binding_violations(markdown: str, facts: dict, *, allowed_text: tuple[str, ...] = ()) -> list[str]:
    """Every field, endpoint or principal the draft names that the proof does not.
    Fenced blocks (the proof request/response, rendered from the proof itself) and
    `allowed_text` (the fixed class hint) are not scanned. Empty list = bound."""
    text = _FENCE.sub(" ", markdown or "")
    for allowed in allowed_text:
        if allowed:
            text = text.replace(allowed, " ")
    tokens = _fact_tokens(facts)
    violations = []
    for span in _BACKTICK.findall(text):
        if not _span_ok(span, tokens, facts):
            violations.append(f"names {span!r}, which the proof does not contain")
    prose = _BACKTICK.sub(" ", text)
    for url in _URL.findall(prose):
        if not _url_ok(url, facts):
            violations.append(f"names endpoint {url!r}, which the proof does not contain")
    prose = _URL.sub(" ", prose)
    for span in _QUOTED.findall(prose):
        if " " not in span.strip() and not _span_ok(span, tokens, facts):
            violations.append(f"names {span!r}, which the proof does not contain")
    for path in _PATH.findall(prose):
        if not _known_path(path, facts):
            violations.append(f"names endpoint {path!r}, which the proof does not contain")
    for ident in _IDENT.findall(prose):
        if ident not in tokens and ident not in _GENERIC_IDENTS:
            violations.append(f"names {ident!r}, which the proof does not contain")
    for name in _PRINCIPAL.findall(_URL.sub(' ', text)):
        if name.lower() not in _PRINCIPAL_STOP and name not in tokens:
            violations.append(f"names principal {name!r}, which the proof does not contain")
    return list(dict.fromkeys(violations))


# --------------------------------------------------------------------------- #
# Optional model phrasing (loopback only; rephrase, never add facts)
# --------------------------------------------------------------------------- #

_SYSTEM = ("You rephrase two sentences of a security write-up. Use ONLY the facts given. "
           "Do not add any field, endpoint, principal, host, or claim that is not in the facts. "
           "Keep every field, endpoint and principal name in backticks exactly as given. "
           "Reply as JSON: {\"impact\": str, \"remediation\": str}.")


def _loopback(base_url: str) -> bool:
    host = (urlsplit(base_url or "").hostname or "").lower()
    return host in ("localhost", "127.0.0.1", "::1") or host.endswith(".localhost")


def _run(coro):
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(1) as pool:
        return pool.submit(asyncio.run, coro).result()


def _model_rephrase(facts: dict, impact: str, remediation: str, config: dict) -> dict | None:
    """{"impact", "remediation"} from the configured loopback model, or None."""
    from harness.ollama_client import OllamaClient
    base_url = ((config or {}).get("ollama") or {}).get("base_url") or "http://localhost:11434"
    if not _loopback(base_url):
        return None   # nothing goes off-host
    model = settings(config)["model"] or ((config or {}).get("agent_defaults") or {}).get("model") or ""
    if not model:
        return None
    user = json.dumps({"facts": {k: facts[k] for k in (
        "vulnerability_class", "method", "endpoint_family", "object", "actor", "owner",
        "principals", "fields", "sensitive_fields", "parameter", "attack_status")},
        "impact": impact, "remediation": remediation})
    try:
        reply = _run(OllamaClient(base_url).chat_json(model, _SYSTEM, user, temperature=0.1))
    except Exception:
        return None
    if not isinstance(reply, dict):
        return None
    out = {k: str(reply.get(k) or "").strip() for k in ("impact", "remediation")}
    return out if all(out.values()) else None


# --------------------------------------------------------------------------- #
# Drafting and export
# --------------------------------------------------------------------------- #

def draft(facts: dict, *, config: dict | None = None) -> dict:
    """{markdown, source, rejected} -- the template, or the model's rephrasing when
    enabled and fact-bound. A template that fails the check is never emitted."""
    from harness.report_generator import _remediation_for
    # The fixed class hint and the proof's own verdict text are not drafted prose.
    hint = (_remediation_for(facts["vulnerability_class"]), facts["observed"])
    template = render(facts)
    problems = fact_binding_violations(template, facts, allowed_text=hint)
    if problems:
        return {"markdown": "", "source": "", "rejected": problems,
                "note": "template failed the fact-binding check; no write-up emitted"}
    result = {"markdown": template, "source": TEMPLATE, "rejected": []}
    if settings(config)["model_phrasing"]:
        phrased = _model_rephrase(facts, _impact(facts), _specific_remediation(facts), config or {})
        if phrased:
            candidate = render(facts, impact=phrased["impact"], remediation=phrased["remediation"])
            problems = fact_binding_violations(candidate, facts, allowed_text=hint)
            if problems:
                result["rejected"] = problems   # fall back to the template
            else:
                result.update(markdown=candidate, source=MODEL)
    return result


def writeup_for(export: dict, proofs_by_case: dict | None, *, config: dict | None = None,
                engagement_id: str = "", captured_principal: str | None = None) -> dict | None:
    proof = proof_bound(export, proofs_by_case)
    if proof is None:
        return None
    facts = _proof_facts(export, proof, engagement_id=engagement_id,
                         captured_principal=captured_principal)
    if facts is None:
        return None
    out = draft(facts, config=config)
    if not out["markdown"]:
        return None
    return {"filename": f"{facts['issue_id'] or facts['proof_id']}.md", "proof_id": facts["proof_id"],
            "source": out["source"], "rejected_model_draft": out["rejected"],
            "markdown": out["markdown"]}


def attach_to_exports(exports: list[dict], proofs_by_case: dict | None, *, config: dict | None = None,
                      engagement_id: str = "", captured_principal: str | None = None) -> list[dict]:
    """report_generator.export_issues_for_host hook: with writeups.export_markdown
    off (the default) returns `exports` untouched; on, adds `writeup` to each
    proof-bound issue and leaves every other issue unchanged."""
    if not settings(config)["export_markdown"]:
        return exports
    for export in exports:
        try:
            w = writeup_for(export, proofs_by_case, config=config, engagement_id=engagement_id,
                            captured_principal=captured_principal)
        except Exception:
            w = None   # a write-up is a convenience; never break the export
        if w is not None:
            export["writeup"] = w
    return exports


def write_files(exports: list[dict], directory) -> list[str]:
    """Save each attached write-up as <directory>/<issue_id>.md; returns the paths."""
    from pathlib import Path
    out_dir = Path(directory)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for export in exports:
        w = export.get("writeup")
        if not w:
            continue
        name = re.sub(r"[^A-Za-z0-9_.-]", "_", w["filename"])
        path = out_dir / name
        path.write_text(w["markdown"], encoding="utf-8")
        paths.append(str(path))
    return paths
