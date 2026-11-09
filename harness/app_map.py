"""app_map.py -- HU-3: the application map, shown to the tester.

A tester's first day goes into drawing this by hand. The harness already holds
most of it, so `build_map` assembles it deterministically from the store, with
no model call and no traffic:

  - roles seen (identities, per-principal access cells, capture attributions);
  - object types with their id patterns and owners (`ownership_facts`);
  - endpoints per object x method x role outcome;
  - client-trusted value fields (price, quantity, role, is_admin, owner ids,
    status flags) found in captured REQUESTS, by field name and value shape;
  - workflows observed: each principal's captures in capture order.

Object types and roles come from HU-1's derivation (`access_matrix.build_draft`
and `access_matrix.object_and_action`), never a second copy of it.

When a stored ApplicationSemanticModel exists (the newest investigation result
that carries one, or one passed in), its hypotheses are overlaid as SEPARATE
entries labelled `basis: "proposed"`. Every item in the map carries a `basis`:
`observed` (it is in the store) or `proposed` (a model said so). A proposed
entry never turns an observed one into a model claim, and a model claim is
never labelled observed, even when it names something that was observed
(`also_observed` says so instead).

`report_section` renders the map for the report; it ships off
(`app_map.report_section: false`), so a default report is unchanged. Nothing
here is specific to one application: names come from route shapes, HTTP
methods and generic field-name/value-shape rules only.
"""
from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from harness import access_matrix

SCHEMA_VERSION = 1
OBSERVED = "observed"
PROPOSED = "proposed"
_MAX_OBSERVATIONS = 2000
_MAX_FIELDS_PER_BODY = 60
_FIELD_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-]{0,63}$")

# Generic client-trusted value rules: (kind, field-name pattern on the
# lower-cased name with separators removed, value shapes accepted). A value of
# None (unknown or redacted) passes any shape: the name alone is then the basis.
_VALUE_RULES = (
    ("role", re.compile(r"^(is|has)?(admin|administrator|superuser|staff|root|moderator)$"
                        r"|role(s|name|id)?$|^privilege|permission|^scopes?$|^groups?$"
                        r"|accesslevel$|^usertype$|^accounttype$"), ("str", "bool", "num", "list")),
    ("price", re.compile(r"price|amount|cost|total$|subtotal|discount|fee$|fees$|balance"
                         r"|credit|charge$|payment$|tax$|^rate$"), ("num", "numstr")),
    ("quantity", re.compile(r"^(qty|quantity|quantities|units|count|itemcount)$"),
     ("num", "numstr")),
    ("identifier", re.compile(r"^(owner|user|account|customer|tenant|org|organization|author"
                              r"|member|buyer|seller)(id|uuid)?$"), ("num", "numstr", "str")),
    ("state", re.compile(r"^(status|state|approved|verified|paid|confirmed|active|enabled"
                         r"|locked|banned|isverified|isactive|isapproved|ispaid)$"),
     ("str", "bool")),
)


# --- small helpers -------------------------------------------------------------------


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


def _shape(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, (int, float)):
        return "num"
    if isinstance(value, list):
        return "list"
    if isinstance(value, dict):
        return "object"
    text = str(value)
    if re.fullmatch(r"-?\d+(\.\d+)?", text):
        return "numstr"
    if text.lower() in ("true", "false"):
        return "bool"
    return "str"


def value_kind(name: str, value=None) -> str | None:
    """The client-trusted kind of one request field ("price", "quantity",
    "role", "identifier", "state"), or None. Name and value shape only."""
    key = _norm(name.rsplit(".", 1)[-1])
    if not key:
        return None
    shape = _shape(value)
    for kind, pattern, shapes in _VALUE_RULES:
        if pattern.search(key) and (shape is None or shape in shapes):
            return kind
    if shape == "bool" and re.match(r"^(is|has|can)_?[a-z]", name.rsplit(".", 1)[-1], re.I):
        return "state"
    return None


def _id_pattern(value: str) -> str:
    if re.fullmatch(r"\d+", value):
        return "integer"
    if re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
                    value):
        return "uuid"
    if re.fullmatch(r"[0-9a-fA-F]{8,}", value):
        return "hex"
    return "opaque"


def _host_forms(host: str) -> set:
    host = (host or "").lower()
    return {host, host.split(":", 1)[0]} - {""}


def _same_host(netloc: str, host: str) -> bool:
    """host:port matches exactly; a bare host matches any port on it."""
    netloc, host = (netloc or "").lower(), (host or "").lower()
    return bool(host) and (netloc == host or (":" not in host and netloc.split(":", 1)[0] == host))


def _principal_label(pid: str) -> str:
    pid = str(pid or "")
    if pid.startswith("captured:") and len(pid) > 21:
        return pid[:21]          # an opaque keyed context: a short stable label is enough
    return pid


def _request_fields(body) -> list:
    """(dotted name, value) pairs of a request body, JSON or form-encoded."""
    if body in (None, ""):
        return []
    try:
        data = json.loads(body) if isinstance(body, (str, bytes)) else body
    except (TypeError, ValueError):
        data = None
    out: list = []
    if isinstance(data, (dict, list)):
        stack = [("", data)]
        while stack and len(out) < _MAX_FIELDS_PER_BODY:
            prefix, value = stack.pop(0)
            if isinstance(value, dict):
                for key, child in value.items():
                    name = f"{prefix}.{key}" if prefix else str(key)
                    if isinstance(child, (dict, list)) and child:
                        stack.append((name, child))
                    out.append((name, child))
            elif isinstance(value, list):
                for child in value[:5]:
                    if isinstance(child, dict):
                        stack.append((prefix, child))
        return out
    if isinstance(body, str) and "=" in body and "\n" not in body:
        return [(k, v) for k, v in parse_qsl(body, keep_blank_values=True)][:_MAX_FIELDS_PER_BODY]
    return []


# --- sources -------------------------------------------------------------------------


def _observations(host: str, engagement_id: str) -> list:
    """This host's retained captures (Orchestrator.analyze -> store.record_observation),
    oldest first by capture time (ingest order when none was supplied). Read-only."""
    from harness import store
    if not Path(store._DB_PATH).exists():
        return []
    conn = store._connect()
    try:
        rows = conn.execute(
            "SELECT observation_id, method, url_redacted, normalized_endpoint, captured_at, "
            "ingested_at, captured_principal_id, facts_json, evidence_sha256, host "
            "FROM exchange_observations WHERE engagement_id = ? AND status != 'deleted' "
            "ORDER BY ingested_at, observation_id LIMIT ?",
            (engagement_id, _MAX_OBSERVATIONS)).fetchall()
        rows = [r for r in rows if _same_host(r[9], host)]
        attributions = store._current_attributions(conn, [r[0] for r in rows])
        out = []
        for (oid, method, url, norm, captured_at, ingested_at, pid, facts, sha, _h) in rows:
            evidence = {}
            blob = store.get_evidence_blob(sha, conn=conn) if sha else None
            if blob:
                try:
                    evidence = json.loads(blob.decode("utf-8", "surrogatepass"))
                except (ValueError, UnicodeDecodeError):
                    evidence = {}
            out.append({"observation_id": oid, "method": (method or "").upper(),
                        "url": url or evidence.get("url") or norm, "captured_at": captured_at,
                        "ingested_at": ingested_at, "principal": pid or "",
                        "facts": json.loads(facts or "{}"),
                        "attribution": attributions.get(oid) or {},
                        "request_body": evidence.get("request_body")})
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()
    out.sort(key=lambda o: (o["captured_at"] is None,
                            o["captured_at"] if o["captured_at"] is not None else o["ingested_at"],
                            o["ingested_at"], o["observation_id"]))
    return out


def _ownership(host: str) -> list:
    """(object key, object type, owner, concrete resource path) per observed
    ownership fact on this host's origin. Public objects have no owner."""
    from harness import store
    from harness.engagement import normalize_path
    if not Path(store._DB_PATH).exists():
        return []
    out = []
    for fact in store.ownership_facts_all():
        ref = str(fact.get("object_ref") or "")
        app = re.search(r"\|app:[a-z]+://([^|]+)\|", ref)
        resource = ref.split("|resource:", 1)[-1] if "|resource:" in ref else ""
        if not app or not _same_host(app.group(1), host) or not resource:
            continue
        if not fact.get("owner_principal_id") or fact.get("public"):
            continue
        path = resource.split("?", 1)[0]
        shape = access_matrix.object_and_action("GET", normalize_path(path))
        if shape:
            out.append((access_matrix.object_key(shape[0]), shape[0],
                        str(fact["owner_principal_id"]), path))
    return sorted(out)


def _asm_dict(asm) -> dict | None:
    if asm is None:
        return None
    if hasattr(asm, "to_dict"):
        return asm.to_dict()
    return asm if isinstance(asm, dict) else None


def stored_semantic_model(host: str) -> tuple[dict | None, str]:
    """(ASM dict, source) from the newest investigation result for `host` that
    carries one, or (None, reason). Read-only: no journal is created to look."""
    from harness import store
    from harness.job_status import JobStatusStore
    path = Path(store._DB_PATH).with_name("harness_jobs.db")
    if not path.exists():
        return None, "no investigation journal"
    try:
        journal = JobStatusStore(path, "app-map-reader")
        jobs = list({j["job_id"]: j for form in sorted(_host_forms(host) | {host})
                     for j in journal.list(form) if j.get("job_id")}.values())
        jobs.sort(key=lambda j: -(j.get("started_at") or 0))
        for job in jobs:
            result = job.get("result")
            if not isinstance(result, dict) and job.get("result_ref"):
                try:
                    result = json.loads(journal.read_result(job["job_id"]))
                except (ValueError, OSError, sqlite3.Error):
                    continue
            if isinstance(result, dict) and isinstance(result.get("application_semantic_model"), dict):
                return result["application_semantic_model"], f"job:{job.get('job_id')}"
    except sqlite3.Error:
        return None, "investigation journal unreadable"
    return None, "no stored semantic model"


# --- the map -------------------------------------------------------------------------


def _outcome_summary(statuses: list) -> str:
    outcomes = {access_matrix._outcome(s) for s in statuses}
    if outcomes == {"allowed"}:
        return "allowed"
    if outcomes == {"denied"}:
        return "denied"
    if "allowed" in outcomes and "denied" in outcomes:
        return "mixed"
    return "allowed" if "allowed" in outcomes else ("denied" if "denied" in outcomes else "unknown")


def build_map(host: str, *, engagement_id: str = "", asm=None, use_stored_asm: bool = True,
              state=None) -> dict:
    """The application map for one host. Deterministic for the same store
    contents; makes no model call and sends no traffic. `asm` (an
    ApplicationSemanticModel or its dict) overrides the stored one; with
    `use_stored_asm=False` and no `asm`, nothing is proposed."""
    from harness.engagement import normalize_path, path_id_values
    host = (host or "").strip().lower()
    draft = access_matrix.build_draft(host, engagement_id=engagement_id, state=state)
    state = state if state is not None else access_matrix._load_state(host, engagement_id)
    observations = _observations(host, engagement_id)
    owned = _ownership(host)

    roles: dict = {}

    def role_seen(name, source, principal=""):
        if not name:
            return
        entry = roles.setdefault(name, {"name": name, "basis": OBSERVED, "sources": set(),
                                        "principals": set()})
        entry["sources"].add(source)
        if principal:
            entry["principals"].add(_principal_label(principal))

    for name in draft["roles"]:
        role_seen(name, "engagement")
    for ident in (getattr(state, "identities", None) or []):
        role_seen(str(ident.get("role") or ""), "identity", str(ident.get("name") or ""))

    objects: dict = {}

    def obj_for(name):
        key = access_matrix.object_key(name)
        return objects.setdefault(key, {"object_type": name, "key": key, "basis": OBSERVED,
                                        "actions": set(), "endpoints": set(), "owners": {},
                                        "id_patterns": {}, "sensitive_fields": set()})

    for o in draft["objects"]:
        obj = obj_for(o["object_type"])
        obj["actions"] |= set(o["actions"])
        obj["sensitive_fields"] |= set(o["sensitive_fields"])

    endpoints: dict = {}

    def endpoint(method, path):
        method = (method or "").upper()
        key = f"{method} {path}"
        if key not in endpoints:
            shape = access_matrix.object_and_action(method, path)
            endpoints[key] = {"key": key, "method": method, "path": path, "basis": OBSERVED,
                              "object_type": shape[0] if shape else None,
                              "action": shape[1] if shape else None, "sources": set(),
                              "roles": {}}
            if shape:
                obj = obj_for(shape[0])
                obj["actions"].add(shape[1])
                obj["endpoints"].add(key)
        return endpoints[key]

    def role_outcome(ep, role, principal, status, source):
        cell = ep["roles"].setdefault(role, {"statuses": [], "principals": set()})
        cell["statuses"].append(status)
        if principal:
            cell["principals"].add(_principal_label(principal))
        ep["sources"].add(source)

    def id_pattern(concrete_path, template, source):
        values = path_id_values(concrete_path)
        if not values:
            return
        shape = access_matrix.object_and_action("GET", template)
        if not shape:
            return
        obj = obj_for(shape[0])
        kind = _id_pattern(values[-1])
        slot = obj["id_patterns"].setdefault((template, kind), {"route": template,
                                                                "pattern": kind, "count": 0,
                                                                "sources": set()})
        slot["count"] += 1
        slot["sources"].add(source)

    value_fields: dict = {}

    def value_field(name, value, location, ep_key, source):
        if not _FIELD_NAME.fullmatch(str(name)):
            return
        kind = value_kind(name, value)
        if not kind:
            return
        entry = value_fields.setdefault((name, location), {
            "field": name, "kind": kind, "location": location, "basis": OBSERVED,
            "endpoints": set(), "sources": set()})
        entry["endpoints"].add(ep_key)
        entry["sources"].add(source)

    # 1. The persisted engagement snapshot: per-principal cells and templates.
    for ep in sorted((getattr(state, "endpoints", None) or {}).values(), key=lambda e: e.key):
        entry = endpoint(ep.method, ep.path)
        entry["sources"].add("engagement")
        for pid, cell in sorted((ep.access_by_principal or {}).items()):
            role = str(cell.get("role") or pid)
            role_seen(role, "access_cell", pid)
            for status in access_matrix._statuses(cell.get("status")):
                role_outcome(entry, role, pid, status, "access_cell")
        body = (ep.template or {}).get("body")
        for name, value in _request_fields(body):
            value_field(name, value, "body", entry["key"], "template")

    # 2. Retained captures, in capture order.
    sequences: dict = {}
    for obs in observations:
        path = normalize_path(obs["url"])
        entry = endpoint(obs["method"], path)
        attribution = obs["attribution"]
        principal = attribution.get("principal_ref") or obs["principal"]
        role = attribution.get("role") or ("anonymous" if obs["principal"] == "anonymous"
                                           else "unattributed")
        role_seen(role, "capture", principal)
        role_outcome(entry, role, principal, obs["facts"].get("status"), "capture")
        id_pattern(urlsplit(obs["url"]).path if "://" in obs["url"] else obs["url"], path, "capture")
        for name, value in _request_fields(obs["request_body"]):
            value_field(name, value, "body", entry["key"], "capture")
        query = urlsplit(obs["url"]).query if "://" in obs["url"] else ""
        for name, value in parse_qsl(query, keep_blank_values=True):
            value_field(name, value, "query", entry["key"], "capture")
        seq = sequences.setdefault(_principal_label(principal), {
            "principal": _principal_label(principal), "roles": set(), "steps": [],
            "order_bases": set()})
        seq["roles"].add(role)
        seq["order_bases"].add("capture" if obs["captured_at"] is not None else "ingest")
        if not seq["steps"] or seq["steps"][-1]["endpoint"] != entry["key"]:
            seq["steps"].append({"endpoint": entry["key"], "object_type": entry["object_type"],
                                 "action": entry["action"],
                                 "status": obs["facts"].get("status")})

    # 3. Ownership facts: owners and the concrete id shapes of owned objects.
    for key, name, owner, concrete in owned:
        obj = obj_for(name)
        obj["owners"][owner] = obj["owners"].get(owner, 0) + 1
        id_pattern(concrete, normalize_path(concrete), "ownership_fact")

    # --- assemble (sorted, sets to lists) ---
    endpoint_list = []
    for key in sorted(endpoints):
        ep = endpoints[key]
        endpoint_list.append({
            "key": key, "method": ep["method"], "path": ep["path"],
            "object_type": ep["object_type"], "action": ep["action"], "basis": OBSERVED,
            "sources": sorted(ep["sources"]),
            "role_outcomes": [{"role": role, "outcome": _outcome_summary(cell["statuses"]),
                               "statuses": sorted({s for s in cell["statuses"] if isinstance(s, int)}),
                               "principals": sorted(cell["principals"]), "basis": OBSERVED}
                              for role, cell in sorted(ep["roles"].items())]})
    object_list = []
    for key in sorted(objects):
        obj = objects[key]
        object_list.append({
            "object_type": obj["object_type"], "key": key, "basis": OBSERVED,
            "actions": sorted(obj["actions"], key=lambda a: access_matrix.ACTIONS.index(a)
                              if a in access_matrix.ACTIONS else 99),
            "endpoints": sorted(obj["endpoints"]),
            "owners": [{"principal": p, "objects_owned": n, "basis": OBSERVED}
                       for p, n in sorted(obj["owners"].items())],
            "id_patterns": [dict(v, sources=sorted(v["sources"]), basis=OBSERVED)
                            for _, v in sorted(obj["id_patterns"].items())],
            "sensitive_fields": sorted(obj["sensitive_fields"])})
    role_list = [{"name": r["name"], "basis": OBSERVED, "sources": sorted(r["sources"]),
                  "principals": sorted(r["principals"])} for _, r in sorted(roles.items())]
    value_list = [dict(v, endpoints=sorted(v["endpoints"]), sources=sorted(v["sources"]))
                  for _, v in sorted(value_fields.items())]
    workflow_list = []
    for label, seq in sorted(sequences.items()):
        if len(seq["steps"]) < 2:
            continue
        bases = seq["order_bases"]
        workflow_list.append({
            "name": f"captured sequence of {label}", "basis": OBSERVED,
            "principal": label, "roles": sorted(seq["roles"]),
            "order_basis": next(iter(bases)) if len(bases) == 1 else "mixed",
            "steps": [dict(step, order=i) for i, step in enumerate(seq["steps"], start=1)]})

    # --- overlay: the model's hypotheses, always `proposed` ---
    asm_source = "passed in" if asm is not None else ""
    asm_doc = _asm_dict(asm)
    if asm_doc is None and use_stored_asm:
        asm_doc, asm_source = stored_semantic_model(host)
    elif asm_doc is None:
        asm_source = "not requested"
    hypotheses: list = []
    if asm_doc:
        observed_roles = {r["name"].lower() for r in role_list}
        for r in asm_doc.get("roles") or []:
            role_list.append({"name": str(r.get("name") or ""), "basis": PROPOSED,
                              "privilege_rank": r.get("privilege_rank", 0),
                              "also_observed": str(r.get("name") or "").lower() in observed_roles})
        for o in asm_doc.get("business_objects") or []:
            name = str(o.get("name") or "")
            object_list.append({
                "object_type": name, "key": access_matrix.object_key(name), "basis": PROPOSED,
                "also_observed": access_matrix.object_key(name) in objects,
                "id_params": list(o.get("id_params") or []),
                "object_scoped": bool(o.get("object_scoped")),
                "endpoints": sorted(set(o.get("read_endpoints") or [])
                                    | set(o.get("write_endpoints") or []))})
        for v in asm_doc.get("value_flows") or []:
            value_list.append({"field": str(v.get("param") or ""), "kind": v.get("kind") or "",
                               "location": "", "basis": PROPOSED,
                               "endpoints": sorted(v.get("endpoints") or []),
                               "note": v.get("note") or "",
                               "also_observed": any(f["field"] == v.get("param")
                                                    for f in value_list if f["basis"] == OBSERVED)})
        for w in asm_doc.get("workflows") or []:
            steps = list(w.get("steps") or [])
            stages = list(w.get("stages") or [])
            workflow_list.append({
                "name": str(w.get("name") or ""), "basis": PROPOSED,
                "category": w.get("category") or "",
                "steps": [{"order": i, "endpoint": s,
                           "stage": stages[i - 1] if i - 1 < len(stages) else ""}
                          for i, s in enumerate(steps, start=1)]})
        for s in asm_doc.get("sensitive_sinks") or []:
            hypotheses.append({"kind": "sensitive_sink", "basis": PROPOSED,
                               "name": s.get("name") or "", "category": s.get("category") or "",
                               "endpoints": sorted(s.get("endpoints") or [])})
        for h in asm_doc.get("chaining_hypotheses") or []:
            hypotheses.append({"kind": "chaining_hypothesis", "basis": PROPOSED,
                               "id": h.get("id") or "", "source": h.get("source") or "",
                               "target": h.get("target") or "",
                               "rationale": h.get("rationale") or "",
                               "rank": h.get("rank", 0.0), "classes": list(h.get("classes") or []),
                               "endpoints": sorted(h.get("endpoints") or [])})

    from harness import security
    return security.sanitize_data({
        "schema_version": SCHEMA_VERSION, "host": host, "engagement_id": engagement_id,
        "sends_traffic": False, "model_calls": 0,
        "sources": {"engagement_snapshot": state is not None,
                    "observations": len(observations), "ownership_facts": len(owned),
                    "semantic_model": asm_source if asm_doc else None,
                    "semantic_model_note": "" if asm_doc else asm_source},
        "roles": role_list, "objects": object_list, "endpoints": endpoint_list,
        "value_fields": value_list, "workflows": workflow_list, "hypotheses": hypotheses,
        "note": "observed items are in the store; proposed items are model hypotheses, "
                "never facts, and nothing here confirms a finding"})


# --- report --------------------------------------------------------------------------


def _cell(text) -> str:
    return str(text if text not in (None, "") else "-").replace("|", "\\|").replace("\n", " ")


def render_markdown(app_map: dict, *, limit: int = 50) -> str:
    lines = ["", "", "## Application Map", "",
             f"_{app_map['sources']['observations']} capture(s), "
             f"{app_map['sources']['ownership_facts']} ownership fact(s). Built from the store "
             "without traffic or a model call. `observed` rows are recorded facts; `proposed` "
             "rows are model hypotheses, never findings._", ""]
    observed = [r for r in app_map["roles"] if r["basis"] == OBSERVED]
    lines.append("**Roles (observed):** " + (", ".join(r["name"] for r in observed) or "none"))
    lines.append("")
    objs = [o for o in app_map["objects"] if o["basis"] == OBSERVED]
    if objs:
        lines += ["### Objects", "", "| Object | Actions | Id patterns | Owners |", "|---|---|---|---|"]
        for o in objs[:limit]:
            ids = ", ".join(f"{p['route']}: {p['pattern']}" for p in o["id_patterns"])
            owners = ", ".join(f"{w['principal']} ({w['objects_owned']})" for w in o["owners"])
            lines.append("| " + " | ".join(_cell(v) for v in (
                o["object_type"], ", ".join(o["actions"]), ids, owners)) + " |")
        lines.append("")
    if app_map["endpoints"]:
        lines += ["### Endpoints by role", "", "| Endpoint | Object | Action | Role outcomes |",
                  "|---|---|---|---|"]
        for ep in app_map["endpoints"][:limit]:
            outcomes = "; ".join(f"{r['role']}: {r['outcome']}"
                                 + (f" {r['statuses']}" if r["statuses"] else "")
                                 for r in ep["role_outcomes"])
            lines.append("| " + " | ".join(_cell(v) for v in (
                ep["key"], ep["object_type"], ep["action"], outcomes)) + " |")
        if len(app_map["endpoints"]) > limit:
            lines.append(f"_{len(app_map['endpoints']) - limit} more endpoint(s) in the API view._")
        lines.append("")
    fields = [f for f in app_map["value_fields"] if f["basis"] == OBSERVED]
    if fields:
        lines += ["### Client-trusted value fields", ""]
        for f in fields[:limit]:
            lines.append(f"- `{f['field']}` ({f['kind']}, {f['location']}) on "
                         + ", ".join(f["endpoints"]))
        lines.append("")
    flows = [w for w in app_map["workflows"] if w["basis"] == OBSERVED]
    if flows:
        lines += ["### Workflows observed (capture order)", ""]
        for w in flows[:limit]:
            lines.append(f"- {w['name']} ({', '.join(w['roles'])}; order: {w['order_basis']}): "
                         + " -> ".join(s["endpoint"] for s in w["steps"]))
        lines.append("")
    proposed = ([("role", r["name"]) for r in app_map["roles"] if r["basis"] == PROPOSED]
                + [("object", o["object_type"]) for o in app_map["objects"] if o["basis"] == PROPOSED]
                + [("value field", f["field"]) for f in app_map["value_fields"]
                   if f["basis"] == PROPOSED]
                + [("workflow", w["name"]) for w in app_map["workflows"] if w["basis"] == PROPOSED]
                + [(h["kind"].replace("_", " "), h.get("source") and f"{h['source']} -> {h['target']}"
                    or h.get("name", "")) for h in app_map["hypotheses"]])
    if proposed:
        lines += ["### Proposed by the model (hypotheses, not observed)", ""]
        for kind, name in proposed[:limit]:
            lines.append(f"- proposed {kind}: {name}")
        lines.append("")
    return "\n".join(lines)


def report_section(host: str, *, config: dict | None = None, engagement_id: str = "") -> str:
    """The report's application-map section, or "" unless `app_map.report_section`
    is on (it ships off, so a default report is unchanged)."""
    cfg = ((config or {}).get("app_map") or {})
    if cfg.get("report_section", False) is not True:
        return ""
    from harness import security
    try:
        text = render_markdown(build_map(host, engagement_id=engagement_id))
    except Exception as exc:     # a broken snapshot must never sink the report
        return f"\n\n## Application Map\n\n_Not available: {type(exc).__name__}._\n"
    return security.sanitize_text(text)
