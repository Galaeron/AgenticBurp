"""access_matrix.py -- HU-1: the operator access matrix.

The bugs that matter most here (access control, data exposure) depend on intent,
and intent used to come only from hand-written `engagement.access_expectations`.
This module gives the tester a way to state it:

  1. `build_draft` derives a DRAFT matrix, deterministically, from what the store
     already holds for one engagement: the role crawl's per-principal access cells
     and supplied captures (the persisted EngagementState), and the observed
     `ownership_facts`. Each row is role x object type x action (read / list /
     create / update / delete) with its observed outcome (allowed / denied /
     unknown), the sensitive field NAMES seen in its responses, and a *proposed*
     expectation with the basis for it. Sends nothing.
  2. Operator answers (`allowed` / `denied` / `owner_only` / `admin_only` /
     `unknown`) are saved per (engagement, host) with provenance: who, when,
     source=operator (`save_answers`, `load_answers`).
  3. `questions` ranks the unanswered cells by impact and caps each round,
     phrasing each as a question ("Can a user update a Product?").
  4. `expectation_for` is the plain lookup a consumer (experiment.py today; the
     T1/T2 validators later) calls for one cell. It returns ONLY an operator
     answer -- a proposed expectation is never returned, so an unanswered cell
     stays a lead and can never confirm anything.

`report_section` renders the matrix and its open questions for the report; it
ships off (`access_matrix.report_section: false`), so a default report is
byte-identical. Nothing here is specific to one application: object types and
actions come from route shapes and HTTP methods only.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

ACTIONS = ("read", "list", "create", "update", "delete")
ANSWERS = ("allowed", "denied", "owner_only", "admin_only", "unknown")
# The answers that say the cell's crossing must NOT succeed for this role.
RESTRICTIVE = frozenset({"owner_only", "admin_only", "denied"})
SOURCE = "operator"
DEFAULT_MAX_QUESTIONS = 20
WILDCARD_ROLE = "*"

# experiment.py's expectation kind for an answer. owner_only is the matrix name of
# the long-standing `private_to_creator`.
EXPECTATION_KIND = {"owner_only": "private_to_creator", "admin_only": "admin_only",
                    "denied": "denied", "allowed": "allowed"}

_ACTION_WEIGHT = {"delete": 5, "update": 5, "create": 4, "read": 3, "list": 2}
_PRIVILEGED_WORDS = ("admin", "administrator", "superuser", "root", "staff", "manager",
                     "moderator", "operator", "support")
_ANON_WORDS = ("anonymous", "anon", "guest", "unauthenticated", "public")
_SENSITIVE_FIELD = re.compile(
    r"pass(word|wd|phrase)?$|secret|token|api_?key|private|credential|salt|hash$|totp|mfa|otp$"
    r"|ssn$|social_?security|card_?(number|no)?$|cvv|cvc|iban|account_?(number|no)$"
    r"|e_?mail|phone|mobile|address$|birth|dob$|salary|tax_?id", re.IGNORECASE)
_ID_SEGMENT = re.compile(r"\{[^}]*\}")
_VERSION_SEGMENT = re.compile(r"v\d+(\.\d+)?$", re.IGNORECASE)
_ROLE_TEXT = re.compile(r"^[A-Za-z0-9_.:@#* -]{1,64}$")
_OBJECT_TEXT = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_MAX_NOTE = 500
_MAX_BODY = 4096

_SCHEMA = """
CREATE TABLE IF NOT EXISTS access_matrix_answers (
    engagement_id TEXT NOT NULL DEFAULT '',
    host TEXT NOT NULL,
    role TEXT NOT NULL,
    object_key TEXT NOT NULL,
    object_type TEXT NOT NULL,
    action TEXT NOT NULL,
    answer TEXT NOT NULL,
    operator TEXT NOT NULL,
    source TEXT NOT NULL,
    answered_at REAL NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    mechanics_json TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (engagement_id, host, role, object_key, action)
);
"""


# --- names ----------------------------------------------------------------------


def _singular(word: str) -> str:
    low = word.lower()
    if low.endswith("ies") and len(word) > 4:
        return word[:-3] + ("Y" if word[-3:].isupper() else "y")
    if low.endswith(("sses", "xes", "ches", "shes")):
        return word[:-2]
    if low.endswith("s") and not low.endswith("ss") and len(word) > 2:
        return word[:-1]
    return word


def object_key(name: str) -> str:
    """The comparison key of an object type: "Notes", "note" and "NOTE" agree."""
    return re.sub(r"[^a-z0-9]", "", _singular(str(name or "").strip()).lower())


def display_name(segment: str) -> str:
    word = _singular(segment)
    return word[:1].upper() + word[1:] if word.islower() else word


def object_and_action(method: str, path: str) -> tuple[str, str] | None:
    """(object type, action) for a normalized route ("GET /api/notes/{id}" ->
    ("Note", "read")), or None when the route names no object or the method maps
    to no action. Shape only: the last named segment is the object; a trailing
    `{id}` addresses one of them."""
    segments = [s for s in (path or "").split("/") if s]
    if not segments:
        return None
    item = bool(_ID_SEGMENT.fullmatch(segments[-1]))
    named = [s for s in segments if not _ID_SEGMENT.fullmatch(s)]
    named = [s for s in named if not _VERSION_SEGMENT.fullmatch(s) and s.lower() != "api"]
    if not named or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", named[-1]):
        return None
    method = (method or "").upper()
    if method == "GET":
        action = "read" if item else "list"
    elif method == "POST":
        action = "update" if item else "create"
    elif method in ("PUT", "PATCH"):
        action = "update"
    elif method == "DELETE":
        action = "delete"
    else:
        return None
    return display_name(named[-1]), action


def _article(word: str) -> str:
    return "an" if (word[:1].lower() in "aeiou") else "a"


def question_text(role: str, object_type: str, action: str) -> str:
    if role == WILDCARD_ROLE:
        who = "any signed-in user"
    elif any(w == role.lower() for w in _ANON_WORDS):
        who = "an anonymous visitor"
    else:
        who = f"{_article(role)} {role}"
    if action == "list":
        return f"Can {who} list {object_type}s?"
    return f"Can {who} {action} {_article(object_type)} {object_type}?"


def _privileged(role: str) -> bool:
    low = (role or "").lower()
    return any(w in low for w in _PRIVILEGED_WORDS)


def _anonymous(role: str) -> bool:
    return (role or "").lower() in _ANON_WORDS


def _outcome(status) -> str:
    if isinstance(status, int) and 200 <= status < 300:
        return "allowed"
    if status in (401, 403):
        return "denied"
    return "unknown"


def _statuses(value) -> list:
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _field_names(body, limit: int = 40) -> set:
    try:
        data = json.loads(body) if isinstance(body, str) else body
    except (TypeError, ValueError):
        return set()
    names: set = set()
    stack = [data]
    while stack and len(names) < limit:
        value = stack.pop()
        if isinstance(value, dict):
            for key, child in value.items():
                if isinstance(key, str) and _SENSITIVE_FIELD.search(key):
                    names.add(key)
                stack.append(child)
        elif isinstance(value, list):
            stack.extend(value[:20])
    return names


def _id_pointer(body) -> str:
    """The JSON pointer of the first `id` leaf in an observed create response, or ""."""
    try:
        data = json.loads(body) if isinstance(body, str) else body
    except (TypeError, ValueError):
        return ""
    queue = [(data, "")]
    while queue:
        value, pointer = queue.pop(0)
        if isinstance(value, dict):
            for key, child in value.items():
                path = f"{pointer}/{str(key).replace('~', '~0').replace('/', '~1')}"
                if key == "id" and isinstance(child, (int, str)) and child != "":
                    return path
                if isinstance(child, dict):
                    queue.append((child, path))
    return ""


# --- the draft ------------------------------------------------------------------


def _load_state(host: str, engagement_id: str):
    from harness import store
    from harness.engagement import EngagementState
    raw = store.load_engagement(host, engagement_id=engagement_id)
    return EngagementState.from_dict(raw) if raw else None


def _owned_objects(host: str) -> dict:
    """object key -> number of observed ownership facts on this host's origin."""
    from harness import store
    from harness.engagement import normalize_path
    counts: dict = {}
    host = (host or "").lower()
    for fact in store.ownership_facts_all():
        ref = str(fact.get("object_ref") or "")
        app = re.search(r"\|app:[a-z]+://([^|]+)\|", ref)
        resource = ref.split("|resource:", 1)[-1] if "|resource:" in ref else ""
        if not app or app.group(1).lower() not in (host, host.split(":", 1)[0]) or not resource:
            continue
        if not fact.get("owner_principal_id") or fact.get("public"):
            continue
        shape = object_and_action("GET", normalize_path(resource))
        if shape:
            key = object_key(shape[0])
            counts[key] = counts.get(key, 0) + 1
    return counts


def _propose(role: str, action: str, obj: dict) -> tuple[str, str]:
    """(proposed answer, basis). A proposal is a starting point for the operator,
    never an expectation any consumer reads."""
    owned, privileged_writes = obj["owned"], obj["privileged_only_writes"]
    owned_basis = (f"{owned} ownership fact(s) observed for this object type" if owned
                   else obj.get("owned_basis", ""))
    if _anonymous(role):
        if owned_basis or action in ("create", "update", "delete"):
            return "denied", "anonymous visitors rarely act on owned objects or write"
        return "unknown", "no basis"
    if owned_basis:
        if action in ("read", "update", "delete"):
            return "owner_only", owned_basis
        return "allowed", "each principal creates and lists its own objects"
    if action in ("create", "update", "delete") and (privileged_writes or obj["readable_by_all"]):
        # (an owned type returned above: a shared catalogue is what privileged roles write)
        basis = ("only a privileged role was observed writing; no ownership seen"
                 if privileged_writes else
                 "every role reads it and no ownership was seen: a shared catalogue")
        return ("allowed" if _privileged(role) else "admin_only"), basis
    if obj["readable_by_all"] and action in ("read", "list"):
        return "allowed", "every probed role read it and no ownership was seen"
    return "unknown", "no basis"


def build_draft(host: str, *, engagement_id: str = "", max_questions: int = DEFAULT_MAX_QUESTIONS,
                state=None) -> dict:
    """The draft matrix for one engagement, with the saved answers folded in and
    this round's questions. Deterministic for the same store contents. Sends
    nothing. `state` (an EngagementState) overrides the persisted snapshot."""
    state = state if state is not None else _load_state(host, engagement_id)
    owned = _owned_objects(host)
    objects: dict = {}
    roles: list = []

    def role_seen(role):
        if role and role not in roles:
            roles.append(role)

    for ident in (getattr(state, "identities", None) or []):
        role_seen(str(ident.get("role") or ""))
    cells: dict = {}
    for ep in sorted((getattr(state, "endpoints", None) or {}).values(), key=lambda e: e.key):
        shape = object_and_action(ep.method, ep.path)
        if shape is None:
            continue
        name, action = shape
        key = object_key(name)
        obj = objects.setdefault(key, {"object_type": name, "key": key, "endpoints": {},
                                       "sensitive_fields": set(), "owned": owned.get(key, 0),
                                       "writers": set(), "readers": {}, "mechanics": {}})
        obj["endpoints"].setdefault(action, []).append(ep.key)
        for variant in ep.capture_variants or []:
            obj["sensitive_fields"] |= _field_names(variant.get("response_body") or "")
        if action == "create" and "{" not in ep.path and not obj["mechanics"].get("create"):
            tmpl = ep.template or {}
            spec = {"method": ep.method, "path": ep.path}
            if tmpl.get("body"):
                from harness import security
                body = security.redact_secrets_in_body(tmpl["body"])
                try:
                    spec["body"] = json.loads(body)
                except (TypeError, ValueError):
                    spec["body"] = body[:_MAX_BODY]
            pointer = next((_id_pointer(v.get("response_body")) for v in ep.capture_variants or []
                            if _outcome(v.get("response_status")) == "allowed"
                            and _id_pointer(v.get("response_body"))), "")
            if pointer:
                spec["id_pointer"] = pointer
            obj["mechanics"]["create"] = spec
        if action == "read" and ep.path.count("{") == 1 and not obj["mechanics"].get("read"):
            obj["mechanics"]["read"] = {"method": "GET", "path": re.sub(r"\{[^}]*\}", "{id}", ep.path)}
        if action == "delete" and ep.path.count("{") == 1 and not obj["mechanics"].get("delete"):
            obj["mechanics"]["delete"] = {"method": "DELETE",
                                          "path": re.sub(r"\{[^}]*\}", "{id}", ep.path)}
        for pid, cell in sorted((ep.access_by_principal or {}).items()):
            role = str(cell.get("role") or pid)
            role_seen(role)
            for status in _statuses(cell.get("status")):
                outcome = _outcome(status)
                row = cells.setdefault((role, key, action), {"statuses": [], "principals": set(),
                                                             "endpoints": set()})
                row["statuses"].append(status)
                row["principals"].add(str(pid))
                row["endpoints"].add(ep.key)
                if outcome == "allowed" and action in ("create", "update", "delete"):
                    obj["writers"].add(role)
                if action in ("read", "list"):
                    obj["readers"].setdefault(role, set()).add(outcome)
    for obj in objects.values():
        writers = obj["writers"]
        obj["privileged_only_writes"] = bool(writers) and all(_privileged(r) for r in writers)
        authed = [r for r in roles if not _anonymous(r)]
        obj["readable_by_all"] = bool(authed) and all(
            "allowed" in obj["readers"].get(r, set()) for r in authed)
        if obj["owned"] == 0 and any(not _privileged(r) and not _anonymous(r) for r in writers) \
                and obj["endpoints"].get("create"):
            # a non-privileged principal created one: objects of this type are probably owned
            obj["owned_basis"] = "created by a non-privileged role"

    answers = {(a["role"], a["object_key"], a["action"]): a
               for a in load_answers(host, engagement_id=engagement_id)}
    rows = []
    for key in sorted(objects):
        obj = objects[key]
        for action in ACTIONS:
            if action not in obj["endpoints"]:
                continue
            for role in roles:
                seen = cells.get((role, key, action))
                outcomes = sorted({_outcome(s) for s in (seen or {}).get("statuses", [])})
                observed = ("allowed" if "allowed" in outcomes else
                            "denied" if "denied" in outcomes else "unknown")
                proposed, basis = _propose(role, action, obj)
                answer = answers.get((role, key, action))
                rows.append({
                    "cell_id": f"{role}|{key}|{action}", "role": role,
                    "object_type": obj["object_type"], "object_key": key, "action": action,
                    "endpoints": sorted((seen or {}).get("endpoints") or obj["endpoints"][action]),
                    "observed": observed,
                    "observed_statuses": sorted({s for s in (seen or {}).get("statuses", [])
                                                 if isinstance(s, int)}),
                    "observed_principals": sorted((seen or {}).get("principals", set())),
                    "sensitive_fields": sorted(obj["sensitive_fields"]) if action in ("read", "list")
                    else [],
                    "proposed": proposed, "proposal_basis": basis, "proposal_is_truth": False,
                    "answer": answer["answer"] if answer else None,
                    "provenance": ({k: answer[k] for k in ("operator", "answered_at", "source", "note")}
                                   if answer else None),
                    "question": question_text(role, obj["object_type"], action),
                })
    for (role, key, action), answer in sorted(answers.items()):
        if not any(r["cell_id"] == f"{role}|{key}|{action}" for r in rows):
            # an answer about a cell the draft does not (yet) show is kept, not dropped
            rows.append({"cell_id": f"{role}|{key}|{action}", "role": role,
                         "object_type": answer["object_type"], "object_key": key,
                         "action": action, "endpoints": [], "observed": "unknown",
                         "observed_statuses": [], "observed_principals": [],
                         "sensitive_fields": [], "proposed": "unknown",
                         "proposal_basis": "not in the draft", "proposal_is_truth": False,
                         "answer": answer["answer"],
                         "provenance": {k: answer[k] for k in
                                        ("operator", "answered_at", "source", "note")},
                         "question": question_text(role, answer["object_type"], action)})
    object_list = [{"object_type": o["object_type"], "key": o["key"],
                    "actions": sorted(o["endpoints"], key=ACTIONS.index),
                    "owned_objects_observed": o["owned"],
                    "sensitive_fields": sorted(o["sensitive_fields"]),
                    "proposed_mechanics": o["mechanics"]} for _, o in sorted(objects.items())]
    return {"host": host, "engagement_id": engagement_id, "roles": roles,
            "objects": object_list, "rows": rows,
            "questions": questions(rows, max_questions=max_questions),
            "answered": sum(1 for r in rows if r["answer"]),
            "open": sum(1 for r in rows if not r["answer"]),
            "note": "proposed expectations are never truth: only an operator answer is "
                    "read by a check, and an unanswered cell stays a lead"}


def _impact(row: dict) -> int:
    score = _ACTION_WEIGHT.get(row["action"], 1)
    if row["observed"] == "allowed" and row["proposed"] in RESTRICTIVE:
        score += 4           # observed success where the proposal expects a boundary
    score += 2 * min(3, len(row.get("sensitive_fields") or []))
    if row["proposed"] == "owner_only":
        score += 2
    if not _privileged(row["role"]) and not _anonymous(row["role"]):
        score += 1           # a low-privilege principal is the usual attacker
    return score


def questions(rows: list, *, max_questions: int = DEFAULT_MAX_QUESTIONS) -> list:
    """The unanswered cells, highest impact first, capped at `max_questions`."""
    cap = max(1, int(max_questions or DEFAULT_MAX_QUESTIONS))
    open_rows = [r for r in rows if not r.get("answer")]
    ranked = sorted(open_rows, key=lambda r: (-_impact(r), r["cell_id"]))
    return [{"cell_id": r["cell_id"], "question": r["question"], "role": r["role"],
             "object_type": r["object_type"], "action": r["action"], "impact": _impact(r),
             "observed": r["observed"], "proposed": r["proposed"],
             "proposal_basis": r["proposal_basis"], "sensitive_fields": r["sensitive_fields"]}
            for r in ranked[:cap]]


# --- answers ----------------------------------------------------------------------


def _clean_spec(spec, part: str) -> dict:
    if not isinstance(spec, dict):
        raise ValueError(f"mechanics.{part} must be an object")
    unknown = set(spec) - {"method", "path", "body", "id_pointer", "content_type"}
    if unknown:
        raise ValueError(f"mechanics.{part} has unknown keys {sorted(unknown)}")
    method, path = str(spec.get("method") or "").upper(), str(spec.get("path") or "")
    if not re.fullmatch(r"GET|POST|PUT|PATCH|DELETE", method):
        raise ValueError(f"mechanics.{part}.method must be an HTTP method")
    if not path.startswith("/") or "://" in path or len(path) > 512:
        raise ValueError(f"mechanics.{part}.path must be a route path starting with '/'")
    out = {"method": method, "path": path}
    if "body" in spec:
        if len(json.dumps(spec["body"])) > _MAX_BODY:
            raise ValueError(f"mechanics.{part}.body is larger than {_MAX_BODY} bytes")
        out["body"] = spec["body"]
    for key in ("id_pointer", "content_type"):
        if spec.get(key):
            out[key] = str(spec[key])[:200]
    return out


def clean_answer(entry) -> dict:
    """One validated answer entry, or ValueError naming what is wrong."""
    if not isinstance(entry, dict):
        raise ValueError("an answer must be an object")
    role, obj = str(entry.get("role") or "").strip(), str(entry.get("object_type") or "").strip()
    action = str(entry.get("action") or "").strip().lower()
    answer = entry.get("answer")
    if not _ROLE_TEXT.fullmatch(role):
        raise ValueError("role must be 1-64 characters of letters, digits or _.:@#*- ")
    if not _OBJECT_TEXT.fullmatch(obj) or not object_key(obj):
        raise ValueError("object_type must be 1-64 characters of letters, digits or _.-")
    if action not in ACTIONS:
        raise ValueError(f"action must be one of {list(ACTIONS)}")
    if answer is not None and answer not in ANSWERS:
        raise ValueError(f"answer must be one of {list(ANSWERS)} (or null to clear)")
    note = str(entry.get("note") or "")
    if len(note) > _MAX_NOTE:
        raise ValueError(f"note is longer than {_MAX_NOTE} characters")
    mechanics = entry.get("mechanics")
    clean_mech = {}
    if mechanics:
        if not isinstance(mechanics, dict):
            raise ValueError("mechanics must be an object")
        unknown = set(mechanics) - {"create", "read", "delete", "marker_pointer"}
        if unknown:
            raise ValueError(f"mechanics has unknown keys {sorted(unknown)}")
        for part in ("create", "read", "delete"):
            if mechanics.get(part):
                clean_mech[part] = _clean_spec(mechanics[part], part)
        if mechanics.get("marker_pointer"):
            clean_mech["marker_pointer"] = str(mechanics["marker_pointer"])[:200]
    return {"role": role, "object_type": obj, "object_key": object_key(obj), "action": action,
            "answer": answer, "note": note, "mechanics": clean_mech}


def save_answers(host: str, answers: list, *, operator: str, engagement_id: str = "",
                 now: float | None = None) -> list:
    """Validate and save operator answers for one (engagement, host). An answer of
    None clears that cell. Every saved row records who, when and source=operator.
    All-or-nothing: one invalid entry saves none. Returns the cleaned entries."""
    from harness import store
    host = (host or "").strip().lower()
    operator = str(operator or "").strip()
    if not host:
        raise ValueError("a host is required")
    if not operator or len(operator) > 64:
        raise ValueError("operator (who is answering) is required, at most 64 characters")
    cleaned = [clean_answer(entry) for entry in answers or []]
    stamp = time.time() if now is None else now
    conn = store._connect()
    try:
        conn.executescript(_SCHEMA)
        with conn:
            for entry in cleaned:
                keys = (engagement_id, host, entry["role"], entry["object_key"], entry["action"])
                if entry["answer"] is None:
                    conn.execute("DELETE FROM access_matrix_answers WHERE engagement_id=? AND "
                                 "host=? AND role=? AND object_key=? AND action=?", keys)
                    continue
                conn.execute(
                    "INSERT OR REPLACE INTO access_matrix_answers (engagement_id, host, role, "
                    "object_key, object_type, action, answer, operator, source, answered_at, note, "
                    "mechanics_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (*keys[:4], entry["object_type"], entry["action"], entry["answer"], operator,
                     SOURCE, stamp, entry["note"],
                     json.dumps(entry["mechanics"]) if entry["mechanics"] else ""))
    finally:
        conn.close()
    return cleaned


def load_answers(host: str, *, engagement_id: str = "") -> list:
    """The saved answers for one (engagement, host). Read-only: a store that has
    no database file or no answers table yet has no answers, and nothing is
    created to find that out."""
    from harness import store
    import sqlite3
    if not Path(store._DB_PATH).exists():
        return []
    conn = store._connect()
    try:
        rows = conn.execute(
            "SELECT role, object_key, object_type, action, answer, operator, source, answered_at, "
            "note, mechanics_json FROM access_matrix_answers WHERE engagement_id=? AND host=? "
            "ORDER BY role, object_key, action", (engagement_id, (host or "").lower())).fetchall()
    except sqlite3.OperationalError:
        return []
    finally:
        conn.close()
    return [{"role": r[0], "object_key": r[1], "object_type": r[2], "action": r[3],
             "answer": r[4], "operator": r[5], "source": r[6], "answered_at": r[7],
             "note": r[8], "mechanics": json.loads(r[9]) if r[9] else {}} for r in rows]


def expectation_for(store_module, host: str, role: str, object_type: str, action: str, *,
                    engagement_id: str = "", principal_id: str = "") -> dict | None:
    """The operator's answer for one cell, or None when there is none.

    Matched by role, then by the principal id (an answer about one account),
    then by the `*` wildcard (any signed-in user). An `unknown` answer and an
    unanswered cell both return None: neither is an expectation, and a consumer
    must treat the cell as a lead. A proposed expectation is never returned.
    `store_module` is accepted for call-site symmetry (the store is
    harness.store); pass None."""
    del store_module
    key, action = object_key(object_type), str(action or "").lower()
    if not key or action not in ACTIONS:
        return None
    hosts = [(host or "").lower()]
    if ":" in hosts[0]:
        hosts.append(hosts[0].split(":", 1)[0])
    for candidate_host in hosts:
        answers = {(a["role"], a["object_key"], a["action"]): a
                   for a in load_answers(candidate_host, engagement_id=engagement_id)}
        for who in [r for r in (role, principal_id, WILDCARD_ROLE) if r]:
            found = answers.get((who, key, action))
            if found is None:
                continue
            if found["answer"] not in EXPECTATION_KIND:
                return None          # 'unknown': the operator does not know -- still a lead
            return {"answer": found["answer"], "expectation": EXPECTATION_KIND[found["answer"]],
                    "role": found["role"], "object_type": found["object_type"],
                    "action": action, "operator": found["operator"],
                    "answered_at": found["answered_at"], "source": found["source"],
                    "mechanics": dict(found["mechanics"] or {}), "host": candidate_host}
    return None


# --- report ---------------------------------------------------------------------------


def _cell(text) -> str:
    return str(text if text not in (None, "") else "-").replace("|", "\\|").replace("\n", " ")


def report_section(host: str, *, config: dict | None = None, engagement_id: str = "") -> str:
    """The report's access-matrix section, or "" unless `access_matrix.report_section`
    is on (it ships off, so a default report is unchanged)."""
    cfg = ((config or {}).get("access_matrix") or {})
    if not cfg.get("report_section", False):
        return ""
    from harness import security
    try:
        draft = build_draft(host, engagement_id=engagement_id,
                            max_questions=int(cfg.get("max_questions_per_round",
                                                      DEFAULT_MAX_QUESTIONS)))
    except Exception as exc:     # a broken snapshot must never sink the report
        return f"\n\n## Access Matrix\n\n_Not available: {type(exc).__name__}._\n"
    lines = ["", "", "## Access Matrix (operator intent)", "",
             f"_{draft['answered']} cell(s) answered, {draft['open']} open. Proposed expectations "
             "are a starting point, never a finding: only an operator answer is tested, and an "
             "unanswered cell stays a lead._", ""]
    if not draft["rows"]:
        lines += ["_No roles or object routes recorded for this engagement yet._", ""]
        return security.sanitize_text("\n".join(lines))
    lines += ["| Role | Object | Action | Observed | Proposed | Answer | Answered by | Sensitive fields |",
              "|---|---|---|---|---|---|---|---|"]
    for row in draft["rows"]:
        who = (row["provenance"] or {}).get("operator")
        lines.append("| " + " | ".join(_cell(v) for v in (
            row["role"], row["object_type"], row["action"], row["observed"], row["proposed"],
            row["answer"], who, ", ".join(row["sensitive_fields"]))) + " |")
    lines.append("")
    if draft["questions"]:
        lines += ["### Open questions (this round)", ""]
        for index, q in enumerate(draft["questions"], start=1):
            lines.append(f"{index}. {q['question']} (observed: {q['observed']}; proposed: "
                         f"{q['proposed']} -- {q['proposal_basis']})")
        lines.append("")
    return security.sanitize_text("\n".join(lines))
