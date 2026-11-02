"""
experiment.py -- one graph -> experiment -> workflow -> proof -> graph cycle (Ticket G).

The task graph proposes (a ChainingHypothesis such as "IDOR/BOLA on Note"); the
workflow engine can run stateful multi-identity sequences; the evidence layer
stores structured proof. Until now nothing connected them: every hypothesis became
a BLOCKED "operator review" task and stayed that way. This module is the missing
translation, for ONE experiment kind only -- cross-account access to a private
object -- and deliberately without broad inference:

  1. `translate_cross_account` turns a hypothesis into an `Experiment` (an
     inspectable, compilable plan) or into a BLOCKED plan naming the exact inputs
     still missing. It never guesses an owner, an id, a body or a pointer.
  2. `evaluate_experiments` records those plans as graph tasks
     (`experiment:<exp id>`), READY or BLOCKED with the missing list as `needs`,
     and gates the proposal's chain-hypothesis task on the experiment.
  3. `run_experiment` compiles the plan into a `workflow_engine.Workflow`, runs it
     through the run's transport as two real identities, judges the three
     exchanges (`judge`, a pure function) and persists a structured ProofRecord.
  4. `run_experiment_loop` feeds the outcome back: the task is marked, observed
     values and the ownership fact are recorded, and BLOCKED experiments are
     re-evaluated, so an experiment that needed `note_id` runs in the same loop
     once another experiment has produced it.

The privacy expectation is OPERATOR-DECLARED (`engagement.access_expectations`).
It is never inferred from a successful read: a read that works proves reachability,
not that the object was meant to be private. The baseline/attack/control sends
carry the proof's case id as their case_ref, so the stored proof's artifact ids
resolve (assessment_health.stored_proof_artifacts_resolve) to execution events
filed under that case.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
import secrets
import time
from dataclasses import asdict, dataclass, field, replace

from harness import task_graph
from harness.application_semantic_model import endpoint_key
from harness.evidence import ProofRecord, TestCaseRef, Verdict
from harness.principals import ANON, AuthzDecision, OwnershipFact, Principal, object_reference
from harness.workflow_engine import (
    Extractor, ExtractorKind, StepStatus, Workflow, WorkflowResult, WorkflowStep,
    execute_workflow,
)

KIND = "cross_account_private_object"
CHECK_ID = "ATHZ-cross-account"
VALIDATOR = "cross_account_experiment"
VALIDATOR_VERSION = "1"
BROWSER_HASH = "browser_hash_input_execution"
BROWSER_STORED = "browser_stored_input_execution"
BROWSER_KINDS = (BROWSER_HASH, BROWSER_STORED)
SUPPORTED_KINDS = (KIND, *BROWSER_KINDS)
SUPPORTED_CLASSES = frozenset({"idor", "bola"})
SUPPORTED_EXPECTATIONS = ("private_to_creator",)
EXPECTATION_SOURCE = "config engagement.access_expectations"

# Judge outcomes.
NEGATIVE = "negative"
CONFIRMED = "confirmed"
INCONCLUSIVE = "inconclusive"

# Workflow step ids; judge() and the compiler agree on these.
SETUP_OWNER, SETUP_OTHER = "setup_owner", "setup_other"
BASELINE, ATTACK, CONTROL = "baseline", "attack", "control"
CLEANUP_OWNER, CLEANUP_OTHER = "cleanup_owner", "cleanup_other"
# Extracted-value names the observed steps use for the marker comparison.
_OWNER_MARKER, _ATTACK_MARKER, _CONTROL_MARKER = "owner_marker", "attack_marker", "control_marker"
# The object holding the id marker (its JSON parent), kept so a 2xx that merely
# echoes the id inside an error object is not read as the owner's data.
_OWNER_OBJECT, _ATTACK_OBJECT, _CONTROL_OBJECT = "owner_object", "attack_object", "control_object"
# The per-identity token a declared create body may carry as `{tag}`: random, unique
# to the identity and the run, so each identity's object holds content only its own
# create sent. The two names bind in the owner's and the other identity's create.
_TAG_OWNER, _TAG_OTHER = "owner_tag", "other_tag"

_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
_DENIED = (401, 403, 404)


# --- the experiment contract ---------------------------------------------------


def experiment_id(kind: str, hypothesis_id: str, object_name: str) -> str:
    """Stable across re-plans: the same kind, hypothesis and object is the same
    experiment, whether it is currently ready or blocked."""
    raw = f"{kind}|{hypothesis_id}|{object_name}".encode("utf-8", "ignore")
    return "exp:" + hashlib.sha256(raw).hexdigest()[:12]


def _step_dict(step: WorkflowStep) -> dict:
    return {"id": step.id, "method": step.method, "url_template": step.url_template,
            "session_ref": step.session_ref, "prerequisites": list(step.prerequisites),
            "extracts": [e.name for e in step.extractors], "observe": step.observe,
            "cleanup": step.cleanup, "action": step.action}


@dataclass(frozen=True)
class Experiment:
    """A compilable, inspectable stateful test. Holds no credential and no
    observed value -- only templates (`{{name}}` placeholders), session references
    and the names of the values it produces and consumes."""
    id: str
    kind: str
    hypothesis_id: str
    required_identities: dict          # role label -> session ref ("owner", "other")
    access_expectation: dict           # {"object", "expectation", "source"}
    setup_steps: tuple = ()
    baseline_steps: tuple = ()
    attack_steps: tuple = ()
    control_steps: tuple = ()
    cleanup_steps: tuple = ()
    extracted_values: tuple = ()       # value names this experiment produces
    assertions: str = ""               # the verdict rule, in words
    # What the runner and the judge need beyond the steps themselves.
    object_name: str = ""
    principals: dict = field(default_factory=dict)   # role label -> principal id
    owner_value: str = ""              # value holding the owner's object id
    other_value: str = ""              # value holding the other principal's own object id
    read_template: str = ""            # "GET /api/notes/{id}": the proof's request template
    read_url_template: str = ""        # absolute, `{id}` -> `{{owner_value}}`
    create_key: str = ""               # "POST /api/notes", for the ownership provenance
    marker_pointer: str = ""
    marker_declared: bool = False      # False: the owner's id is the marker
    consumed_values: tuple = ()        # observed values the steps bind
    tagged: bool = False               # the declared create body carries a `{tag}`
    mechanism_version: int = 1
    binding: dict = field(default_factory=dict)  # declared mechanism input references, no credentials

    def to_workflow(self, case_ref: str = "") -> Workflow:
        """Compile to ONE workflow: setup, baseline, attack, control, then the
        cleanup steps flagged `cleanup=True`. `case_ref` (the proof's case id) is
        stamped on the baseline/attack/control steps only; setup keeps its
        per-step ref."""
        judged = tuple(replace(s, case_ref=case_ref) if case_ref else s
                       for s in self.baseline_steps + self.attack_steps + self.control_steps)
        cleanup = tuple(replace(s, cleanup=True) for s in self.cleanup_steps)
        return Workflow(self.id, self.setup_steps + judged + cleanup,
                        2 if self.kind in BROWSER_KINDS else 1, self.assertions)

    def to_dict(self) -> dict:
        return {"contract_version": 2, "id": self.id, "kind": self.kind,
                "mechanism_version": self.mechanism_version, "binding": dict(self.binding),
                "hypothesis_id": self.hypothesis_id,
                "required_identities": dict(self.required_identities),
                "access_expectation": dict(self.access_expectation),
                "setup_steps": [_step_dict(s) for s in self.setup_steps],
                "baseline_steps": [_step_dict(s) for s in self.baseline_steps],
                "attack_steps": [_step_dict(s) for s in self.attack_steps],
                "control_steps": [_step_dict(s) for s in self.control_steps],
                "cleanup_steps": [_step_dict(s) for s in self.cleanup_steps],
                "cost": {"minimum_requests": len(self.setup_steps + self.baseline_steps + self.attack_steps + self.control_steps),
                         "mutating_requests": sum(s.action == 'http' and s.method.upper() not in ('GET','HEAD','OPTIONS') for s in self.setup_steps + self.baseline_steps + self.attack_steps + self.control_steps)},
                "extracted_values": list(self.extracted_values),
                "consumed_values": list(self.consumed_values),
                "tagged": self.tagged, "assertions": self.assertions}


@dataclass
class ExperimentPlan:
    """A ready Experiment, or the exact inputs that keep it from being one."""
    status: str                              # "ready" | "blocked"
    experiment: Experiment | None = None
    missing: list = field(default_factory=list)
    experiment_id: str = ""
    object_name: str = ""
    hypothesis_id: str = ""
    # For the bounded planner: which missing items are only an extraction pointer
    # or an unobserved value ("hard" = something else, e.g. an expectation or an
    # identity, that no capture can supply).
    unblock: dict = field(default_factory=dict)

    @property
    def ready(self) -> bool:
        return self.status == "ready"


# --- translation ----------------------------------------------------------------


def missing_expectation(obj: str) -> str:
    return f"no declared access expectation for object '{obj}' (engagement.access_expectations)"


def missing_extraction(key: str) -> str:
    return f"no declared id extraction (JSON pointer) for {key}"


def missing_read_endpoint(obj: str) -> str:
    return f"no supported read endpoint with an {{id}} placeholder for '{obj}'"


def missing_value(name: str) -> str:
    return f"value '{name}' not yet observed"


MISSING_TAG = "the create body needs a per-identity {tag} field to distinguish the two objects"
MISSING_SECOND_IDENTITY = "no second identity distinct from the owner"
MISSING_OWNER_IDENTITY = "no authenticated session for the owner"
STAGE_DEADLINE = "stage deadline reached"
# Why a READY experiment was left unrun: each is a named bound, never a negative.
BUDGET_REASONS = ("owning run cancelled", "engagement experiment max_runs exhausted",
                  "owning request budget exhausted", STAGE_DEADLINE)


def _snake(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", (name or "").lower()).strip("_") or "object"


def _parent_values(*texts: str, reserved=("id",)) -> list:
    """`{name}` placeholders other than the reserved ones (`{id}`; in a create body
    also `{tag}`): values some earlier step must have observed (a parent object's
    id), never guessed."""
    names: list = []
    for text in texts:
        for name in _PLACEHOLDER.findall(text or ""):
            if name not in reserved and name not in names:
                names.append(name)
    return names


def _template(text: str, id_value: str = "", tag_value: str = "") -> str:
    """Declared `{name}` placeholders -> the engine's `{{name}}`; `{id}` becomes
    `{{id_value}}` and `{tag}` `{{tag_value}}` when one is given."""
    def repl(match):
        name = match.group(1)
        if name == "id" and id_value:
            name = id_value
        elif name == "tag" and tag_value:
            name = tag_value
        return "{{" + name + "}}"
    return _PLACEHOLDER.sub(repl, text or "")


def _absolute(base_url: str, path: str) -> str | None:
    if re.match(r"^https?://", path or "", re.IGNORECASE):
        return path
    if not base_url:
        return None
    return base_url.rstrip("/") + "/" + (path or "").lstrip("/")


def _declared_key(spec: dict) -> str:
    return f"{str(spec.get('method', '')).upper()} {spec.get('path', '')}"


def _normalized_key(spec: dict) -> str:
    return endpoint_key(spec.get("method", ""), _PLACEHOLDER.sub("{id}", str(spec.get("path", ""))))


def _hypothesis_of(item, asm):
    """(hypothesis id, hypothesis or None) for a ChainingHypothesis or a graph Task."""
    if hasattr(item, "meta") and hasattr(item, "kind"):
        hid = (getattr(item, "meta", None) or {}).get("hypothesis_id", "")
        return hid, next((h for h in getattr(asm, "chaining_hypotheses", []) or []
                          if getattr(h, "id", "") == hid), None)
    return getattr(item, "id", ""), item


def _object_for(hyp, asm):
    """The BusinessObject a hypothesis is about: named in its source ("IDOR/BOLA
    on Note") or sharing an endpoint key with it. None when neither holds."""
    source = (getattr(hyp, "source", "") or "").lower()
    endpoints = set(getattr(hyp, "endpoints", []) or [])
    objects = list(getattr(asm, "business_objects", []) or [])
    for obj in sorted(objects, key=lambda o: -len(o.name or "")):
        if obj.name and re.search(rf"\b{re.escape(obj.name.lower())}\b", source):
            return obj
    return next((o for o in objects
                 if endpoints & set(list(o.read_endpoints) + list(o.write_endpoints))), None)


def _object_name_from_source(hyp) -> str:
    match = re.search(r"\bon\s+(.+)$", getattr(hyp, "source", "") or "")
    return (match.group(1).strip() if match else "") or getattr(hyp, "id", "") or "?"


def _expectation_for(expectations, object_name: str, endpoints: set):
    """The declared expectation for an object: matched by name, or by a declared
    create/read endpoint key that is one of the hypothesis's endpoints."""
    declared = [e for e in (expectations or []) if isinstance(e, dict)]
    if object_name:
        for exp in declared:
            if str(exp.get("object", "")).strip().lower() == object_name.lower():
                return exp
    for exp in declared:
        for part in ("create", "read"):
            spec = exp.get(part)
            if isinstance(spec, dict) and spec.get("method") and spec.get("path") \
                    and _normalized_key(spec) in endpoints:
                return exp
    return None


def _identities(sessions) -> tuple:
    """(owner, other) as (session ref, principal id): the first authenticated
    session and the next authenticated one with a DIFFERENT principal."""
    authed = [(ref, pid) for ref, pid in (sessions or [])
              if ref and pid and ref != "anonymous" and pid != ANON]
    owner = authed[0] if authed else None
    other = next((s for s in authed[1:] if owner and s[1] != owner[1]), None)
    return owner, other


def translate_cross_account(hypothesis_or_task, asm, expectations, sessions, values, *,
                            base_url: str = "", id_pointers: dict | None = None) -> ExperimentPlan:
    """Translate one IDOR/BOLA hypothesis into a cross-account private-object
    experiment, or into a blocked plan listing every input that is missing.

    `expectations` is the operator's `engagement.access_expectations`; `sessions`
    the run's registered (session ref, principal id) pairs; `values` the values
    observed so far. `id_pointers` maps a declared create key to an id pointer a
    validated planner proposal supplied: it can complete an extraction, never an
    expectation. Sends nothing."""
    values = values or {}
    hid, hyp = _hypothesis_of(hypothesis_or_task, asm)
    if hyp is None:
        return ExperimentPlan("blocked", missing=[
            f"hypothesis '{hid}' is not in the application semantic model"],
            experiment_id=experiment_id(KIND, hid, ""), hypothesis_id=hid,
            unblock={"hard": True, "extractions": [], "values": []})
    endpoints = set(getattr(hyp, "endpoints", []) or [])
    obj = _object_for(hyp, asm)
    exp = _expectation_for(expectations, obj.name if obj else "", endpoints)
    name = (obj.name if obj else "") or str((exp or {}).get("object", "")).strip() \
        or _object_name_from_source(hyp)
    exp_id = experiment_id(KIND, hid, name)
    missing: list = []
    unblock = {"object": name, "extractions": [], "values": [], "hard": False}

    def hard(text: str) -> None:
        missing.append(text)
        unblock["hard"] = True

    owner, other = _identities(sessions)
    declared = str((exp or {}).get("expectation", "")).strip()
    create = (exp or {}).get("create") if isinstance((exp or {}).get("create"), dict) else {}
    read = (exp or {}).get("read") if isinstance((exp or {}).get("read"), dict) else {}
    delete = (exp or {}).get("delete") if isinstance((exp or {}).get("delete"), dict) else {}
    if exp is None:
        hard(missing_expectation(name))
    elif declared not in SUPPORTED_EXPECTATIONS:
        hard(f"unsupported access expectation '{declared or '(none)'}' for object '{name}' "
             f"(engagement.access_expectations supports only 'private_to_creator')")
    elif not create.get("method") or not create.get("path"):
        hard(f"no declared create endpoint (method, path) for object '{name}'")
    elif str(create["method"]).upper() not in ("POST", "PUT"):
        hard(f"unsupported create method '{create['method']}' for object '{name}' (POST or PUT)")
    if exp is not None and declared in SUPPORTED_EXPECTATIONS:
        if not read.get("path") or str(read.get("method", "GET")).upper() != "GET" \
                or "{id}" not in str(read.get("path")):
            hard(missing_read_endpoint(name))
        if delete and (not delete.get("method") or "{id}" not in str(delete.get("path", ""))):
            hard(f"declared delete endpoint for object '{name}' needs a method and an "
                 f"{{id}} placeholder in its path")

    if owner is None:
        hard(MISSING_OWNER_IDENTITY)
    elif other is None:
        hard(MISSING_SECOND_IDENTITY)

    create_key = _declared_key(create) if create.get("method") and create.get("path") else ""
    pointer = str(create.get("id_pointer") or "") if create else ""
    if create_key and not pointer:
        pointer = str((id_pointers or {}).get(create_key, ""))
    owner_value, other_value = f"{_snake(name)}_id", f"{_snake(name)}_other_id"
    if exp is not None and declared in SUPPORTED_EXPECTATIONS and create_key:
        if not pointer:
            missing.append(missing_extraction(create_key))
            unblock["extractions"].append(
                {"endpoint": create_key, "method": str(create["method"]).upper(),
                 "path": str(create["path"]), "as": owner_value})
        elif not pointer.startswith("/"):
            hard(f"declared id extraction for {create_key} is not a JSON pointer: '{pointer}'")

    body_decl = create.get("body", "") if create else ""
    body_text = json.dumps(body_decl, separators=(",", ":")) \
        if isinstance(body_decl, (dict, list)) else str(body_decl or "")
    consumed: list = []
    if exp is not None and declared in SUPPORTED_EXPECTATIONS:
        consumed = _parent_values(create.get("path", ""), read.get("path", ""),
                                  delete.get("path", ""))
        consumed += [n for n in _parent_values(body_text, reserved=("id", "tag"))
                     if n not in consumed]
        for needed in consumed:
            if not values.get(needed):
                missing.append(missing_value(needed))
                unblock["values"].append(needed)
    create_url = _absolute(base_url, str(create.get("path", ""))) if create_key else None
    read_url = _absolute(base_url, str(read.get("path", ""))) if read.get("path") else None
    delete_url = _absolute(base_url, str(delete.get("path", ""))) if delete.get("path") else None
    if exp is not None and declared in SUPPORTED_EXPECTATIONS:
        for path, url in ((create.get("path"), create_url), (read.get("path"), read_url),
                          (delete.get("path"), delete_url)):
            if path and url is None:
                hard(f"no target base URL to resolve '{path}'")
                break

    if missing:
        return ExperimentPlan("blocked", missing=missing, experiment_id=exp_id,
                              object_name=name, hypothesis_id=hid, unblock=unblock)

    owner_ref, owner_pid = owner
    other_ref, other_pid = other
    marker_declared = bool(str(exp.get("marker_pointer") or "").strip())
    marker_pointer = str(exp.get("marker_pointer") or "").strip() if marker_declared else pointer
    if not marker_pointer.startswith("/"):
        return ExperimentPlan("blocked", missing=[
            f"marker_pointer for object '{name}' is not a JSON pointer: '{marker_pointer}'"],
            experiment_id=exp_id, object_name=name, hypothesis_id=hid,
            unblock={"object": name, "extractions": [], "values": [], "hard": True})
    method = str(create["method"]).upper()
    content_type = str(create.get("content_type") or "") or (
        "application/json" if isinstance(body_decl, (dict, list))
        or body_text.lstrip().startswith(("{", "[")) else "")
    tagged = "{tag}" in body_text
    create_template = _template(create_url)

    def creator(step_id, ref, value):
        # `{tag}` binds a token unique to THIS identity and run (see run_experiment).
        body_template = _template(body_text, tag_value=_TAG_OWNER if step_id == SETUP_OWNER
                                  else _TAG_OTHER)
        return WorkflowStep(
            step_id, method, create_template, ref, body_template=body_template,
            extractors=(Extractor(value, ExtractorKind.JSON_POINTER, pointer),),
            prerequisites=() if step_id == SETUP_OWNER else (SETUP_OWNER,),
            content_type=content_type)

    read_method = str(read.get("method", "GET")).upper()
    read_owner = _template(read_url, owner_value)
    read_other = _template(read_url, other_value)

    parent_pointer = marker_pointer.rsplit("/", 1)[0]

    def reader(step_id, ref, url, marker_name, prerequisites, object_name=""):
        extractors = [Extractor(marker_name, ExtractorKind.JSON_POINTER, marker_pointer,
                                required=False)]
        if object_name and not marker_declared:
            extractors.append(Extractor(object_name, ExtractorKind.JSON_POINTER, parent_pointer,
                                        required=False))
        return WorkflowStep(
            step_id, read_method, url, ref, prerequisites=prerequisites, observe=True,
            extractors=tuple(extractors))

    cleanup: list = []
    if delete:
        delete_method = str(delete["method"]).upper()
        for step_id, ref, value, prereq in ((CLEANUP_OWNER, owner_ref, owner_value, SETUP_OWNER),
                                            (CLEANUP_OTHER, other_ref, other_value, SETUP_OTHER)):
            cleanup.append(WorkflowStep(step_id, delete_method, _template(delete_url, value), ref,
                                        prerequisites=(prereq,), cleanup=True))
    experiment = Experiment(
        id=exp_id, kind=KIND, hypothesis_id=hid,
        required_identities={"owner": owner_ref, "other": other_ref},
        access_expectation={"object": name, "expectation": declared, "source": EXPECTATION_SOURCE},
        setup_steps=(creator(SETUP_OWNER, owner_ref, owner_value),
                     creator(SETUP_OTHER, other_ref, other_value)),
        baseline_steps=(reader(BASELINE, owner_ref, read_owner, _OWNER_MARKER, (SETUP_OWNER,),
                               _OWNER_OBJECT),),
        attack_steps=(reader(ATTACK, other_ref, read_owner, _ATTACK_MARKER,
                             (SETUP_OWNER, BASELINE), _ATTACK_OBJECT),),
        control_steps=(reader(CONTROL, other_ref, read_other, _CONTROL_MARKER, (SETUP_OTHER,),
                              _CONTROL_OBJECT),),
        cleanup_steps=tuple(cleanup),
        extracted_values=(owner_value, other_value),
        assertions=(f"declared {declared}: '{name}' created by {owner_pid} must not be readable "
                    f"by {other_pid}; attack 401/403/404 = controlled negative, attack 2xx "
                    f"carrying the owner's marker = authorization failure, anything else "
                    f"inconclusive; baseline and control must both be 2xx"),
        object_name=name, principals={"owner": owner_pid, "other": other_pid},
        owner_value=owner_value, other_value=other_value,
        read_template=f"{read_method} {read.get('path')}", read_url_template=read_owner,
        create_key=create_key, marker_pointer=marker_pointer, marker_declared=marker_declared,
        consumed_values=tuple(consumed), tagged=tagged)
    return ExperimentPlan("ready", experiment, experiment_id=exp_id, object_name=name,
                          hypothesis_id=hid, unblock=unblock)


# --- the verdict -----------------------------------------------------------------


@dataclass(frozen=True)
class Judgement:
    outcome: str                  # NEGATIVE | CONFIRMED | INCONCLUSIVE
    reason: str
    statuses: dict = field(default_factory=dict)     # baseline/attack/control -> HTTP status
    artifacts: dict = field(default_factory=dict)    # baseline/attack/control -> artifact id
    # Inconclusive only because nothing distinguishes the owner's object from the
    # other principal's own: a per-identity `{tag}` in the create body would.
    needs_tag: bool = False


def _is_2xx(status) -> bool:
    return isinstance(status, int) and 200 <= status < 300


def _parse_object(text: str):
    """The dict an object extractor captured: canonical JSON, or (for a whole-body
    extraction, which the engine renders with str()) a Python literal. None when
    it is not an object."""
    for parse in (json.loads, ast.literal_eval):
        try:
            value = parse(text)
        except (ValueError, SyntaxError, TypeError):
            continue
        return value if isinstance(value, dict) else None
    return None


def _volatile(key) -> bool:
    """Keys whose value legitimately differs between two reads of one object."""
    name, lowered = str(key), str(key).lower()
    return (name.endswith("At") or lowered.endswith("_at") or "timestamp" in lowered
            or lowered in {"updated", "created", "modified", "ts", "time", "date",
                           "lastmodified", "last_modified"})


_MISSING = object()


def _leaves(value, path=()):
    """(path, scalar) for every non-volatile scalar leaf of a JSON value."""
    if isinstance(value, dict):
        for key, child in value.items():
            if not _volatile(key):
                yield from _leaves(child, path + (key,))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _leaves(child, path + (index,))
    else:
        yield path, value


def _at(value, path):
    """The value at `path`, or _MISSING when any step of it is absent."""
    for step in path:
        try:
            value = value[step]
        except (KeyError, IndexError, TypeError):
            return _MISSING
    return value


def _object_matches(owner, attack, required) -> bool:
    """Every non-volatile scalar leaf of the owner's object is PRESENT in the
    attack's at the same path (a missing key is not a null), and the `required`
    leaves (see _required_leaves) are equal. Everything else may differ."""
    for path, leaf in _leaves(owner):
        got = _at(attack, path)
        if got is _MISSING or (path in required and got != leaf):
            return False
    return True


def _distinctive(owner, control, marker_key: str, owner_tag: str = "") -> list:
    """The owner's leaves that can show the attack returned the OWNER'S object, not
    just an object with the same id.

    A leaf carrying the owner's `{tag}` token is the strongest such content: only
    the owner's create sent that token, so it can appear in another principal's
    response only if the owner's object was returned. Without one, content is:
    non-volatile, not the marker/id itself, not trivial (None, a bool or an empty
    string -- values any error or default object carries) and, with the other
    principal's own object (`control`) to contrast with, different from it
    (`{"type": "note"}` is in both)."""
    leaves = [(path, leaf) for path, leaf in _leaves(owner) if path != (marker_key,)]
    if owner_tag:
        tagged = [(path, leaf) for path, leaf in leaves
                  if isinstance(leaf, str) and owner_tag in leaf]
        if tagged:
            return tagged
    leaves = [(path, leaf) for path, leaf in leaves
              if leaf is not None and not isinstance(leaf, bool) and leaf != ""]
    if control is None:
        return leaves
    return [(path, leaf) for path, leaf in leaves if _at(control, path) != leaf]


def _required_leaves(owner, distinctive, owner_tag: str = "") -> set:
    """The leaf paths the attack's object must reproduce exactly.

    With the owner's `{tag}` among the distinctive leaves, only those: the token
    proves the owner's content came back, so a viewer-relative field (`isOwner`, a
    view counter) may differ. Without one, a distinctive leaf can be server metadata
    (an `ownerId`) that a masked or nulled response still carries, so every
    non-trivial leaf must match -- a reader-dependent value then stays inconclusive,
    which a `{tag}` resolves."""
    if owner_tag and any(isinstance(leaf, str) and owner_tag in leaf
                         for _, leaf in distinctive):
        return {path for path, _ in distinctive}
    return {path for path, leaf in _leaves(owner)
            if leaf is not None and not isinstance(leaf, bool) and leaf != ""}


def judge(result: WorkflowResult, owner_marker: str | None = None, *,
          match_object: bool = False, marker_key: str = "id",
          owner_tag: str = "") -> Judgement:
    """The verdict for one executed experiment workflow. Pure: no I/O, no ledger.

    `owner_marker` is the value that identifies the owner's object in a read
    response. None means "take it from the baseline response at the declared
    marker pointer" (an explicit pointer); a string is used as given (the owner's
    id), and an empty string is unknown -- never a basis for a verdict.

    `match_object` (set when the marker is only the owner's id) also requires the
    attack's object -- the JSON parent of the marker -- to carry the owner's
    object, not merely echo its id: a 200 `{"data": {"id": 41, "error":
    "forbidden"}}` is a soft denial, not an access. That needs content to compare
    (see `_distinctive`): a leaf carrying `owner_tag`, the token only the owner's
    create sent, or otherwise a non-trivial leaf besides the marker (`marker_key`)
    that differs from the other principal's own object. With none the comparison
    proves nothing and a 2xx stays inconclusive (`needs_tag`). Only a denial
    needs no content. Every owner leaf must be PRESENT in the attack object;
    only the distinctive ones must be equal.

    Artifact ids are reported only for steps that actually sent (status PASSED, so
    the transport outcome was ok); a step blocked by the gate, the budget or scope
    has no exchange to cite.

      inconclusive  baseline not 2xx or lacking the marker, control not 2xx (the
                    second session or endpoint is not shown to work), a marker that
                    does not tell the two objects apart, an attack that is neither
                    a denial nor a 2xx, or a 2xx without the marker;
      negative      attack 401/403/404 with a valid baseline and control;
      confirmed     attack 2xx carrying the owner's marker (the caller still has to
                    establish the ownership fact before it is a proof).
    """
    steps = {s.step_id: s for s in result.steps}
    statuses = {n: getattr(steps.get(n), "status_code", None) for n in (BASELINE, ATTACK, CONTROL)}
    artifacts = {n: (steps[n].artifact_id or "") if n in steps and steps[n].status == StepStatus.PASSED
                 else "" for n in (BASELINE, ATTACK, CONTROL)}

    def inconclusive(reason: str, needs_tag: bool = False) -> Judgement:
        return Judgement(INCONCLUSIVE, reason, statuses, artifacts, needs_tag)

    def passed(name: str) -> bool:
        step = steps.get(name)
        return step is not None and step.status == StepStatus.PASSED

    if not passed(BASELINE):
        stopped = next((s for s in result.steps if s.status in (
            StepStatus.BLOCKED, StepStatus.FAILED, StepStatus.CANCELLED)), None)
        why = f"{stopped.step_id}: {stopped.reason}" if stopped else "no step ran"
        return inconclusive(f"baseline did not complete ({why})")
    if not _is_2xx(statuses[BASELINE]):
        return inconclusive(f"baseline read as the owner returned HTTP {statuses[BASELINE]}, not 2xx")
    seen = steps[BASELINE].extracted.get(_OWNER_MARKER, "")
    expected = seen if owner_marker is None else owner_marker
    if not expected:
        return inconclusive("the owner's marker is unknown: the baseline response does not carry it")
    if seen != expected:
        return inconclusive("baseline response lacks the owner's object id/marker")
    owner_object = (_parse_object(steps[BASELINE].extracted.get(_OWNER_OBJECT, ""))
                    if match_object else None)
    if match_object and owner_object is None:
        return inconclusive("baseline response carries no object at the marker's parent")
    if not passed(CONTROL) or not _is_2xx(statuses[CONTROL]):
        return inconclusive(
            f"control read of the other principal's own object returned HTTP {statuses[CONTROL]}, "
            f"not 2xx: its session or the endpoint is not shown to work")
    if steps[CONTROL].extracted.get(_CONTROL_MARKER, "") == expected:
        return inconclusive("the marker does not distinguish the owner's object from the other "
                            "principal's own object", needs_tag=True)
    if not passed(ATTACK):
        return inconclusive("the attack read did not complete")
    if len({v for v in artifacts.values() if v}) < 3:
        return inconclusive("baseline, attack and control exchanges are not three distinct artifacts")
    attack = statuses[ATTACK]
    if attack in _DENIED:
        return Judgement(NEGATIVE, f"attack read denied with HTTP {attack}; baseline and control "
                                   f"were 2xx", statuses, artifacts)
    if _is_2xx(attack):
        if steps[ATTACK].extracted.get(_ATTACK_MARKER, "") == expected:
            if match_object:
                distinctive = _distinctive(
                    owner_object,
                    _parse_object(steps[CONTROL].extracted.get(_CONTROL_OBJECT, "")),
                    marker_key, owner_tag)
                if not distinctive:
                    return inconclusive(
                        "the owner's object has no distinctive content to compare (only its id, "
                        "volatile or trivial values, or nothing that differs from the other "
                        "principal's own object)", needs_tag=True)
                if not _object_matches(
                        owner_object, _parse_object(steps[ATTACK].extracted.get(_ATTACK_OBJECT, "")),
                        _required_leaves(owner_object, distinctive, owner_tag)):
                    return inconclusive(
                        "the attack response carries the id but not the owner's object")
            return Judgement(CONFIRMED, f"attack read returned HTTP {attack} carrying the owner's "
                                        f"marker", statuses, artifacts)
        return inconclusive(f"attack returned HTTP {attack} without the owner's marker: not a "
                            f"demonstrated crossing")
    return inconclusive(f"attack returned HTTP {attack}: neither a denial nor an access")


# --- one run -----------------------------------------------------------------------


def _mask_workflow(result: WorkflowResult) -> dict:
    """result.to_dict() with every observed value masked: ids and markers stay out
    of the persisted task graph; the names stay."""
    data = result.to_dict()
    data["values"] = {k: "[observed]" for k in data.get("values", {})}
    for step in data.get("steps", []):
        step["extracted"] = {k: "[observed]" for k in step.get("extracted", {})}
    return data


@dataclass
class ExperimentOutcome:
    outcome: str                  # NEGATIVE | CONFIRMED | INCONCLUSIVE
    reason: str
    proof: ProofRecord
    persisted: bool
    workflow: WorkflowResult
    case: TestCaseRef
    values: dict                  # the experiment's extracted values, name -> value
    cleanup: str
    ownership_fact: OwnershipFact | None = None
    # Executed, but nothing could distinguish the two objects and the declared create
    # body has no `{tag}`: the experiment is BLOCKED on that exact input, not failed.
    needs_tag: bool = False


def _cleanup_note(experiment: Experiment, result: WorkflowResult) -> str:
    if not experiment.cleanup_steps:
        return "none declared"
    done, registered = len(result.cleanup_completed), len(result.cleanup_registered)
    return f"completed {done}/{registered} registered cleanup step(s)"


async def run_experiment(experiment: Experiment, run_context, *, ledger,
                         values: dict | None = None) -> ExperimentOutcome:
    """Run one ready experiment through the run's transport, judge it and persist
    its proof. Baseline, attack and control are sent under the proof's case id."""
    from harness import store
    if experiment.kind in BROWSER_KINDS:
        return await _run_browser_experiment(experiment, run_context)
    owner_pid, other_pid = experiment.principals["owner"], experiment.principals["other"]
    case = TestCaseRef.make(
        run_id=run_context.run_id, request_template_id=experiment.read_template,
        check_id=CHECK_ID, principal_id=other_pid, workflow_state_id=experiment.id,
        finding_ref=experiment.hypothesis_id)
    workflow = experiment.to_workflow(case.case_id)
    bound = {n: (values or {})[n] for n in experiment.consumed_values if (values or {}).get(n)}
    if experiment.tagged:
        # One random token per identity and run, never reused: content only that
        # identity's own create sent.
        bound[_TAG_OWNER], bound[_TAG_OTHER] = secrets.token_hex(8), secrets.token_hex(8)
    result = await execute_workflow(workflow, run_context, initial_values=bound, capability=VALIDATOR)
    owner_id = result.values.get(experiment.owner_value, "")
    judged = judge(result, None if experiment.marker_declared else owner_id,
                   match_object=not experiment.marker_declared,
                   marker_key=experiment.marker_pointer.rsplit("/", 1)[-1]
                   .replace("~1", "/").replace("~0", "~"),
                   owner_tag=bound.get(_TAG_OWNER, ""))
    outcome, reason, fact = judged.outcome, judged.reason, None

    if outcome in (CONFIRMED, NEGATIVE):
        ref = object_reference(_bind(experiment.read_url_template, result.values),
                               run_id=run_context.run_id)
        session = getattr(getattr(run_context, "sessions", None), "get", lambda _r: None)(
            experiment.required_identities["other"])
        other = getattr(session, "principal", None) or Principal(id=other_pid)
        prior = ledger.lookup(ref)
        # `lookup` is None both for an object nobody declared anything about and
        # for one whose equally specific declarations contradict each other.
        contradictory = prior is None and ledger.has_declaration(ref)
        # What the ledger already says about the OTHER principal and this object,
        # from operator declarations (shared, public, any authenticated account,
        # declared permissions) or earlier observations. A declared entitlement
        # means the read is not a crossing, whatever the experiment saw.
        entitled = ledger.authorization(other, ref) == AuthzDecision.AUTHORIZED
        conflicting = prior is not None and prior.known and (
            prior.shared_with or prior.public or prior.authenticated
            or prior.owner_principal_id != owner_pid)
        if outcome == CONFIRMED and contradictory:
            outcome, reason = INCONCLUSIVE, "contradictory operator declarations"
        elif outcome == CONFIRMED and (entitled or conflicting):
            outcome, reason = INCONCLUSIVE, (
                "the ownership ledger already holds a conflicting declaration for this object")
        elif not contradictory and (prior is None or not prior.known):
            # Establish the declared ownership (created-as the owner) BEFORE the
            # verdict is persisted. A read that merely worked never does this.
            fact = ledger.record(OwnershipFact(
                object_ref=ref, owner_principal_id=owner_pid,
                provenance=f"declared private_to_creator; created-as:{owner_pid} "
                           f"via {experiment.create_key}"))
        if outcome == CONFIRMED and ledger.authorization(other, ref) != AuthzDecision.UNAUTHORIZED:
            outcome, reason, fact = INCONCLUSIVE, (
                "the ownership ledger does not establish the read as an unauthorized crossing"), None

    cleanup = _cleanup_note(experiment, result)
    verdict = {CONFIRMED: Verdict.CONFIRMED, NEGATIVE: Verdict.CONTROLLED_NEGATIVE}.get(
        outcome, Verdict.INCONCLUSIVE)
    art = judged.artifacts
    proof = ProofRecord(
        proof_id="", case=case, validator=VALIDATOR, verdict=verdict,
        validator_version=VALIDATOR_VERSION,
        baseline_artifact_id=art.get(BASELINE, ""), attack_artifact_id=art.get(ATTACK, ""),
        control_artifact_ids=(art[CONTROL],) if art.get(CONTROL) else (),
        expected_invariant=experiment.assertions, observed_result=reason,
        limitation=f"cleanup: {cleanup}", executed=any(art.values()))
    ok, why = store.persist_proof_record(proof)
    if not ok:
        outcome, reason = INCONCLUSIVE, f"proof was not persisted: {why}"
    produced = {n: result.values[n] for n in experiment.extracted_values if n in result.values}
    return ExperimentOutcome(outcome, reason, proof, ok, result, case, produced, cleanup, fact,
                             needs_tag=bool(judged.needs_tag and not experiment.tagged
                                            and outcome == INCONCLUSIVE and ok))


def _bind(template: str, values: dict) -> str:
    from harness.workflow_engine import bind_template
    return bind_template(template, values)[0]


# --- graph tasks ---------------------------------------------------------------------


def supports(hypothesis) -> bool:
    return bool({str(c).lower() for c in (getattr(hypothesis, "classes", []) or [])}
                & SUPPORTED_CLASSES)


def experiment_tasks(state) -> list:
    return [t for t in state.graph.tasks.values() if t.kind == "experiment"]


def evaluate_experiments(state, asm, expectations, sessions, values=None, *,
                         base_url: str = "", id_pointers: dict | None = None) -> dict:
    """Prerequisite evaluation for every IDOR/BOLA hypothesis: translate it and
    record the result as a graph task. A ready plan is a READY `experiment:<id>`
    task; a blocked one is the same task BLOCKED with the missing inputs as
    `needs`. Re-running it re-evaluates BLOCKED experiment tasks against the values
    and identities known now (clearing `needs` when one has become satisfiable).
    The proposal's chain-hypothesis task is gated on the experiment: it stays a
    proposal, never run and never confirmed here. Sends nothing.

    Returns {experiment task id: ExperimentPlan}."""
    from harness.engagement import add_chain_hypothesis_task
    values = state.observed_values if values is None else values
    graph, plans, by_object = state.graph, {}, {}
    for hyp in getattr(asm, "chaining_hypotheses", []) or []:
        if not supports(hyp):
            continue
        plan = translate_cross_account(hyp, asm, expectations, sessions, values,
                                       base_url=base_url, id_pointers=id_pointers)
        # One experiment per object: a second hypothesis on the same object (a
        # different sink) is validated by that same run, not by creating more.
        shared = by_object.get((KIND, plan.object_name.lower()))
        if shared is None:
            tid = task_graph.make_id("experiment", plan.experiment_id)
            by_object[(KIND, plan.object_name.lower())] = tid
            meta = {"hypothesis_id": plan.hypothesis_id, "kind": KIND,
                    "object": plan.object_name}
            if plan.ready:
                meta["experiment"] = plan.experiment.to_dict()
            else:
                meta.update(missing=list(plan.missing), unblock=plan.unblock)
            task = graph.add(
                "experiment", plan.experiment_id,
                reason=f"cross-account private-object test of '{plan.object_name}' "
                       f"({getattr(hyp, 'source', '')})",
                needs="" if plan.ready else "; ".join(plan.missing),
                source=",".join(getattr(hyp, "endpoints", []) or [])[:200], meta=meta,
                value=float(getattr(hyp, "rank", 0.0) or 0.0))
            # An existing task is brought up to date: a satisfiable plan drops the
            # stale missing list (whether the task is still BLOCKED or was already
            # released by a single observed value) and carries the experiment; a
            # still-blocked one carries its current missing inputs.
            if task.status == task_graph.BLOCKED and task.meta.get("awaiting_tag") and not (
                    plan.ready and plan.experiment.tagged):
                pass    # a run found nothing to tell the objects apart: only a `{tag}` unblocks it
            elif task.status in (task_graph.BLOCKED, task_graph.READY):
                if plan.ready:
                    task.meta.pop("missing", None)
                    task.meta.pop("unblock", None)
                    task.meta["experiment"] = plan.experiment.to_dict()
                    if task.status == task_graph.BLOCKED:
                        graph.resolve_need(task.id)
                elif task.status == task_graph.BLOCKED:
                    task.needs = "; ".join(plan.missing)
                    task.meta.update(missing=list(plan.missing), unblock=plan.unblock)
            plans[task.id] = plan
            tid = task.id
        else:
            tid = shared
        chain = add_chain_hypothesis_task(
            graph, hyp, needs=f"validated by {tid}", depends_on=[tid],
            extra_meta={"experiment": tid})
        if chain.status not in (task_graph.DONE, task_graph.SKIPPED):
            chain.needs = f"validated by {tid}"
            if tid not in chain.depends_on:
                chain.depends_on.append(tid)
            chain.meta["experiment"] = tid
    return plans


# --- the feedback loop ------------------------------------------------------------------


def selected_experiment_tasks(state, hypothesis_ids=None) -> list:
    tasks = experiment_tasks(state)
    if hypothesis_ids is None:
        return tasks
    selected = set(hypothesis_ids)
    aliases = {t.meta.get("experiment") for t in state.graph.tasks.values()
               if t.kind == "chain-hypothesis" and t.target in selected}
    return [t for t in tasks if t.meta.get("hypothesis_id") in selected or t.id in aliases]


def _relevant_policy(plan, run_context):
    gate = run_context.gate.config
    if plan.kind == BROWSER_HASH:
        return {'active':gate.active_enabled}
    capability = 'browser_stored_experiment' if plan.kind == BROWSER_STORED else VALIDATOR
    policy = {'active':gate.active_enabled,'writes':gate.allow_mutating_replay,
              'effective_mutating_ceiling':run_context.gate.mutating_headroom(None,capability)[2]}
    if plan.kind in BROWSER_KINDS:
        return policy
    from urllib.parse import urlsplit
    route = urlsplit(plan.read_url_template)
    prefix = route.path.split('{', 1)[0]
    owners = ((run_context.config or {}).get('authz') or {}).get('owners', {})
    selected = {}
    for host, entries in owners.items():
        if host not in (route.netloc, route.hostname, '*'):
            continue
        selected[host] = [entry for entry in entries if
            str(entry.get('path', '')).split('{', 1)[0].startswith(prefix) or
            prefix.startswith(str(entry.get('path', '')).split('{', 1)[0].split('*', 1)[0])]
    policy['owners'] = {host:rows for host,rows in selected.items() if rows}
    return policy


def experiment_applicability(plan: Experiment, run_context, values=None) -> str:
    """Exact within-run applicability of a migrated attempt, never credentials.

    Hash only consumed values, not the whole engagement's mutable state. Session
    refreshes change generation even when a reference/principal is unchanged.
    """
    data = asdict(plan)
    data.pop("id", None)
    data.pop("hypothesis_id", None)  # equivalent aliases can reference one object's proof
    sessions = {}
    for role, ref in plan.required_identities.items():
        session = run_context.sessions.get(ref)
        sessions[role] = {"reference": ref, "principal": getattr(session, "principal_id", None),
                          "generation": getattr(session, "generation", None),
                          "expired": getattr(session, "health", "expired") == "expired",
                          "origins": sorted(getattr(session, "allowed_origins", ())),
                          "registration": id(session) if session is not None else None}
    consumed = {name: hashlib.sha256(str((values or {}).get(name, "")).encode()).hexdigest()
                for name in plan.consumed_values}
    payload = {"run": run_context.run_id, "mechanism": data, "oracle_version": VALIDATOR_VERSION,
               "sessions": sessions, "consumed_values": consumed,
               "declared_policy": _relevant_policy(plan, run_context)}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()


def run_sessions(run_context) -> list:
    """The run's authenticated sessions as (session ref, principal id), in
    registration order. The anonymous session is never an experiment identity."""
    return [(s.session_id, s.principal_id) for s in run_context.sessions.all()
            if s.headers and s.session_id != "anonymous" and s.principal_id not in ("", ANON)
            and s.health != "expired"]


def _resolve_value_needs(state, name: str) -> None:
    """A newly observed value releases any task whose ONLY prerequisite is that
    value. A task naming other missing inputs is left to the re-evaluation."""
    only = missing_value(name)
    for task in list(state.graph.blocked()):
        if task.needs == only:
            state.graph.resolve_need(task.id)


async def _consult_planner(state, planner, asm, ctx: dict, counts: dict, asked: set, hypothesis_ids=None) -> bool:
    """Ask the planner, once per task, about a blocked experiment whose missing
    items are only an extraction pointer or an unobserved value. Returns whether
    anything it proposed was accepted AND resolved an input."""
    if planner is None:
        return False
    changed = False
    for task in [t for t in selected_experiment_tasks(state, hypothesis_ids) if t.status == task_graph.BLOCKED]:
        unblock = task.meta.get("unblock") or {}
        if task.id in asked or unblock.get("hard") or not (
                unblock.get("extractions") or unblock.get("values")):
            continue
        asked.add(task.id)
        counts["calls"] += 1
        try:
            outcome = await planner.plan(task, hypotheses=getattr(asm, "chaining_hypotheses", []))
        except Exception as exc:   # a failing model must never sink the loop
            counts["errors"] += 1
            counts.setdefault("error_types", []).append(type(exc).__name__)
            continue
        counts["accepted"] += len(outcome.accepted)
        counts["rejected"] += len(outcome.rejected)
        if outcome.pointers:
            ctx["id_pointers"].update(outcome.pointers)
            changed = True
        for name, value in outcome.values.items():
            state.observed_values[name] = value
            changed = True
    return changed


def _replan(state, asm, ctx: dict) -> dict:
    if ctx.get("run_context") is not None:
        _evaluate_browser(state, asm, ctx["run_context"])
    return evaluate_experiments(state, asm, ctx["expectations"], ctx["sessions"],
                                state.observed_values, base_url=ctx["base_url"],
                                id_pointers=ctx["id_pointers"])


async def run_experiment_loop(state, run_context, *, ledger, expectations, sessions, max_runs,
                              planner=None, asm=None, base_url: str = "", hypothesis_ids=None,
                              deadline: float | None = None) -> dict:
    """Run READY experiment tasks, feeding each outcome back into the graph.

    Per run: execute (compile, send, judge, persist the proof); mark the task DONE
    (negative or confirmed) or FAILED (inconclusive) with the proof id as its
    evidence; record the extracted values in `state.observed_values` and the
    ownership fact in `ledger`; then re-evaluate the BLOCKED experiment tasks with
    the new values, so a dependent experiment becomes READY and runs in this same
    loop. Stops when no READY experiment remains, `max_runs` have run, the run is
    cancelled or the optional `deadline` (time.monotonic()) has passed.

    Returns {"completed", "failed", "blocked", "deferred", "runs", "planner"}:
    `blocked` maps each blocked task id to its exact missing inputs."""
    asm = asm if asm is not None else getattr(state, "semantic_model", None)
    counts = {"accepted": 0, "rejected": 0, "calls": 0, "errors": 0}
    completed, failed, runs = [], [], 0
    if asm is None:
        return {"completed": [], "failed": [], "blocked": {}, "deferred": [], "runs": 0,
                "planner": counts, "skipped": "no application semantic model"}
    ctx = {"expectations": expectations or [], "sessions": list(sessions or []),
           "base_url": base_url, "id_pointers": {}, "run_context": run_context}
    asked: set = set()
    _replan(state, asm, ctx)
    if run_context.cancel.cancelled:
        planner = None
    if await _consult_planner(state, planner, asm, ctx, counts, asked, hypothesis_ids):
        _replan(state, asm, ctx)

    def past_deadline():
        return deadline is not None and time.monotonic() >= deadline

    while runs < max_runs and not run_context.cancel.cancelled and not past_deadline():
        selected = {t.id for t in selected_experiment_tasks(state, hypothesis_ids)}
        task = next((t for t in state.graph.ready_by_value()
                     if t.kind == "experiment" and t.id in selected), None)
        if task is None:
            break
        if task.meta.get("kind") in BROWSER_KINDS:
            plan = translate_browser(task.meta.get("hypothesis_id"), asm, run_context)
        else:
            plan = translate_cross_account(task, asm, ctx["expectations"], ctx["sessions"],
                                           state.observed_values, base_url=base_url,
                                           id_pointers=ctx["id_pointers"])
        if not plan.ready:
            # What made it ready is gone (a session left, a value was withdrawn): park it.
            task.needs = "; ".join(plan.missing)
            task.meta.update(missing=list(plan.missing), unblock=plan.unblock)
            state.graph.mark(task.id, task_graph.BLOCKED)
            continue
        missing_authority = preflight_authority(plan.experiment, run_context)
        if missing_authority:
            task.needs = missing_authority
            task.meta['missing'] = [missing_authority]
            task.meta['readiness'] = {'status':'needs_prerequisite','reason':missing_authority}
            state.graph.mark(task.id, task_graph.BLOCKED)
            continue
        applicability = experiment_applicability(plan.experiment, run_context, state.observed_values)
        run_context.experiment_runs += 1  # reserve before I/O; failures/cancellation still consume the bound
        try:
            done = await run_experiment(plan.experiment, run_context, ledger=ledger,
                                        values=state.observed_values)
        except Exception as exc:
            task.meta['applicability'] = applicability
            task.meta['reason'] = 'experiment attempt failed: '+type(exc).__name__
            task.meta['readiness'] = {'status':'inconclusive','reason':task.meta['reason']}
            state.graph.mark(task.id,task_graph.FAILED)
            raise
        runs += 1
        art = {"baseline": done.proof.baseline_artifact_id, "attack": done.proof.attack_artifact_id,
               "control": (done.proof.control_artifact_ids or ("",))[0]}
        attempt_ids = task.meta.setdefault("attempt_ids", [])
        if task.evidence_ref and task.evidence_ref != task.source and task.evidence_ref not in attempt_ids:
            attempt_ids.append(task.evidence_ref)
        if done.proof.proof_id not in attempt_ids:
            attempt_ids.append(done.proof.proof_id)
        task.evidence_ref = done.proof.proof_id
        task.meta["applicability"] = applicability
        task.meta["readiness"] = {"status": "ready", "reason": "attempt executed"}
        task.meta.update(outcome=done.outcome, artifacts=art, reason=done.reason,
                         workflow=_mask_workflow(done.workflow), cleanup=done.cleanup,
                         proof_verdict=done.proof.verdict.value)
        succeeded = done.outcome in (NEGATIVE, CONFIRMED)
        if done.needs_tag:
            task.needs = MISSING_TAG
            task.meta.update(missing=[MISSING_TAG], awaiting_tag=True,
                             unblock={"object": plan.object_name, "extractions": [],
                                      "values": [], "hard": True})
            state.graph.mark(task.id, task_graph.BLOCKED)
        else:
            state.graph.mark(task.id, task_graph.DONE if succeeded else task_graph.FAILED)
        entry = {"task_id": task.id, "experiment_id": plan.experiment_id,
                 "hypothesis_id": plan.hypothesis_id, "outcome": done.outcome,
                 "reason": done.reason, "proof_id": done.proof.proof_id,
                 "verdict": done.proof.verdict.value, "case_id": done.case.case_id,
                 "artifacts": art, "cleanup": done.cleanup}
        if not done.needs_tag:      # a task blocked on the tag is reported under "blocked"
            (completed if succeeded else failed).append(entry)
        for dependent in state.graph.tasks.values():
            if dependent.kind == "chain-hypothesis" and dependent.meta.get("experiment") == task.id:
                dependent.meta["experiment_outcome"] = done.outcome
        # New observations: values for later experiments (never logged), then the
        # re-evaluation that turns a satisfied BLOCKED experiment into a READY one.
        for name, value in done.values.items():
            state.observed_values[name] = value
            _resolve_value_needs(state, name)
        _replan(state, asm, ctx)
        if await _consult_planner(state, planner, asm, ctx, counts, asked, hypothesis_ids):
            _replan(state, asm, ctx)

    stopped_by = ('owning run cancelled' if run_context.cancel.cancelled else
                  'experiment max_runs exhausted' if runs >= max_runs else
                  STAGE_DEADLINE if past_deadline() else
                  'no ready selected experiment; prerequisites or selection remain')
    return {"stopped_by": stopped_by, "completed": completed, "failed": failed,
            "blocked": {t.id: list(t.meta.get("missing") or [t.needs])
                        for t in experiment_tasks(state) if t.status == task_graph.BLOCKED},
            "deferred": [t.id for t in experiment_tasks(state) if t.status == task_graph.READY],
            "runs": runs, "planner": counts}


def project_proofs(state, run_context):
    """Project only this run's stored attempts; never broaden a case to a family."""
    from harness import store
    from harness.assessment_health import stored_proof_artifacts_resolve
    if run_context is None:
        return {"cases": [], "findings": []}
    references = {ref for task in experiment_tasks(state)
                  for ref in [task.evidence_ref, *task.meta.get("attempt_ids", [])] if ref and ref != task.source}
    if not references:
        return {"cases": [], "findings": []}
    cases, findings, found = [], [], set()
    for proof in store.proofs_for_run(run_context.run_id):
        if proof['proof_id'] not in references:
            continue
        found.add(proof['proof_id'])
        case = proof['case']
        resolved = stored_proof_artifacts_resolve(proof)
        conclusive = proof['verdict'] in ('confirmed', 'controlled_negative') and resolved
        cases.append(dict(case_id=case['case_id'], proof_id=proof['proof_id'],
            mechanism=proof['validator'], status=proof['verdict'] if conclusive else 'inconclusive',
            executed=proof['executed'], artifacts_resolved=resolved,
            request_template_id=case['request_template_id'], principal_id=case['principal_id'],
            workflow_state_id=case['workflow_state_id']))
        if not conclusive or proof['verdict'] != 'confirmed':
            continue
        # The attack event supplies the actual observed location, never a guessed ID.
        events = store.ledger_events_for(case['case_id'])
        event = next((e for e in events if (e.get('data') or {}).get('artifact_id') == proof['attack_artifact_id']), None)
        url = (event or {}).get('data', {}).get('request', '')
        findings.append(dict(vulnerability_class=('dom_xss' if proof['validator'] == BROWSER_HASH else 'stored_xss' if proof['validator'] == BROWSER_STORED else 'idor'), severity='high', confidence=1.0,
            confirmed=True, confirmed_by_leg=proof['validator'], validator=proof['validator'],
            case_id=case['case_id'], proof_id=proof['proof_id'], url=url,
            summary=proof['observed_result'], basis='derived'))
    cases.extend({"proof_id": ref, "status": "unresolved", "executed": False,
                  "reason": "referenced attempt missing from owning run store"} for ref in sorted(references - found))
    return {"cases": cases, "findings": findings}


# Browser mechanisms are compilers/judges in the same controller, not validators
# that infer execution from reflected text or guessed consumer URLs.
def translate_browser(hypothesis_id, asm, run_context, *, check_cost=True):
    from urllib.parse import urlsplit, parse_qsl, urlencode, urlunsplit
    from harness.run_context import ScopePolicy
    eng = (run_context.config or {}).get('engagement', {})
    bindings = [b for b in eng.get('browser_bindings', []) if b.get('hypothesis_id') == hypothesis_id]
    kind = bindings[0].get('mechanism', '') if len(bindings) == 1 else ''
    eid = experiment_id(kind, hypothesis_id, 'browser')
    def blocked(reason):
        return ExperimentPlan('blocked', missing=[reason], experiment_id=eid,
                              hypothesis_id=hypothesis_id, object_name='browser', unblock={'hard':True})
    if hypothesis_id not in {h.id for h in getattr(asm, 'chaining_hypotheses', [])}:
        return blocked('existing semantic hypothesis required')
    if len(bindings) != 1 or kind not in BROWSER_KINDS:
        return blocked('one explicit supported browser binding required')
    allowed = {'mechanism','hypothesis_id','session_ref'} | ({'route','location','parameter'} if kind == BROWSER_HASH else {'write_capture','pointer','consumer_url'})
    if set(bindings[0]) - allowed:
        return blocked('unsupported browser binding fields')
    binding = dict(bindings[0])
    session_ref = binding.get('session_ref', '')
    session = run_context.sessions.get(session_ref)
    if session is None or session.health == 'expired':
        return blocked('registered nonexpired browser session required')
    gate = run_context.gate.config
    if not gate.active_enabled:
        return blocked('active browser testing disabled')
    context = run_context.experiment_context or {}
    route = binding.get('route', '') if kind == BROWSER_HASH else binding.get('consumer_url', '')
    if not isinstance(route, str) or urlsplit(route).scheme not in ('http','https') or urlsplit(route).username is not None:
        return blocked('explicit HTTP consumer route required')
    urls = [route]
    from harness import security
    binding['route_sha256'] = hashlib.sha256(route.encode()).hexdigest()
    binding['route' if kind == BROWSER_HASH else 'consumer_url'] = security.sanitize_text(route)
    body_template, write = '', None
    if kind == BROWSER_HASH:
        parsed = urlsplit(route)
        fragment_path, separator, query = parsed.fragment.partition('?')
        pairs = parse_qsl(query, keep_blank_values=True)
        parameter = binding.get('parameter')
        if binding.get('location') != 'fragment_query' or not fragment_path or not separator or sum(k == parameter for k,v in pairs) != 1:
            return blocked('existing unique fragment-query parameter required')
        phases = []
        public_base = _browser_url_base(route)
        for phase in (BASELINE, ATTACK, CONTROL):
            url = public_base + '{{browser_url_suffix_' + phase + '}}'
            phases.append((WorkflowStep(phase,'GET',url,session_ref,action='browser_visit', observation_marker='{{browser_marker_'+phase+'}}'),))
    else:
        if not gate.allow_mutating_replay:
            return blocked('stored writes require mutating permission')
        ceiling = getattr(gate, 'mutating_ceiling_by_check', {}).get('browser_stored_experiment', 0)
        if ceiling < 3:
            return blocked('explicit browser_stored_experiment mutating ceiling of at least 3 required')
        captures = context.get('captured', ())
        index = binding.get('write_capture')
        if isinstance(index,bool) or not isinstance(index,int) or not 0 <= index < len(captures):
            return blocked('existing write capture index required')
        try:
            write = _browser_capture(run_context,index)
        except (ValueError,TypeError,KeyError,IndexError):
            return blocked("valid observed write capture required")
        if write.method.upper() not in ('POST','PUT','PATCH'):
            return blocked('stored mechanism supports JSON POST/PUT/PATCH only')
        headers = {str(k).lower():v for k,v in (write.request_headers or {}).items()}
        if 'application/json' not in str(headers.get('content-type','')).lower():
            return blocked('observed JSON write content type required')
        try:
            data = json.loads(write.request_body or '')
            pointer = binding.get('pointer','')
            if not isinstance(pointer,str) or not pointer.startswith('/'):
                raise ValueError('pointer')
            tokens = [t.replace('~1','/').replace('~0','~') for t in pointer[1:].split('/')]
            container = data
            for token in tokens[:-1]:
                container = container[_array_index(token)] if isinstance(container,list) else container[token]
            key = _array_index(tokens[-1]) if isinstance(container,list) else tokens[-1]
            if not isinstance(container[key],str):
                raise ValueError('existing string')
            body_template = json.dumps(data)
        except (ValueError,TypeError,KeyError,IndexError):
            return blocked('existing JSON string pointer required')
        if urlsplit(write.url).username is not None:
            return blocked('credential-bearing write URL unsupported')
        urls.append(write.url)
        # Pin the actual captured write binding for applicability; credentials omitted.
        binding['write'] = {'method':write.method.upper(),'url_sha256':hashlib.sha256(write.url.encode()).hexdigest(),'url':security.sanitize_text(write.url),
                            'body_sha256':hashlib.sha256((write.request_body or '').encode()).hexdigest()}
        phases = []
        previous = ()
        for phase in (BASELINE, ATTACK, CONTROL):
            plant = 'plant_' + phase
            body = '{{browser_body_' + phase + '}}'
            phases.append((WorkflowStep(plant,write.method.upper(),_browser_url_base(write.url)+'{{browser_write_suffix}}',session_ref,
                body_template=body,prerequisites=previous,content_type='application/json',require_success=True),
                WorkflowStep(phase,'GET',_browser_url_base(route)+'{{browser_consumer_suffix}}',session_ref,prerequisites=(plant,),action='browser_visit',observation_marker='{{browser_marker_'+phase+'}}')))
            previous = (phase,)
    if any(not run_context.scope.in_scope(url) or ScopePolicy.origin_of(url) not in session.allowed_origins for url in urls):
        return blocked('browser binding outside scope or registered identity origins')
    exp = Experiment(eid,kind,hypothesis_id,{'browser':session_ref},{},
        baseline_steps=phases[0],attack_steps=phases[1],control_steps=phases[2],
        principals={'browser':session.principal_id},read_template='GET '+security.sanitize_text(route),
        read_url_template=security.sanitize_text(route),binding=binding,
        assertions='computed nonce execution only in attack; baseline and escaped control silent')
    minimum = 6 if kind == BROWSER_STORED else 3
    if check_cost and run_context.budget.remaining is not None and run_context.budget.remaining < minimum:
        return blocked('insufficient request budget for complete browser protocol')
    if check_cost and kind == BROWSER_STORED and run_context.gate.mutating_headroom(_browser_case(exp,run_context).case_id,'browser_stored_experiment')[0] < 3:
        return blocked('insufficient same-case mutating allowance for three plants')
    return ExperimentPlan('ready',exp,experiment_id=eid,hypothesis_id=hypothesis_id,object_name='browser')


def _evaluate_browser(state, asm, run_context):
    from harness.engagement import add_chain_hypothesis_task
    bindings = ((run_context.config or {}).get('engagement', {}) or {}).get('browser_bindings', [])
    selected = {b.get('hypothesis_id') for b in bindings}
    selected.update(h.id for h in getattr(asm, 'chaining_hypotheses', []) if set(h.classes or []) & {'dom_xss','stored_xss'})
    for hyp in getattr(asm, 'chaining_hypotheses', []):
        if hyp.id not in selected:
            continue
        plan = translate_browser(hyp.id,asm,run_context)
        kind = next((b.get('mechanism') for b in bindings if b.get('hypothesis_id') == hyp.id),'')
        task = state.graph.add('experiment',plan.experiment_id,reason='declared browser execution experiment',
            needs='' if plan.ready else '; '.join(plan.missing),
            meta={'hypothesis_id':hyp.id,'kind':kind},value=float(hyp.rank or 0))
        task.meta['readiness'] = {'status':'ready' if plan.ready else 'needs_prerequisite','reason':'; '.join(plan.missing)}
        if task.status in (task_graph.READY,task_graph.BLOCKED):
            task.needs = '' if plan.ready else '; '.join(plan.missing)
            task.meta['missing'] = list(plan.missing)
            if plan.ready:
                task.meta['experiment'] = plan.experiment.to_dict()
                state.graph.resolve_need(task.id)
            else:
                state.graph.mark(task.id,task_graph.BLOCKED)
        add_chain_hypothesis_task(state.graph,hyp,needs='validated by '+task.id,
                                 depends_on=[task.id],extra_meta={'experiment':task.id})


async def _run_browser_experiment(plan, run_context):
    import html
    from urllib.parse import quote
    from harness import store
    a,b = secrets.randbelow(800)+100, secrets.randbelow(800)+100
    markers = {phase:'av_'+secrets.token_hex(12)+':'+phase+':' for phase in (BASELINE,ATTACK,CONTROL)}
    def payload(phase):
        return '<img src=x onerror="alert(\'' + markers[phase] + "'+(" + str(a) + '*' + str(b) + '))">'
    raw = {BASELINE:'baseline_'+markers[BASELINE], ATTACK:payload(ATTACK), CONTROL:html.escape(payload(CONTROL),quote=True)}
    values = {'browser_'+phase: (quote(value,safe='') if plan.kind == BROWSER_HASH else json.dumps(value)[1:-1])
              for phase,value in raw.items()}
    private = _browser_private_binding(plan,run_context)
    route = private['route' if plan.kind == BROWSER_HASH else 'consumer_url']
    values.update({'browser_marker_'+phase:marker for phase,marker in markers.items()})
    if plan.kind == BROWSER_HASH:
        from urllib.parse import unquote_plus
        prefix, query = route.split('#',1)[1].split('?',1)
        for phase in (BASELINE,ATTACK,CONTROL):
            pairs = query.split('&')
            replaced = [pair.split('=',1)[0]+'='+quote(raw[phase],safe='') if unquote_plus(pair.split('=',1)[0]) == private['parameter'] else pair for pair in pairs]
            values['browser_url_suffix_'+phase] = ('?'+route.split('#',1)[0].split('?',1)[1] if '?' in route.split('#',1)[0] else '')+'#'+prefix+'?'+'&'.join(replaced)
    else:
        values['browser_consumer_suffix'] = route[len(_browser_url_base(route)):]
    case = _browser_case(plan,run_context)
    wf = plan.to_workflow(case.case_id)
    # The three plants share this exact case; policy cannot be reset by a phase label.
    steps=[]
    for step in wf.steps:
        if step.action == 'http':
            phase=step.id.removeprefix('plant_')
            capture = _browser_capture(run_context,plan.binding['write_capture'])
            pin = plan.binding['write']
            if (capture.method.upper() != pin['method'] or hashlib.sha256(capture.url.encode()).hexdigest() != pin['url_sha256'] or
                    hashlib.sha256((capture.request_body or '').encode()).hexdigest() != pin['body_sha256']):
                raise ValueError('declared write capture changed after compilation')
            values['browser_write_suffix'] = capture.url[len(_browser_url_base(capture.url)):]
            data=json.loads(capture.request_body)
            container=data
            tokens=[t.replace('~1','/').replace('~0','~') for t in plan.binding['pointer'][1:].split('/')]
            for token in tokens[:-1]:
                container=container[_array_index(token)] if isinstance(container,list) else container[token]
            key=_array_index(tokens[-1]) if isinstance(container,list) else tokens[-1]
            container[key]=raw[phase]
            name='browser_body_'+phase
            values[name]=json.dumps(data)
            step=replace(step,body_template='{{'+name+'}}')
        steps.append(replace(step,case_ref=case.case_id))
    wf=replace(wf,steps=tuple(steps))
    result = await execute_workflow(wf,run_context,initial_values=values,
        capability='browser_stored_experiment' if plan.kind == BROWSER_STORED else plan.kind)
    observations = {s.step_id:s for s in result.steps if s.step_id in (BASELINE,ATTACK,CONTROL)}
    arts = {phase:observations[phase].artifact_id for phase in observations}
    verdict,reason = Verdict.INCONCLUSIVE,'required browser writes/visits incomplete'
    if result.complete and len(arts) == 3 and len(set(arts.values())) == 3 and all(observations[p].observation.get('marker_present') for p in (BASELINE,ATTACK,CONTROL)):
        dialogs = {phase:observations[phase].observation.get('dialogs',[]) for phase in observations}
        console = {phase:[text for text in observations[phase].observation.get('console',[]) if markers[phase] in text] for phase in observations}
        expected = markers[ATTACK]+str(a*b)
        attack = dialogs[ATTACK] == ['alert:'+expected] or (not dialogs[ATTACK] and console[ATTACK] == [expected])
        silent_controls = not dialogs[BASELINE] and not dialogs[CONTROL] and not console[BASELINE] and not console[CONTROL]
        if silent_controls and attack:
            verdict,reason = Verdict.CONFIRMED,'computed nonce executed only in attack visit'
        elif not any(dialogs.values()) and not any(console.values()):
            verdict,reason = Verdict.CONTROLLED_NEGATIVE,'all three observations completed without input execution'
        else:
            reason = 'unmatched or control browser signal; execution boundary inconclusive'
    from harness.assessment_health import stored_proof_artifacts_resolve
    if verdict in (Verdict.CONFIRMED,Verdict.CONTROLLED_NEGATIVE) and not stored_proof_artifacts_resolve({'case':case.to_dict(),'baseline_artifact_id':arts.get(BASELINE,''),'attack_artifact_id':arts.get(ATTACK,''),'control_artifact_ids':[arts.get(CONTROL,'')]}):
        verdict,reason = Verdict.INCONCLUSIVE,'durable browser evidence unavailable'
    control_verified = (any(s.step_id == 'plant_control' and s.status == StepStatus.PASSED for s in result.steps)
                        and CONTROL in observations and observations[CONTROL].status == StepStatus.PASSED
                        and observations[CONTROL].observation.get('marker_present',False))
    cleanup = ('none declared; final stored state is escaped control' if control_verified else
               'none declared; escaped control state unverified') if plan.kind == BROWSER_STORED else 'none declared'
    proof = ProofRecord('',case,plan.kind,verdict,validator_version='1',
        baseline_artifact_id=arts.get(BASELINE,''),attack_artifact_id=arts.get(ATTACK,''),
        control_artifact_ids=(arts[CONTROL],) if arts.get(CONTROL) else (),
        expected_invariant=plan.assertions,observed_result=reason,limitation='cleanup: '+cleanup,
        executed=any(s.executed for s in result.steps))
    ok,why = store.persist_proof_record(proof)
    outcome = CONFIRMED if verdict == Verdict.CONFIRMED else NEGATIVE if verdict == Verdict.CONTROLLED_NEGATIVE else INCONCLUSIVE
    if not ok:
        outcome,reason = INCONCLUSIVE,'proof persistence failed: '+why
    return ExperimentOutcome(outcome,reason,proof,ok,result,case,{},cleanup)



def preflight_authority(plan, run_context):
    """Check every declared leg before the first write; transport rechecks at send."""
    from harness.run_context import ScopePolicy
    for step in (plan.setup_steps + plan.baseline_steps + plan.attack_steps + plan.control_steps + plan.cleanup_steps):
        session = run_context.sessions.get(step.session_ref)
        if session is None or session.health == 'expired':
            return 'required registered identity missing or expired'
        if ScopePolicy.origin_of(step.url_template) not in session.allowed_origins:
            return 'required identity is not authorized for step origin'
        if not run_context.scope.in_scope(step.url_template):
            return 'declared step outside owning run scope'
    return ''


def _blocked_on(task, status, reason):
    """AR-FP: the typed reason a task did not complete. `operator_input` names each
    declaration, binding, session or permission only the operator can supply;
    `awaiting_value` a value no phase observed; `budget` the bound that left it
    unrun; `failed_unchanged` an inconclusive attempt not re-run without new evidence."""
    if status == 'completed':
        return None
    if reason == 'engagement experiments disabled':
        return {'category': 'disabled', 'inputs': [reason]}
    if status == 'deferred':
        return {'category': 'budget', 'inputs': [reason]}
    if task.status == task_graph.FAILED:
        final = task.meta.get('final_pass') or {}
        if final.get('status') == 'failed_unchanged':
            return {'category': 'failed_unchanged', 'inputs': [final['reason']]}
        return {'category': 'inconclusive', 'inputs': [reason]}
    if task.status == task_graph.BLOCKED:
        inputs = [m for m in (task.meta.get('missing') or [task.needs]) if m]
        operator = [m for m in inputs if not m.startswith("value '")]
        return {'category': 'operator_input' if operator else 'awaiting_value', 'inputs': inputs}
    return {'category': status, 'inputs': [reason]}


def task_dispositions(state, run_context, *, enabled, max_runs, planner_enabled=False):
    """Bounded final case state; a pending proposal never becomes a clean negative."""
    tasks=[]
    for task in experiment_tasks(state):
        final = task.meta.get('final_pass') or {}
        if not enabled:
            status,reason='disabled','engagement experiments disabled'
        elif task.status == task_graph.DONE:
            status,reason='completed','stored attempt completed'
        elif task.status == task_graph.FAILED:
            status,reason='inconclusive',task.meta.get('reason','attempt failed')
        elif task.status == task_graph.BLOCKED:
            reason=task.needs
            status=('deferred' if 'budget' in reason or 'allowance' in reason else
                    'policy_denied' if 'permission' in reason or 'scope' in reason else
                    'disabled' if 'disabled' in reason else 'missing_prerequisite')
        elif final.get('status') == 'deferred':
            status,reason='deferred',final['reason']
        elif run_context is not None and run_context.cancel.cancelled:
            status,reason='deferred','owning run cancelled'
        elif run_context is not None and run_context.experiment_runs >= max_runs:
            status,reason='deferred','engagement experiment max_runs exhausted'
        elif run_context is not None and run_context.budget.remaining == 0:
            status,reason='deferred','owning request budget exhausted'
        else:
            status,reason='advisory','ready experiment not selected before stage termination'
        tasks.append({'task_id':task.id,'hypothesis_id':task.meta.get('hypothesis_id'),
            'status':status,'reason':reason,'blocked_on':_blocked_on(task, status, reason),
            'attempt_ids':list(task.meta.get('attempt_ids',[])),
            'readiness':dict(task.meta.get('readiness',{})),
            'cost':dict((task.meta.get('experiment') or {}).get('cost',{}))})
    advisory = [{'task_id':t.id,'kind':t.kind,'status':'advisory',
                 'reason':'no registered experiment compiler attached to this proposal'}
                for t in state.graph.tasks.values() if t.kind == 'chain-hypothesis' and not t.meta.get('experiment')]
    return {'schema_version':2,'enabled':enabled,'planner_enabled':planner_enabled,
            'supported_mechanisms':list(SUPPORTED_KINDS),'advisory_tasks':advisory,'max_runs':max_runs,
            'attempts_reserved':getattr(run_context,'experiment_runs',0),
            'request_budget_remaining':run_context.budget.remaining if run_context else None,
            'tasks':tasks}


def _array_index(token):
    if not token.isdecimal() or str(int(token)) != token:
        raise ValueError("canonical nonnegative JSON array index required")
    return int(token)


def _browser_case(plan,run_context):
    check = 'INPV-browser-hash' if plan.kind == BROWSER_HASH else 'INPV-browser-stored'
    return TestCaseRef.make(run_id=run_context.run_id,request_template_id=plan.read_template,
        check_id=check,principal_id=plan.principals['browser'],workflow_state_id=plan.id,
        finding_ref=plan.hypothesis_id,parameter_location='fragment_query' if plan.kind == BROWSER_HASH else 'body_json',
        parameter_name=plan.binding.get('parameter',plan.binding.get('pointer','')))



def _browser_url_base(url):
    from urllib.parse import urlsplit,urlunsplit
    parsed=urlsplit(url)
    return urlunsplit((parsed.scheme,parsed.netloc,parsed.path,'',''))


def _browser_capture(run_context,index):
    from harness.models import HttpExchange
    raw=(run_context.experiment_context or {}).get('captured',())[index]
    return raw if isinstance(raw,HttpExchange) else HttpExchange.model_validate(raw)


def _browser_private_binding(plan,run_context):
    bindings=((run_context.config or {}).get('engagement',{}) or {}).get('browser_bindings',[])
    matches=[b for b in bindings if b.get('hypothesis_id') == plan.hypothesis_id and b.get('mechanism') == plan.kind]
    if len(matches) != 1:
        raise ValueError('declared browser binding unavailable')
    binding=matches[0]
    route=binding.get('route' if plan.kind == BROWSER_HASH else 'consumer_url','')
    if hashlib.sha256(route.encode()).hexdigest() != plan.binding['route_sha256']:
        raise ValueError('declared browser route changed after compilation')
    return binding
