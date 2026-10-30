"""
experiment_planner.py -- bounded planning proposals for BLOCKED experiments (Ticket G).

A cross-account experiment (experiment.py) can be blocked on an input that a real
capture already contains: the JSON pointer to the id in a create response, or a
value such as a parent object's id. A model may PROPOSE how to read it; this module
decides whether the proposal is acceptable. The model is never trusted:

  - the input is the blocked experiment's subgraph only -- the task, its missing
    list, and summaries of the related captures (method, path, status, top-level
    JSON keys with each value cut to 40 characters, secret-named keys withheld);
  - a proposal is a small structured action, validated against the REAL captures
    before anything acts on it: the capture index must exist, a pointer must resolve
    to a scalar in that capture's response JSON, the kind must be supported and the
    hypothesis must exist; an invalid proposal is rejected with a reason and still
    counts toward the bound;
  - at most `max_proposals` proposals are considered per call;
  - a planner can resolve a missing extraction pointer or a missing value, and only
    when validation succeeds against a real capture. It can NEVER supply an access
    or ownership expectation: those stay an operator declaration
    (engagement.access_expectations), and any proposal that tries is rejected.

The model call is injectable (`propose_fn`), so tests use a deterministic fake;
`ollama_propose_fn` is the production default over the run's Ollama client.
"""
from __future__ import annotations

import inspect
import json
import re
from dataclasses import dataclass, field

from harness.experiment import SUPPORTED_KINDS

DEFAULT_MAX_PROPOSALS = 6
VALUE_CHARS = 40
MAX_SUMMARIES = 10
ACTIONS = ("inspect_capture", "identify_field", "instantiate_workflow", "stop")

_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# A proposal that names any of these is an attempt to declare who may access what.
_EXPECTATION_WORDS = re.compile(
    r"owner|ownership|expect|access|declare|private|public|shared|permission|authoriz", re.I)
_SECRET_KEY = re.compile(r"pass|token|secret|auth|key|session|cookie|jwt|credential", re.I)

SYSTEM_PROMPT = (
    "You help unblock an authorization test that is missing an input. Reply with a JSON "
    'object {"proposals": [...]} holding at most a few proposals, each one of: '
    '{"action":"inspect_capture","capture":<index>}, '
    '{"action":"identify_field","capture":<index>,"pointer":"/json/pointer","as":"<value name>"}, '
    '{"action":"instantiate_workflow","kind":"cross_account_private_object","hypothesis":"<id>"}, '
    '{"action":"stop"}. Use only capture indexes and field names that appear in the input. '
    "You cannot declare who owns an object or who may read it; do not try. Do not guess."
)


def _capture_fields(capture) -> tuple:
    """(method, url, status, response body) of an HttpExchange or its dict form."""
    get = (capture.get if isinstance(capture, dict) else lambda k, d=None: getattr(capture, k, d))
    return (str(get("method", "") or "").upper(), str(get("url", "") or ""),
            get("response_status", None), str(get("response_body", "") or ""))


def summarize_capture(capture, index: int) -> dict:
    """One capture reduced to what a planner may see: no headers, no request body,
    and each top-level JSON value cut to VALUE_CHARS; values under a secret-looking
    key are withheld outright."""
    from urllib.parse import urlsplit
    method, url, status, body = _capture_fields(capture)
    keys: dict = {}
    try:
        data = json.loads(body)
    except ValueError:
        data = None
    if isinstance(data, dict):
        for key, value in list(data.items())[:20]:
            if _SECRET_KEY.search(str(key)):
                keys[str(key)] = "[withheld]"
            elif isinstance(value, (dict, list)):
                keys[str(key)] = ("{...}" if isinstance(value, dict) else "[...]")
            else:
                keys[str(key)] = str(value)[:VALUE_CHARS]
    return {"capture": index, "method": method, "path": urlsplit(url).path or "/",
            "status": status, "keys": keys}


def _scalar_at(body: str, pointer: str) -> str | None:
    """The scalar at a JSON pointer in `body`, as the workflow engine would extract
    it; None when the pointer does not resolve, or resolves to null, an empty
    string, an object or an array."""
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        return None
    try:
        cur = json.loads(body or "")
        for token in pointer[1:].split("/"):
            token = token.replace("~1", "/").replace("~0", "~")
            cur = cur[int(token)] if isinstance(cur, list) else cur[token]
    except (ValueError, TypeError, KeyError, IndexError):
        return None
    if isinstance(cur, (dict, list)) or cur is None or cur == "":
        return None
    return str(cur)


@dataclass
class PlannerOutcome:
    accepted: list = field(default_factory=list)     # [{"proposal", "effect"}]
    rejected: list = field(default_factory=list)     # [{"proposal", "reason"}]
    pointers: dict = field(default_factory=dict)     # declared create key -> id pointer
    values: dict = field(default_factory=dict)       # value name -> scalar from a real capture
    instantiate: list = field(default_factory=list)  # hypothesis ids to re-translate
    dropped: int = 0                                 # proposals beyond the bound, never considered
    stopped: bool = False


def validate_instantiation(kind, hypothesis, hypothesis_ids) -> str:
    """Shared bounded mechanism selection guard; never authorizes a request."""
    if not isinstance(kind, str) or kind not in SUPPORTED_KINDS:
        return f"unsupported workflow kind {kind!r}"
    if not isinstance(hypothesis, str) or hypothesis not in hypothesis_ids:
        return f"hypothesis {hypothesis!r} does not exist"
    return ""


class ExperimentPlanner:
    def __init__(self, propose_fn, *, captures=(), max_proposals: int = DEFAULT_MAX_PROPOSALS):
        self.propose_fn = propose_fn
        self.captures = list(captures or [])
        self.max_proposals = max(0, int(max_proposals))

    def subgraph_for(self, task) -> dict:
        """The blocked experiment's subgraph: the task, what it is missing, and the
        related captures (index = position in this planner's capture list)."""
        from harness.engagement import normalize_path
        unblock = task.meta.get("unblock") or {}
        keys = {k.strip() for k in (task.source or "").split(",") if k.strip()}
        keys |= {e.get("endpoint", "") for e in unblock.get("extractions", [])}
        obj = (unblock.get("object") or task.meta.get("object") or "").lower()
        related = []
        for index, capture in enumerate(self.captures):
            method, url, _status, _body = _capture_fields(capture)
            if (f"{method} {normalize_path(url)}" in keys
                    or (obj and obj in normalize_path(url).lower())):
                related.append(summarize_capture(capture, index))
            if len(related) >= MAX_SUMMARIES:
                break
        return {"task": {"id": task.id, "hypothesis_id": task.meta.get("hypothesis_id", ""),
                         "object": obj, "needs": task.needs},
                "missing": list(task.meta.get("missing") or []),
                "needs_extraction": [{"endpoint": e["endpoint"], "as": e["as"]}
                                     for e in unblock.get("extractions", [])],
                "needs_values": list(unblock.get("values", [])),
                "captures": related, "allowed_actions": list(ACTIONS)}

    def _capture_index(self, proposal: dict):
        index = proposal.get("capture")
        if isinstance(index, bool) or not isinstance(index, int) \
                or not 0 <= index < len(self.captures):
            return None, f"capture index {index!r} does not exist"
        return index, ""

    def _validate(self, proposal, task, hypothesis_ids: set, outcome: PlannerOutcome) -> str:
        """"" when the proposal was accepted (its effect recorded on `outcome`),
        otherwise the reason it was rejected."""
        from harness.engagement import normalize_path
        if not isinstance(proposal, dict):
            return "proposal is not an object"
        action = proposal.get("action")
        if not isinstance(action, str):
            return "proposal has no action"
        if _EXPECTATION_WORDS.search(action) or any(
                _EXPECTATION_WORDS.search(str(k)) for k in proposal if k != "action"):
            return ("a planner may not supply an access or ownership expectation: that is "
                    "declared by the operator (engagement.access_expectations)")
        if action not in ACTIONS:
            return f"unknown action '{action}'"
        if action == "stop":
            outcome.stopped = True
            return ""
        if action == "instantiate_workflow":
            problem = validate_instantiation(proposal.get("kind"), proposal.get("hypothesis"), hypothesis_ids)
            if problem:
                return problem
            outcome.instantiate.append(proposal["hypothesis"])
            return ""
        index, reason = self._capture_index(proposal)
        if index is None:
            return reason
        if action == "inspect_capture":
            return ""
        # identify_field
        name, pointer = proposal.get("as"), proposal.get("pointer")
        if not isinstance(name, str) or not _NAME.match(name):
            return f"'as' {name!r} is not a value name"
        method, url, _status, body = _capture_fields(self.captures[index])
        scalar = _scalar_at(body, pointer)
        if scalar is None:
            return f"pointer {pointer!r} does not resolve to a scalar in capture {index}"
        unblock = task.meta.get("unblock") or {}
        for ext in unblock.get("extractions", []):
            if ext["as"] == name and method == ext["method"] \
                    and normalize_path(url) == normalize_path(ext["path"]):
                outcome.pointers[ext["endpoint"]] = pointer
                return ""
        if name in (unblock.get("values") or []):
            outcome.values[name] = scalar
            return ""
        return (f"'{name}' does not resolve a missing input of {task.id} "
                f"(capture {index} is {method} {normalize_path(url)})")

    async def plan(self, task, *, hypotheses=()) -> PlannerOutcome:
        """One bounded call for one blocked task. Considers at most max_proposals
        proposals; every accepted one is validated against the real captures."""
        proposals = self.propose_fn(self.subgraph_for(task))
        if inspect.isawaitable(proposals):
            proposals = await proposals
        proposals = list(proposals) if isinstance(proposals, (list, tuple)) else []
        outcome = PlannerOutcome(dropped=max(0, len(proposals) - self.max_proposals))
        hypothesis_ids = {getattr(h, "id", "") for h in hypotheses or ()}
        for proposal in proposals[:self.max_proposals]:
            reason = self._validate(proposal, task, hypothesis_ids, outcome)
            if reason:
                outcome.rejected.append({"proposal": proposal, "reason": reason})
            else:
                outcome.accepted.append({"proposal": proposal})
            if outcome.stopped:
                break
        return outcome


def ollama_propose_fn(ollama, model: str, *, temperature: float = 0.0):
    """The production `propose_fn`: the run's Ollama client asked for JSON. A model
    failure propagates to the caller, which counts it and moves on."""
    async def propose(subgraph: dict) -> list:
        from harness.ollama_client import model_stage
        with model_stage("planner"):
            data = await ollama.chat_json(model, SYSTEM_PROMPT,
                                          json.dumps(subgraph, default=str)[:12000],
                                          temperature=temperature)
        proposals = data.get("proposals") if isinstance(data, dict) else None
        return proposals if isinstance(proposals, list) else []
    return propose
