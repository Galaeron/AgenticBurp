"""
Penetration task graph -- the closed loop as an explicit dependency DAG.

Until now the engagement's escalation work lived in a FLAT queue: a list of
"things to do" with no notion that one depends on another. But a real
engagement is a dependency graph -- "test the admin API" is *blocked* until you
"obtain an admin session," which is *blocked* until you "confirm the auth
bypass." The AppSecSanta 2026 survey names this directly (VulnBot's
"penetration task graph: nodes are tasks, edges are dependencies"); it is the
structural upgrade that turns our implicit finding->identity->new-surface cycle
into an inspectable object the driver can walk correctly.

A Task is READY only when every task it depends_on is done. The driver surfaces
ready tasks; blocked tasks are shown with the prerequisite they are waiting on
(often "needs human/credentials"), so nothing is silently stuck and the operator
sees exactly what would unlock the next move. Marking a task done automatically
re-evaluates the graph, promoting any dependents whose prerequisites are now all
satisfied.

Pure data + graph logic -- deterministic, serializable, no LLM. It replaces the
old pending_actions queue as the engagement state's work model.
"""
from __future__ import annotations
from dataclasses import dataclass, field

# P1.4 -- MITRE ATT&CK mapping. A deliberately small, hand-picked subset: only
# vulnerability classes this harness actually detects/confirms get an entry, and
# only the single most-applicable technique per class (ATT&CK sub-techniques and
# multi-technique nuance are out of scope for a task-graph label). Keyed on the
# same `vulnerability_class` strings Finding/validators already use, lowercased,
# so callers never need a second vocabulary. Extend freely; an unmapped class is
# not an error -- the task simply carries no attack_technique (never fabricated).
ATTACK_TECHNIQUE_MAP: dict = {
    "sqli": ("T1190", "Exploit Public-Facing Application"),
    "xss": ("T1189", "Drive-by Compromise"),
    "stored_xss": ("T1189", "Drive-by Compromise"),
    "dom_xss": ("T1189", "Drive-by Compromise"),
    "idor": ("T1078", "Valid Accounts"),
    "bola": ("T1078", "Valid Accounts"),
    "authz": ("T1078", "Valid Accounts"),
    "missing_authentication": ("T1190", "Exploit Public-Facing Application"),
    "ssrf": ("T1190", "Exploit Public-Facing Application"),
    "xxe": ("T1190", "Exploit Public-Facing Application"),
    "command_injection": ("T1059", "Command and Scripting Interpreter"),
    "path_traversal": ("T1083", "File and Directory Discovery"),
    "deserialization": ("T1190", "Exploit Public-Facing Application"),
    "jwt_forge": ("T1552", "Unsecured Credentials"),
    "secret_disclosure": ("T1552", "Unsecured Credentials"),
    "reset_token": ("T1110", "Brute Force"),
    "rate_limit": ("T1110", "Brute Force"),
    "csrf": ("T1204", "User Execution"),
    "open_redirect": ("T1204", "User Execution"),
    "ssti": ("T1190", "Exploit Public-Facing Application"),
    "sequence": ("T1078", "Valid Accounts"),          # mass assignment
    "privilege_escalation": ("T1068", "Exploitation for Privilege Escalation"),
    "toctou": ("T1068", "Exploitation for Privilege Escalation"),
    "recon": ("T1595", "Active Scanning"),
}


def attack_technique_for(vulnerability_class: str) -> tuple | None:
    """(technique_id, technique_name) for a vulnerability class, or None when
    this harness has no mapped ATT&CK technique for it. Never guesses."""
    return ATTACK_TECHNIQUE_MAP.get((vulnerability_class or "").strip().lower())


# Severity sets a task's base band for value-ordered search (below); confidence
# then scales it 0.25x-1.0x within that band. This is a weighted priority score,
# not a strict severity-first sort: a low-confidence "critical" can still rank
# below a high-confidence "high" -- confidence is real signal, not a tie-break.
_SEVERITY_WEIGHT = {"critical": 4.0, "high": 3.0, "medium": 2.0, "low": 1.0, "info": 0.5}


def _default_value(meta: dict) -> float:
    """A task's default search value: severity band scaled by confidence within
    that band (0.25-1.0x of the band weight). Unscored input (no
    severity/confidence in meta) is a known-neutral 1.0, same as an explicit
    "low" -- unremarkable, not zero."""
    sev = str(meta.get("severity") or "").strip().lower()
    weight = _SEVERITY_WEIGHT.get(sev, 1.0)
    conf = meta.get("confidence")
    if isinstance(conf, (int, float)):
        scale = 0.25 + 0.75 * max(0.0, min(1.0, float(conf)))
        return weight * scale
    return weight


# Task lifecycle. Following VulnBot's PTG, a finished task carries a SUCCESS axis:
# a task that finished but FAILED is preserved (not silently dropped) and, crucially,
# does NOT satisfy dependents -- a prerequisite must actually SUCCEED to unblock what
# depends on it ("test admin" stays blocked if "obtain admin session" failed). Failed
# tasks are surfaced for reanalysis rather than retried blindly.
READY = "ready"       # all prerequisites succeeded -> actionable now
BLOCKED = "blocked"   # waiting on a prerequisite (see depends_on / needs)
DONE = "done"         # finished, succeeded
FAILED = "failed"     # finished, did not succeed -> flagged for reanalysis
SKIPPED = "skipped"   # deliberately not doing it

# Only these satisfy a dependency (let a dependent become ready).
_SATISFYING = (DONE, SKIPPED)


@dataclass
class Task:
    id: str
    kind: str            # analyze | confirm | recrawl_area | recrawl_as_derived | obtain | manual
    target: str          # endpoint key / area / identity
    reason: str = ""
    status: str = READY
    depends_on: list = field(default_factory=list)  # task ids that must be DONE first
    needs: str = ""      # human-readable prerequisite when blocked (e.g. "admin credentials")
    # A dependency that is SKIPPED satisfies its dependents ONLY when the SKIPPED
    # task was OPTIONAL (weakness #14). Skipping a REQUIRED capability (obtain a
    # credential, confirm an authz bypass) must NOT silently unlock what needs it.
    optional: bool = False
    source: str = ""     # the finding/url that spawned it
    meta: dict = field(default_factory=dict)
    # P1.4 -- MITRE-shaped attack tree. attack_technique/_name are populated from
    # ATTACK_TECHNIQUE_MAP (auto, via meta["vulnerability_class"]) unless the
    # caller supplies an explicit override; both stay "" when unmapped, never
    # fabricated. evidence_ref is the pointer to what justifies this node --
    # defaults to `source` (already "the finding/url that spawned it") when not
    # given explicitly, so every node references *something*, even if only its
    # own origin. value is this node's priority score for ready_by_value().
    attack_technique: str = ""
    attack_technique_name: str = ""
    evidence_ref: str = ""
    value: float = 0.0

    def to_dict(self) -> dict:
        return {"id": self.id, "kind": self.kind, "target": self.target, "reason": self.reason,
                "status": self.status, "depends_on": self.depends_on, "needs": self.needs,
                "optional": self.optional, "source": self.source, "meta": self.meta,
                "attack_technique": self.attack_technique,
                "attack_technique_name": self.attack_technique_name,
                "evidence_ref": self.evidence_ref, "value": self.value}

    @classmethod
    def from_dict(cls, d: dict) -> "Task":
        return cls(id=d["id"], kind=d.get("kind", ""), target=d.get("target", ""),
                   reason=d.get("reason", ""), status=d.get("status", READY),
                   depends_on=list(d.get("depends_on", [])), needs=d.get("needs", ""),
                   optional=bool(d.get("optional", False)),
                   source=d.get("source", ""), meta=d.get("meta", {}) or {},
                   attack_technique=d.get("attack_technique", ""),
                   attack_technique_name=d.get("attack_technique_name", ""),
                   evidence_ref=d.get("evidence_ref", ""),
                   value=float(d.get("value", 0.0) or 0.0))


def make_id(kind: str, target: str) -> str:
    return f"{kind}:{target}"


@dataclass
class TaskGraph:
    tasks: dict = field(default_factory=dict)   # id -> Task

    def add(self, kind: str, target: str, *, reason: str = "", depends_on: list | None = None,
            needs: str = "", optional: bool = False, source: str = "", meta: dict | None = None,
            attack_technique: str = "", evidence_ref: str = "", value: float | None = None) -> Task:
        """Add a task (idempotent by id = kind:target). If it already exists it is
        returned unchanged unless it was DONE/SKIPPED, in which case a re-add is
        ignored -- a finished task is not silently resurrected. New tasks start
        BLOCKED when they have unmet dependencies, READY otherwise. `optional`
        marks a task whose SKIP still satisfies dependents (weakness #14).

        P1.4: `attack_technique`, when not given explicitly, is looked up from
        `meta["vulnerability_class"]` via ATTACK_TECHNIQUE_MAP -- stays "" when
        the class is unmapped, never guessed. `evidence_ref` defaults to
        `source` when not given explicitly (every node references *something*).
        `value`, when not given, is derived from `meta["severity"]`/
        `meta["confidence"]` (see _default_value) and drives ready_by_value()."""
        tid = make_id(kind, target)
        existing = self.tasks.get(tid)
        if existing is not None:
            return existing
        deps = list(depends_on or [])
        status = BLOCKED if any(self._pending(d) for d in deps) or needs else READY
        meta = meta or {}
        technique, technique_name = "", ""
        if attack_technique:
            technique = attack_technique
        else:
            mapped = attack_technique_for(meta.get("vulnerability_class", ""))
            if mapped:
                technique, technique_name = mapped
        t = Task(id=tid, kind=kind, target=target, reason=reason, status=status,
                 depends_on=deps, needs=needs, optional=optional, source=source, meta=meta,
                 attack_technique=technique, attack_technique_name=technique_name,
                 evidence_ref=evidence_ref or source,
                 value=value if value is not None else _default_value(meta))
        self.tasks[tid] = t
        return t

    def _satisfied(self, d: "Task | None") -> bool:
        """A dependency satisfies its dependents only when it actually SUCCEEDED
        (DONE), or was SKIPPED *and* declared OPTIONAL. A missing/FAILED/pending
        dependency, or a SKIPPED REQUIRED one, does not -- you can't test what you
        never managed to unlock, and skipping a required capability is not success
        (weakness #14)."""
        if d is None:
            return False
        if d.status == DONE:
            return True
        if d.status == SKIPPED:
            return bool(getattr(d, "optional", False))
        return False

    def _pending(self, dep_id: str) -> bool:
        return not self._satisfied(self.tasks.get(dep_id))

    def mark(self, task_id: str, status: str) -> None:
        t = self.tasks.get(task_id)
        if t is None:
            return
        t.status = status
        self._unlock()  # a success may promote dependents; a failure never does

    def failed(self) -> list:
        return [t for t in self.tasks.values() if t.status == FAILED]

    def mark_by(self, kind: str, target: str, status: str = DONE) -> None:
        self.mark(make_id(kind, target), status)

    def _unlock(self) -> None:
        """Promote BLOCKED tasks whose dependencies are now all satisfied. A task
        with a `needs` note stays blocked until it is explicitly resolved (its
        prerequisite is a human/credential input, not another task)."""
        for t in self.tasks.values():
            if t.status == BLOCKED and not t.needs and not any(self._pending(d) for d in t.depends_on):
                t.status = READY

    def resolve_need(self, task_id: str) -> None:
        """Clear a task's human/credential prerequisite, then re-evaluate."""
        t = self.tasks.get(task_id)
        if t is not None:
            t.needs = ""
            if not any(self._pending(d) for d in t.depends_on):
                t.status = READY

    def ready(self) -> list:
        return [t for t in self.tasks.values() if t.status == READY]

    def ready_by_value(self) -> list:
        """P1.4 -- value-ordered search over the graph: the same READY set as
        `ready()`, sorted highest-`value`-first (a greedy/best-first walk of the
        attack tree -- pursue the node the dependency graph currently allows
        that looks most worth investigating, rather than FIFO insertion order).
        Ties break on task id for a deterministic, reproducible ordering (two
        equal-value tasks must not silently reorder between runs on the exact
        same graph state)."""
        return sorted(self.ready(), key=lambda t: (-t.value, t.id))

    def blocked(self) -> list:
        return [t for t in self.tasks.values() if t.status == BLOCKED]

    def to_dict(self) -> dict:
        return {"tasks": {tid: t.to_dict() for tid, t in self.tasks.items()}}

    @classmethod
    def from_dict(cls, d: dict) -> "TaskGraph":
        g = cls()
        for tid, td in (d.get("tasks", {}) or {}).items():
            g.tasks[tid] = Task.from_dict(td)
        return g
