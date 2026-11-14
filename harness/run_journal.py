"""run_journal.py -- a durable record of the units of work a run has finished (E7).

A crashed or killed investigation had to start over: its discovery crawl, every
worklist session and every capture review (model calls) ran again. With
`runs.journal` on, the run writes each finished unit here as it goes:

    discovery            the engagement state and the parts of the crawl result later phases read
    worklist:<node key>  one worklist node's outcome
    review:<capture key> the findings one capture review produced
    coverage:checkpoint  the coverage matrix checkpoint (also every N legs inside the drive)
    phase:<name>         {"finished_at"} when a phase completed

A resumed run (same root job id, same context key) reads them back and skips what is
done. A row is only used when its checksum holds and its context key matches this
journal's: a damaged or foreign row is a miss, never an error. The journal is its own
SQLite file beside the job store, so the findings schema is untouched.

Credentials are never written. Request headers go through security.redact_headers (the
redaction stored captures use), the headers a role supplied are replaced by a pointer to
the role (`$role:<principal id>`) that the resumed run fills from its own roles, and any
role credential value left anywhere in a payload is withheld.

Unit keys hold no credential value either (worklist_investigator.node_key,
RunJournal.exchange_key): a resumed run whose roles logged in again, with new token
values, still finds the units an earlier attempt finished. The discovery unit records
each principal's identity key (a digest), so restore_discovery moves the principal's
stored captures to the identity key of its current credentials.
"""
from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace

from harness import security

log = logging.getLogger("harness.run_journal")

# Rows older than this are dropped when a journal is opened.
RETENTION_SECONDS = 14 * 24 * 3600.0
_ROLE_POINTER = "$role:"
_MIN_SECRET_LENGTH = 4


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


class RunJournal:
    """The units of one root job in a journal file (see the module docstring).

    `roles` (role_crawl.RoleSession) are the identities of the run: their credential
    header values are withheld from every payload."""

    def __init__(self, path, root_job_id: str, context_key: str, *, roles=()):
        self.path = Path(path)
        self.root_job_id = str(root_job_id)
        self.context_key = str(context_key)
        self._roles = tuple(roles or ())
        secrets = {str(value) for role in roles or ()
                   for name, value in (getattr(role, "headers", None) or {}).items()
                   if security.is_credential_header(name) and len(str(value)) >= _MIN_SECRET_LENGTH}
        # Escaped forms too: a value with a quote or backslash is written escaped in JSON.
        self._secrets = sorted(secrets | {json.dumps(v)[1:-1] for v in secrets}, key=len, reverse=True)
        self._stats = {"hits": 0, "misses": 0, "writes": 0, "corrupt": 0}

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path, timeout=10)
        try:
            conn.execute("CREATE TABLE IF NOT EXISTS run_units (root_job_id TEXT, unit TEXT, "
                         "context_key TEXT, payload TEXT NOT NULL, sha256 TEXT NOT NULL, "
                         "created_at REAL, PRIMARY KEY(root_job_id, unit))")
            conn.commit()
            return conn
        except Exception:
            conn.close()
            raise

    def prune(self, now: float | None = None) -> int:
        """Drop rows older than RETENTION_SECONDS (every root's); returns how many."""
        cutoff = (time.time() if now is None else now) - RETENTION_SECONDS
        with closing(self._connect()) as conn, conn:
            return conn.execute("DELETE FROM run_units WHERE created_at < ?", (cutoff,)).rowcount

    def _withhold_credentials(self, text: str) -> str:
        for secret in self._secrets:
            text = text.replace(secret, security.SECRET_VALUE_PLACEHOLDER)
        return text

    def exchange_key(self, exchange) -> str:
        """The journal key of one capture's review: the exchange as
        assessment_health.observation_key sees it, with each role-supplied credential
        header as a pointer to its role (pack_exchange) and any role credential left
        in it withheld. A resumed run whose roles logged in again (new token values)
        finds the review an earlier attempt finished; observation_key alone hashes the
        token values and never matches."""
        data = pack_exchange(exchange, self._roles)
        record = [data.get("method"), data.get("url"),
                  {k.lower(): v for k, v in (data.get("request_headers") or {}).items()},
                  data.get("request_body"), data.get("response_status"),
                  {k.lower(): v for k, v in (data.get("response_headers") or {}).items()},
                  data.get("response_body")]
        return _digest(self._withhold_credentials(json.dumps(record, sort_keys=True, default=str)))

    def put(self, unit: str, payload: dict) -> None:
        """Write (or replace) one unit in a single short transaction."""
        text = self._withhold_credentials(json.dumps(payload, sort_keys=True, default=str))
        with closing(self._connect()) as conn, conn:
            conn.execute("INSERT OR REPLACE INTO run_units VALUES (?,?,?,?,?,?)",
                         (self.root_job_id, unit, self.context_key, text, _digest(text), time.time()))
        self._stats["writes"] += 1

    def _read(self, row) -> dict | None:
        """The payload of a stored row when it is this journal's and intact, else None."""
        context_key, payload, digest = row
        if context_key != self.context_key:
            return None
        if _digest(payload) != digest:
            self._stats["corrupt"] += 1
            return None
        try:
            value = json.loads(payload)
        except ValueError:
            self._stats["corrupt"] += 1
            return None
        if not isinstance(value, dict):
            self._stats["corrupt"] += 1
            return None
        return value

    def get(self, unit: str) -> dict | None:
        with closing(self._connect()) as conn:
            row = conn.execute("SELECT context_key, payload, sha256 FROM run_units "
                               "WHERE root_job_id=? AND unit=?", (self.root_job_id, unit)).fetchone()
        value = self._read(row) if row else None
        self._stats["hits" if value is not None else "misses"] += 1
        return value

    def units(self, prefix: str) -> dict[str, dict]:
        """Every intact unit of this journal whose name starts with `prefix`, by name."""
        with closing(self._connect()) as conn:
            rows = conn.execute("SELECT unit, context_key, payload, sha256 FROM run_units "
                                "WHERE root_job_id=? AND substr(unit, 1, ?) = ?",
                                (self.root_job_id, len(prefix), prefix)).fetchall()
        found = {}
        for unit, *row in rows:
            value = self._read(row)
            if value is not None:
                found[unit] = value
                self._stats["hits"] += 1
            else:
                self._stats["misses"] += 1
        return found

    def has_any(self, *, any_context: bool = False) -> bool:
        """Whether the root job has a unit: one with this journal's context key, or
        (any_context) under any key, which tells a changed configuration from no journal."""
        query, args = "SELECT 1 FROM run_units WHERE root_job_id=?", [self.root_job_id]
        if not any_context:
            query, args = query + " AND context_key=?", args + [self.context_key]
        with closing(self._connect()) as conn:
            return conn.execute(query + " LIMIT 1", args).fetchone() is not None

    def stats(self) -> dict:
        return dict(self._stats)


# --------------------------------------------------------------------------- #
# What the investigation journals, and how it comes back
# --------------------------------------------------------------------------- #

def pack_exchange(exchange, roles) -> dict:
    """A captured exchange as a dict that carries no credential: a request header a role
    supplied becomes a pointer to that role, any other secret-named request header is
    redacted (security.redact_headers)."""
    data = json.loads(json.dumps(exchange if isinstance(exchange, dict) else exchange.model_dump(),
                                 default=str))
    owned = {(name.lower(), str(value)): role.principal_id()
             for role in roles or () for name, value in (getattr(role, "headers", None) or {}).items()
             if security.is_credential_header(name)}
    headers = data.get("request_headers") or {}
    pointers = {name: f"{_ROLE_POINTER}{owned[(name.lower(), str(value))]}"
                for name, value in headers.items() if (name.lower(), str(value)) in owned}
    redacted = security.redact_headers({n: v for n, v in headers.items() if n not in pointers})
    data["request_headers"] = {n: pointers.get(n, redacted.get(n)) for n in headers}
    return data


def unpack_exchange(data: dict, roles) -> dict:
    """pack_exchange's inverse: role pointers become the role's own header value again.
    A pointer to a role this run does not have is dropped (the header is not sent)."""
    by_principal = {role.principal_id(): role for role in roles or ()}
    out = dict(data)
    headers = {}
    for name, value in (data.get("request_headers") or {}).items():
        if isinstance(value, str) and value.startswith(_ROLE_POINTER):
            role = by_principal.get(value[len(_ROLE_POINTER):])
            supplied = {k.lower(): v for k, v in (getattr(role, "headers", None) or {}).items()}
            if name.lower() in supplied:
                headers[name] = supplied[name.lower()]
        else:
            headers[name] = value
    out["request_headers"] = headers
    return out


def identity_keys(roles) -> dict:
    """{principal id: engagement.capture_identity_key of its headers}. A digest, never
    the credential; restore_discovery uses it to move a principal's captures to the
    identity key of its current credentials."""
    from harness.engagement import capture_identity_key
    return {role.principal_id(): capture_identity_key(getattr(role, "headers", None) or {})
            for role in roles or ()}


def rekey_captures(state, stored_identities: dict, roles) -> int:
    """Move each capture variant recorded under a principal's earlier credentials to
    the identity key of that principal's current ones (it logged in again between the
    attempts). Without this the restored captures match no role: the worklist skips
    them as missing_principal and the coverage drive has no replay template for the
    principal. An identity key two principals shared, or a principal this run does
    not have, is left as it is. Returns how many variants moved."""
    from harness.engagement import rekey_variant
    current = identity_keys(roles)
    targets: dict = {}
    for principal, old in (stored_identities or {}).items():
        if principal in current and current[principal] != old:
            targets.setdefault(old, set()).add(current[principal])
    shared = {old for principal, old in (stored_identities or {}).items()
              if list((stored_identities or {}).values()).count(old) > 1}
    moves = {old: next(iter(new)) for old, new in targets.items()
             if len(new) == 1 and old not in shared}
    moved = 0
    for ep in (getattr(state, "endpoints", None) or {}).values():
        variants, ids = [], set()
        for variant in ep.capture_variants:
            if variant.get("identity_key") in moves:
                variant = rekey_variant(variant, moves[variant["identity_key"]])
                moved += 1
            if variant.get("capture_id") not in ids:
                ids.add(variant.get("capture_id"))
                variants.append(variant)
        ep.capture_variants = variants
    return moved


def discovery_payload(state, rc, roles) -> dict:
    """The "discovery" unit: the engagement state, the parts of the crawl result `rc`
    that investigate_engagement reads after discovery (captures, sensitive-file
    evidence, the crawled endpoints, the candidate and IDOR lists, errors), and each
    principal's identity key (identity_keys)."""
    return {
        "identities": identity_keys(roles),
        "state": state.to_dict(),
        "rc": {
            "errors": list(getattr(rc, "errors", None) or []),
            "captured": [pack_exchange(c, roles) for c in getattr(rc, "captured", None) or []],
            "sensitive_file_evidence": list(getattr(rc, "sensitive_file_evidence", None) or []),
            "sensitive_file_hits": list(getattr(rc, "sensitive_file_hits", None) or []),
            "endpoints": [{"method": getattr(e, "method", ""), "path": getattr(e, "path", "")}
                          for e in getattr(rc, "endpoints", None) or []],
            "auth_bypass_candidates": list(getattr(rc, "auth_bypass_candidates", None) or []),
            "idor_candidates": list(getattr(rc, "idor_candidates", None) or []),
            "idor_findings": list(getattr(rc, "idor_findings", None) or []),
            "withheld_operations": list(getattr(rc, "withheld_operations", None) or []),
            "discovery_bounds": list(getattr(rc, "discovery_bounds", None) or []),
        },
    }


def restore_discovery(payload: dict, roles):
    """(state, rc) from a "discovery" unit: the same EngagementState and a stand-in for
    the crawl result with the fields discovery_payload kept."""
    from harness.engagement import EngagementState
    stored = payload["rc"]
    rc = SimpleNamespace(
        errors=list(stored.get("errors") or []),
        captured=[unpack_exchange(c, roles) for c in stored.get("captured") or []],
        sensitive_file_evidence=list(stored.get("sensitive_file_evidence") or []),
        sensitive_file_hits=list(stored.get("sensitive_file_hits") or []),
        endpoints=[SimpleNamespace(**e) for e in stored.get("endpoints") or []],
        auth_bypass_candidates=list(stored.get("auth_bypass_candidates") or []),
        idor_candidates=list(stored.get("idor_candidates") or []),
        idor_findings=list(stored.get("idor_findings") or []),
        withheld_operations=list(stored.get("withheld_operations") or []),
        discovery_bounds=list(stored.get("discovery_bounds") or []),
        identity_probes=[])
    state = EngagementState.from_dict(payload["state"])
    moved = rekey_captures(state, payload.get("identities") or {}, roles)
    if moved:
        log.info("restore_discovery: %d capture variant(s) moved to the current "
                 "credentials of their principal", moved)
    return state, rc


def resume_finding(finding: dict, root_job_id: str, *, proofs_for_case=None, resolves=None) -> dict:
    """A copy of a finding from an interrupted run for use in the resumed one, marked
    `resumed_from`. A confirmation keeps its status and proof ids only while the proof
    can still be shown: its proof record exists and, when it names exchanges, they
    resolve (stored_proof_artifacts_resolve). Otherwise it is downgraded to
    unconfirmed with the reason, never claimed. A confirmed finding with no proof
    pointer claimed nothing beyond its own run, so its status is kept."""
    out = dict(finding, resumed_from=root_job_id)
    case_id, proof_id = out.get("case_id"), out.get("proof_id")
    if not out.get("confirmed") or not case_id or not proof_id:
        return out
    if proofs_for_case is None:
        from harness import store
        proofs_for_case = store.proofs_for_case
    if resolves is None:
        from harness.assessment_health import stored_proof_artifacts_resolve as resolves
    try:
        proof = next((p for p in proofs_for_case(case_id) if p.get("proof_id") == proof_id), None)
        names_exchanges = proof is not None and any(
            [proof.get("baseline_artifact_id"), proof.get("attack_artifact_id"),
             *(proof.get("control_artifact_ids") or [])])
        shown = proof is not None and (not names_exchanges or resolves(proof))
    except Exception as e:  # a lookup that fails shows nothing
        log.warning("resume: proof lookup failed for case %s: %s", case_id, e)
        shown = False
    if not shown:
        out.update(confirmed=False, oracle_verified=False, verification_state="candidate",
                   resume_downgrade=f"proof belongs to interrupted job {root_job_id}; "
                                    "re-run to re-establish")
    return out


def resume_outcome(outcome: dict, root_job_id: str, **lookups) -> dict:
    """A worklist outcome from an interrupted run, its findings passed through
    resume_finding; `confirmed` follows them."""
    findings = [resume_finding(f, root_job_id, **lookups) for f in outcome.get("findings_detail") or []]
    return dict(outcome, findings_detail=findings,
                confirmed=any(f.get("confirmed") for f in findings))
