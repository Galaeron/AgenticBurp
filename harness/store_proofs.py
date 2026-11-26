"""Proof and evidence-blob repository of the harness state store.

Structured proof records and the content-addressed evidence blob store.

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


def persist_proof_record(proof) -> tuple[bool, str]:
    """Persist one structured proof attempt (Astra T01), append-only.

    Rejects a proof whose case ref is inconsistent -- a forged/unknown case whose
    case_id does not match its own identity-bearing fields. Uses INSERT OR IGNORE
    keyed on the per-attempt proof_id, so re-persisting is idempotent and a later
    weaker attempt never overwrites an earlier stronger proof of the same case
    (best_proof_for_case selects the strongest)."""
    from harness.evidence import ProofRecord  # local import: evidence has no store dependency
    if not isinstance(proof, ProofRecord):
        return False, "not a ProofRecord"
    if not proof.case.consistent:
        return False, "unknown_or_forged_case"
    c = proof.case
    conn = _store._connect()
    try:
        conn.execute(
            f"INSERT OR IGNORE INTO proof_records ({_store._PROOF_COLUMNS}) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (proof.proof_id, c.run_id, c.case_id, c.principal_id, c.request_template_id,
             c.check_id, c.parameter_location, c.parameter_name, c.workflow_state_id, c.finding_ref,
             proof.validator, proof.validator_version, proof.verdict.value,
             int(proof.executed), int(proof.legacy), proof.baseline_artifact_id,
             proof.attack_artifact_id, json.dumps(list(proof.control_artifact_ids)),
             proof.expected_invariant, proof.observed_result, proof.limitation,
             proof.created_at),
        )
        if proof.policy_fingerprint:
            conn.execute(
                "INSERT OR IGNORE INTO proof_identity (proof_id, policy_fingerprint, identity_version, "
                "created_at) VALUES (?,?,?,?)",
                (proof.proof_id, proof.policy_fingerprint, _store._PROOF_IDENTITY_VERSION, proof.created_at))
        if getattr(proof, "evidence_source", ""):
            conn.execute(
                "INSERT OR IGNORE INTO proof_evidence_source (proof_id, evidence_source, created_at) "
                "VALUES (?,?,?)", (proof.proof_id, proof.evidence_source, proof.created_at))
        conn.commit()
        return True, "accepted"
    finally:
        conn.close()


def _proof_row_to_dict(row) -> dict:
    """Reconstruct a ProofRecord.to_dict()-shaped dict (nested case) from a row."""
    (proof_id, run_id, case_id, principal_id, request_template_id, check_id,
     parameter_location, parameter_name, workflow_state_id, finding_ref, validator, validator_version,
     verdict, executed, legacy, baseline_artifact_id, attack_artifact_id,
     control_artifact_ids_json, expected_invariant, observed_result, limitation, created_at,
     policy_fingerprint, evidence_source) = row
    return {
        "proof_id": proof_id,
        "case": {"run_id": run_id, "case_id": case_id, "principal_id": principal_id,
                 "request_template_id": request_template_id, "check_id": check_id,
                 "parameter_location": parameter_location, "parameter_name": parameter_name,
                 "workflow_state_id": workflow_state_id, "finding_ref": finding_ref},
        "validator": validator, "validator_version": validator_version, "verdict": verdict,
        "executed": bool(executed), "legacy": bool(legacy),
        "baseline_artifact_id": baseline_artifact_id, "attack_artifact_id": attack_artifact_id,
        "control_artifact_ids": json.loads(control_artifact_ids_json or "[]"),
        "expected_invariant": expected_invariant, "observed_result": observed_result,
        "limitation": limitation, "created_at": created_at,
        "policy_fingerprint": policy_fingerprint or "",
        **({"evidence_source": evidence_source} if evidence_source else {}),
    }


def proofs_for_case(case_id: str) -> list[dict]:
    """All proof attempts for one case, oldest first (append-only history)."""
    conn = _store._connect()
    try:
        rows = conn.execute(
            f"SELECT {_store._PROOF_SELECT} WHERE p.case_id = ? ORDER BY p.created_at ASC",
            (case_id,)).fetchall()
        return [_store._proof_row_to_dict(r) for r in rows]
    finally:
        conn.close()


def best_proof_for_case(case_id: str) -> dict | None:
    """The strongest proof attempt for a case (confirmed > controlled_negative >
    inconclusive/blocked > error; ties break to the most recent). A later weaker
    attempt never displaces an earlier stronger one."""
    from harness.evidence import Verdict
    proofs = _store.proofs_for_case(case_id)
    if not proofs:
        return None
    return max(proofs, key=lambda d: (Verdict(d["verdict"]).rank(), d["created_at"]))


# ---------------------------------------------------------------------------
# FR-2 (F03): content-addressed evidence blob store. Callers MUST redact a
# blob's bytes (harness.security.redact_secrets_in_url / redact_headers /
# redact_secrets_in_body) BEFORE calling put_evidence_blob -- this store has
# no redaction logic of its own and persists exactly what it is given.
# ---------------------------------------------------------------------------

# ARC-13: the redaction assertion. Callers redact, but nothing checked it. Every blob
# is now re-run through the project's own redactors (harness.evidence_redaction); a
# correctly redacted blob changes nothing. What happens when one would change is
# EVIDENCE_BLOB_UNREDACTED_POLICY:
#   "flag"   -- store the blob as before, count it and log a warning (no values).
#               The DEFAULT: it changes no live behaviour. `verify_evidence_ledger
#               --check-blobs` lists the flagged blobs from the stored data.
#   "refuse" -- raise UnredactedEvidenceError and store nothing. The callers already
#               catch a failed write and mark the evidence degraded.
# "refuse" is the safer end state but is an owner decision: it could degrade evidence
# if a caller's redaction is weaker than this check, which only a live run can show.
# A call can override the policy with `unredacted=`.
EVIDENCE_BLOB_UNREDACTED_POLICY = "flag"


class UnredactedEvidenceError(ValueError):
    """put_evidence_blob refused a blob the redactors would still change."""


def evidence_blob_redaction_status() -> dict:
    """Process-lifetime count of blobs stored under the "flag" policy that the
    redactors would still have changed, plus the policy in force."""
    with _store._STATS_LOCK:
        flags = _store._UNREDACTED_BLOB_FLAGS
    return {"policy": _store.EVIDENCE_BLOB_UNREDACTED_POLICY, "unredacted_flags": flags,
            "lifetime": "process"}


def put_evidence_blob(data: bytes, *, unredacted: str | None = None) -> str:
    """Store `data` keyed by its own sha256 hex digest; returns that digest.

    Idempotent: INSERT OR IGNORE means storing the same bytes twice is a
    no-op, never a duplicate row or an overwrite -- the table is content-
    addressed, so the same hash always means the same bytes.

    `data` must already be redacted (see the comment above): a blob the
    redactors would still change is handled per `unredacted` ("flag" or
    "refuse"; default EVIDENCE_BLOB_UNREDACTED_POLICY).
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError(f"evidence blob data must be bytes, got {type(data).__name__}")
    policy = unredacted or _store.EVIDENCE_BLOB_UNREDACTED_POLICY
    if policy not in ("flag", "refuse"):
        raise ValueError(f"unredacted must be 'flag' or 'refuse', got {policy!r}")
    from harness.evidence_redaction import redaction_findings
    try:
        findings = redaction_findings(data)
    except Exception:       # e.g. RecursionError on a hostile body: unverifiable, not unstorable
        findings = [("check-failed", "")]
    if findings:
        kinds = ", ".join(sorted({kind for kind, _ in findings}))
        if policy == "refuse":
            raise _store.UnredactedEvidenceError(
                f"evidence blob not stored: {len(findings)} unredacted field(s) ({kinds})")
        with _store._STATS_LOCK:
            _store._UNREDACTED_BLOB_FLAGS += 1
        import logging
        logging.getLogger("harness.store").warning(
            "evidence blob stored with %d unredacted field(s) (%s); the caller must redact "
            "before put_evidence_blob", len(findings), kinds)
    digest = hashlib.sha256(data).hexdigest()
    conn = _store._connect()
    try:
        conn.execute(
            "INSERT OR IGNORE INTO evidence_blobs (sha256, data, created_at) VALUES (?, ?, ?)",
            (digest, sqlite3.Binary(bytes(data)), time.time()))
        conn.commit()
    finally:
        conn.close()
    return digest


def iter_evidence_blobs(db_path=None):
    """`(sha256, bytes)` for every stored blob, read-only, for the ledger verifier."""
    conn = _store._open_read_only(db_path)
    try:
        for digest, data in conn.execute("SELECT sha256, data FROM evidence_blobs ORDER BY sha256"):
            yield digest, bytes(data)
    except sqlite3.OperationalError:     # a store with no blob table yet has nothing to check
        return
    finally:
        conn.close()


def get_evidence_blob(h: str, *, conn: "sqlite3.Connection | None" = None) -> bytes | None:
    """The raw bytes stored under hash `h`, or None if absent. Does not
    re-verify the hash -- see evidence_blob_resolves() for the verified
    presence check that resolvability depends on.

    `conn`: optional already-open connection to run this lookup on, instead
    of opening (and closing) a fresh one just for this one hash (RA-4: lets
    a batched report reuse ONE connection across every blob hash it needs to
    resolve, rather than one fresh connection per hash). Omitted (the
    default, and what every existing caller gets) preserves the exact prior
    behavior; a caller-supplied `conn` is never closed here -- that stays
    the caller's responsibility."""
    if not h:
        return None
    owns_conn = conn is None
    c = conn if conn is not None else _store._connect()
    try:
        row = c.execute(
            "SELECT data FROM evidence_blobs WHERE sha256 = ?", (h,)).fetchone()
    finally:
        if owns_conn:
            c.close()
    if row is None:
        return None
    return bytes(row[0])


def evidence_blob_resolves(h: str, *, conn: "sqlite3.Connection | None" = None) -> bool:
    """True iff a blob is present for hash `h` AND its bytes still hash to
    `h`. This is the storage-backed check FR-2's resolvability depends on --
    a present-but-corrupted row (or one that was deleted) resolves False,
    same as a hash that was never stored at all.

    `conn`: optional shared connection, forwarded to get_evidence_blob (see
    its docstring) -- RA-4 batched-report perf. Omitted (the default)
    preserves the exact prior one-connection-per-call behavior."""
    data = _store.get_evidence_blob(h, conn=conn)
    if data is None:
        return False
    return hashlib.sha256(data).hexdigest() == h


def proofs_for_run(run_id: str) -> list[dict]:
    """Read every immutable proof attempt for exact run-level accounting."""
    conn = _store._connect()
    try:
        rows = conn.execute(
            f"SELECT {_store._PROOF_SELECT} WHERE p.run_id = ? ORDER BY p.created_at ASC",
            (run_id,)).fetchall()
        return [_store._proof_row_to_dict(row) for row in rows]
    finally:
        conn.close()


# The facade, bound last: the functions above read harness.store names through it at call
# time, and binding it here lets this module be imported before harness.store.
from harness import store as _store  # noqa: E402
