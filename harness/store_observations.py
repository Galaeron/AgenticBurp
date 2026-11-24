"""Exchange-observation repository of the harness state store (I02-C).

Observation piles, their revisions and attributions.

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
import hmac
import re
from urllib.parse import urlparse

from harness.models import HttpExchange


# ---------------------------------------------------------------------------
# I02-C: supplied observations that produced no finding stay available, so a
# later analysis can compare against them. Contract and owner decisions:
# docs/OBSERVATION_MEMORY.md. Write: record_observation. Read (the one bounded
# path): select_observations, rendered by observation_context_block. Analyst
# actions: correct_observation_attribution, delete_observation. Citations:
# resolve_observation_refs / get_observation.
# ---------------------------------------------------------------------------

_OBSERVATION_FACTS_MAX_BYTES = 2048
_OBSERVATION_EVIDENCE_MAX_BYTES = 64 * 1024
_OBSERVATION_KEYS_MAX = 32
_OBSERVATION_LABEL_MAX = 64
_ATTRIBUTION_FIELDS = ("principal_ref", "role", "tenant", "session_ref")
_CAPTURE_FIELD_DEFAULTS = {"captured_at": None, "capture_source": "",
                           "completeness": "unknown", "state_version": None}
# Structural labels rendered into prompts: no whitespace, quotes, backticks or
# shell punctuation. Analyst attribution labels may also contain spaces.
_UNSAFE_STRUCTURAL = re.compile(r"[^A-Za-z0-9_.:@/+\-]")
_UNSAFE_ATTRIBUTION = re.compile(r"[^A-Za-z0-9 _.:@/+\-]")
# The shared sanitizer masks credentials by context (header lines, key=value),
# not bare tokens, so an attribution label is also checked for credential shape:
# an auth-scheme prefix, a JWT, or a long mixed-case opaque token.
_CREDENTIAL_SHAPED = re.compile(
    r"^(?i:bearer|basic|digest|negotiate|token)\s|eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"
    r"|(?=[A-Za-z0-9_+/=\-]*[0-9])(?=[A-Za-z0-9_+/=\-]*[a-z])(?=[A-Za-z0-9_+/=\-]*[A-Z])"
    r"[A-Za-z0-9_+/=\-]{32,}")


class ObservationRevisionConflict(ValueError):
    """An attribution correction named a revision that is no longer current."""


class ObservationDeleted(LookupError):
    """The observation was deleted by the analyst; only its tombstone remains."""


def _supplied_capture_fields(exchange) -> dict:
    """The I07 capture fields the client actually supplied (absent = unknown)."""
    return {name: getattr(exchange, name, default)
            for name, default in _store._CAPTURE_FIELD_DEFAULTS.items()
            if getattr(exchange, name, default) != default}


def exchange_identity(exchange) -> tuple[str, str]:
    """(exchange_id, source) shared by finding provenance and observations.

    The capture driver's own id wins ("client"). Otherwise the id is the content
    hash persist_findings has always used ("content"). Supplied I07 capture
    fields join that hash only when present, so a legacy exchange keeps its old
    id, and the same body captured at two different times stays two captures.
    """
    capture_id = getattr(exchange, "capture_id", "") or ""
    if capture_id:
        return capture_id, "client"
    from harness import cache as _cache
    content = _cache.ExchangeCache.compute_exchange_hash(exchange)
    supplied = _store._supplied_capture_fields(exchange)
    if supplied:
        content = hashlib.sha256(json.dumps([content, supplied], sort_keys=True).encode()).hexdigest()
    return content[:16], "content"


def _observation_host(url: str) -> str:
    """Scope host without URL userinfo, so a credential in a URL never becomes
    part of a stored key."""
    return urlparse(url or "").netloc.rpartition("@")[2]


def _observation_endpoint(url: str) -> str:
    from urllib.parse import urlsplit, urlunsplit
    parts = urlsplit(url or "")
    return _store._normalize_endpoint(urlunsplit(parts._replace(netloc=parts.netloc.rpartition("@")[2])))


def _observation_id(host: str, engagement_id: str, exchange_id: str) -> str:
    return hashlib.sha256(json.dumps([host, engagement_id, exchange_id]).encode()).hexdigest()[:32]


def _structural_label(value, limit: int = _OBSERVATION_LABEL_MAX) -> str:
    return _store._UNSAFE_STRUCTURAL.sub("?", str(value or ""))[:limit]


def _store_key(conn: sqlite3.Connection) -> bytes:
    return bytes.fromhex(conn.execute(
        "SELECT value FROM state_metadata WHERE name='principal-hmac-v1'").fetchone()[0])


def _observation_digest(exchange, key: bytes) -> str:
    """Keyed digest of the immutable capture facts. Volatile transport headers
    are left out (as in the cache hash), so a recapture differing only in Date
    is the same content. Keyed, so a digest over credential-bearing content
    cannot be tested offline against guessed values."""
    from harness import cache as _cache
    strip = _cache.ExchangeCache._strip_volatile_headers
    canonical = json.dumps({
        "url": exchange.url, "method": exchange.method,
        "request_headers": strip(exchange.request_headers), "request_body": exchange.request_body,
        "response_status": exchange.response_status,
        "response_headers": strip(exchange.response_headers), "response_body": exchange.response_body,
        "capture": _store._supplied_capture_fields(exchange),
    }, sort_keys=True, default=str)
    return hmac.new(key, b"observation-digest-v1\x1f" + canonical.encode(), hashlib.sha256).hexdigest()


def _observation_facts(exchange) -> dict:
    """Bounded structural response facts: status, content type, size and the
    top-level JSON key names. No values -- the sanitized evidence blob holds
    the content."""
    from harness import security
    content_type = next((v for k, v in (exchange.response_headers or {}).items()
                         if k.lower() == "content-type"), "")
    body = exchange.response_body or ""
    facts: dict = {"status": exchange.response_status,
                   "content_type": _store._structural_label(content_type.split(";")[0].strip()),
                   "body_bytes": len(body.encode("utf-8", "surrogatepass"))}
    if body.lstrip().startswith("{"):
        try:
            parsed = json.loads(body)
        except (ValueError, RecursionError):
            parsed = None
        if isinstance(parsed, dict):
            keys = sorted({_store._structural_label(security.sanitize_text(k)) for k in parsed
                           if isinstance(k, str)} - {""})
            if keys:
                facts["json_keys"] = keys[:_store._OBSERVATION_KEYS_MAX]
                if len(keys) > _store._OBSERVATION_KEYS_MAX:
                    facts["json_keys_truncated"] = True
    while len(json.dumps(facts)) > _store._OBSERVATION_FACTS_MAX_BYTES and facts.get("json_keys"):
        facts["json_keys"] = facts["json_keys"][:-1]
        facts["json_keys_truncated"] = True
    return facts


def _observation_evidence(exchange) -> tuple[bytes, bool]:
    """The sanitized exchange as a resolvable evidence object, capped in size.
    Truncation is explicit (`evidence_truncated`), never silent."""
    from harness import security
    clean = security.sanitized_exchange(exchange)
    doc = {"url": clean.url, "method": clean.method,
           "request_headers": clean.request_headers, "request_body": clean.request_body,
           "response_status": clean.response_status, "response_headers": clean.response_headers,
           "response_body": clean.response_body, "capture": _store._supplied_capture_fields(exchange)}

    def encoded() -> bytes:
        return json.dumps(doc, sort_keys=True, default=str).encode("utf-8", "surrogatepass")

    data = encoded()
    if len(data) <= _store._OBSERVATION_EVIDENCE_MAX_BYTES:
        return data, False
    doc["evidence_truncated"] = True
    for name in ("response_body", "request_body"):
        while doc[name] and len(encoded()) > _store._OBSERVATION_EVIDENCE_MAX_BYTES:
            doc[name] = doc[name][: len(doc[name]) // 2]
    if len(encoded()) > _store._OBSERVATION_EVIDENCE_MAX_BYTES:
        doc.update(request_headers={}, response_headers={}, url=doc["url"][:2048])
    data = encoded()
    if len(data) > _store._OBSERVATION_EVIDENCE_MAX_BYTES:
        data = json.dumps({"method": _store._structural_label(clean.method), "evidence_truncated": True}).encode()
    return data, True


def clean_observation_attribution(attribution: dict | None) -> dict:
    """Analyst-declared attribution labels, validated. An absent or empty value
    means unknown. A value that looks like a credential is rejected, never
    stored: a label must survive the shared sanitizer unchanged."""
    from harness import security
    attribution = dict(attribution or {})
    unknown_fields = set(attribution) - set(_store._ATTRIBUTION_FIELDS)
    if unknown_fields:
        raise ValueError(f"unknown attribution field(s): {sorted(unknown_fields)}")
    clean: dict = {}
    for name in _store._ATTRIBUTION_FIELDS:
        value = attribution.get(name)
        if value is None or value == "":
            clean[name] = None
            continue
        if (not isinstance(value, str) or len(value) > _store._OBSERVATION_LABEL_MAX
                or value != value.strip() or _store._UNSAFE_ATTRIBUTION.search(value)):
            raise ValueError(f"attribution {name} must be a short plain label")
        if security.sanitize_text(value) != value or _store._CREDENTIAL_SHAPED.search(value):
            raise ValueError(f"attribution {name} looks like a credential; use a label")
        clean[name] = value
    return clean


def _unknown_attribution() -> dict:
    return {"revision": 0, "source": "unknown", **{name: None for name in _store._ATTRIBUTION_FIELDS}}


def _current_attributions(conn: sqlite3.Connection, ids: list[str]) -> dict[str, dict]:
    if not ids:
        return {}
    marks = ",".join("?" for _ in ids)
    rows = conn.execute(
        f"SELECT a.observation_id, a.revision, a.principal_ref, a.role, a.tenant, a.session_ref, a.source "
        f"FROM observation_attributions a WHERE a.observation_id IN ({marks}) AND a.revision = "
        f"(SELECT MAX(b.revision) FROM observation_attributions b WHERE b.observation_id = a.observation_id)",
        list(ids)).fetchall()
    return {r[0]: {"revision": r[1], "principal_ref": r[2], "role": r[3], "tenant": r[4],
                   "session_ref": r[5], "source": r[6]} for r in rows}


def record_observation(exchange: HttpExchange, *, engagement_id: str = "",
                       captured_principal: str | None = None, attribution: dict | None = None,
                       run_id: str = "", now: float | None = None) -> dict:
    """Retain one supplied capture, whether or not it produced a finding.

    Returns {"status", "observation_id", "exchange_id"}. The idempotency key is
    (host, engagement_id, exchange_id) and status is one of:
      stored     -- new observation; attribution revision 1 is written with it;
      duplicate  -- same scoped capture, same content digest: nothing written;
      conflict   -- same scoped capture id, different content: rejected, and the
                    stored observation is untouched;
      deleted    -- the analyst deleted this capture: it is not resurrected.
    Credentials are never stored: the evidence is the sanitized exchange, the
    captured context is the existing keyed label and the digest is keyed.
    """
    engagement_id = _store._engagement_partition(engagement_id)
    host = _store._observation_host(exchange.url)
    if not host:
        raise ValueError("an observation needs an absolute URL with a host")
    declared = _store.clean_observation_attribution(attribution)
    if captured_principal is None:
        captured_principal = _store.captured_principal_id(exchange)
    exchange_id, id_source = _store.exchange_identity(exchange)
    observation_id = _store._observation_id(host, engagement_id, exchange_id)
    facts = _store._observation_facts(exchange)
    evidence, truncated = _store._observation_evidence(exchange)
    evidence_hash = hashlib.sha256(evidence).hexdigest()
    supplied = _store._supplied_capture_fields(exchange)
    now = time.time() if now is None else now
    from harness import security
    result = {"observation_id": observation_id, "exchange_id": exchange_id}
    conn = _store._connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        digest = _store._observation_digest(exchange, _store._store_key(conn))
        existing = conn.execute(
            "SELECT observation_id, content_digest, status FROM exchange_observations "
            "WHERE host = ? AND engagement_id = ? AND exchange_id = ?",
            (host, engagement_id, exchange_id)).fetchone()
        if existing is not None:
            if existing[2] == "deleted":
                status = "deleted"
            elif hmac.compare_digest(existing[1], digest):
                status = "duplicate"
            else:
                status = "conflict"
            return {**result, "observation_id": existing[0], "status": status}
        conn.execute("INSERT OR IGNORE INTO evidence_blobs (sha256, data, created_at) VALUES (?, ?, ?)",
                     (evidence_hash, sqlite3.Binary(evidence), now))
        conn.execute(
            "INSERT INTO exchange_observations (observation_id, host, engagement_id, exchange_id, "
            "id_source, content_digest, captured_principal_id, method, url_redacted, "
            "normalized_endpoint, captured_at, ingested_at, capture_source, completeness, "
            "state_version, facts_json, evidence_sha256, evidence_truncated, first_run_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (observation_id, host, engagement_id, exchange_id, id_source, digest, captured_principal,
             exchange.method, security.redact_secrets_in_url(exchange.url),
             _store._observation_endpoint(exchange.url), supplied.get("captured_at"), now,
             supplied.get("capture_source") or "unknown", supplied.get("completeness", "unknown"),
             supplied.get("state_version"), json.dumps(facts, sort_keys=True), evidence_hash,
             int(truncated), run_id or ""))
        conn.execute(
            "INSERT INTO observation_attributions (observation_id, revision, engagement_id, "
            "principal_ref, role, tenant, session_ref, source, reason, created_at) "
            "VALUES (?, 1, ?, ?, ?, ?, ?, ?, '', ?)",
            (observation_id, engagement_id, *(declared[name] for name in _store._ATTRIBUTION_FIELDS),
             "analyst" if any(declared.values()) else "unknown", now))
        conn.commit()
        return {**result, "status": "stored"}
    finally:
        if conn.in_transaction:
            conn.rollback()
        conn.close()


def _attribution_join(current_context: str, current: dict,
                      other_context: str, other: dict) -> tuple[bool, str]:
    """Whether an earlier observation may inform the current analysis, and why.

    Scope (site/pile/endpoint) is already applied in SQL; equal URLs alone never
    join. A recognized credential context (the keyed captured-auth label) joins
    with itself. `anonymous` only means "no recognized credential header", so it
    counts as unknown. Otherwise only an analyst-declared tenant on both sides
    joins. Declared tenants that differ never join; an unknown tenant never
    matches another unknown one.
    """
    mine, theirs = current.get("tenant"), other.get("tenant")
    if mine and theirs and mine != theirs:
        return False, "tenant-mismatch"
    if current_context and current_context == other_context and current_context != "anonymous":
        return True, "same-captured-context"
    if mine and theirs:
        return True, "declared-same-tenant"
    return False, "unattributed-context"


def select_observations(url: str, *, engagement_id: str = "", captured_principal: str,
                        attribution: dict | None = None, exclude_exchange_id: str = "",
                        limit: int = 8, scan_limit: int = 200) -> dict:
    """The one bounded retrieval path for earlier observations of this endpoint.

    Scope: same host, same pile (engagement_id) and same normalized endpoint
    (path kept, query values dropped), excluding the current capture; at most
    `scan_limit` most recently ingested rows are considered and `limit` are
    selected. The attribution predicate (_attribution_join) then decides each
    row; rows it rejects are reported only as counts per reason, never by id.
    Deleted observations that would have joined are listed as unavailable.
    The current capture's stored attribution (if it was already ingested) wins
    over the one supplied with this request.

    Ordering is by capture time when known; rows without one keep ingest order
    and say so (`order_basis`), so arrival order is never silently treated as
    capture order. `digest` changes whenever the selection, an attribution
    revision, a deletion or an evidence expiry changes.
    """
    engagement_id = _store._engagement_partition(engagement_id)
    host = _store._observation_host(url)
    endpoint = _store._observation_endpoint(url)
    current = {**_store._unknown_attribution(), **_store.clean_observation_attribution(attribution)}
    selected: list[dict] = []
    unavailable: list[dict] = []
    excluded: dict[str, int] = {}
    conn = _store._connect()
    try:
        if exclude_exchange_id:
            own = conn.execute(
                "SELECT observation_id FROM exchange_observations "
                "WHERE host = ? AND engagement_id = ? AND exchange_id = ?",
                (host, engagement_id, exclude_exchange_id)).fetchone()
            if own is not None:
                current = _store._current_attributions(conn, [own[0]]).get(own[0], current)
        rows = conn.execute(
            "SELECT observation_id, method, normalized_endpoint, captured_at, ingested_at, "
            "captured_principal_id, facts_json, state_version, completeness, capture_source, "
            "evidence_sha256, evidence_truncated, status FROM exchange_observations "
            "WHERE host = ? AND engagement_id = ? AND normalized_endpoint = ? AND exchange_id != ? "
            "ORDER BY ingested_at DESC LIMIT ?",
            (host, engagement_id, endpoint, exclude_exchange_id, max(0, int(scan_limit)))).fetchall()
        attributions = _store._current_attributions(conn, [r[0] for r in rows])
        for (oid, method, norm, captured_at, ingested_at, context, facts_json, state_version,
             completeness, capture_source, evidence_sha, evidence_truncated, status) in rows:
            attribution_now = attributions.get(oid, _store._unknown_attribution())
            joined, reason = _store._attribution_join(captured_principal, current, context, attribution_now)
            if not joined:
                excluded[reason] = excluded.get(reason, 0) + 1
            elif status == "deleted":
                unavailable.append({"observation_id": oid, "reason": "deleted"})
            elif len(selected) >= limit:
                excluded["over-limit"] = excluded.get("over-limit", 0) + 1
            else:
                selected.append({
                    "observation_id": oid, "method": method, "normalized_endpoint": norm,
                    "captured_at": captured_at, "ingested_at": ingested_at,
                    "order_basis": "capture" if captured_at is not None else "ingest",
                    "state_version": state_version, "completeness": completeness,
                    "capture_source": capture_source, "facts": json.loads(facts_json or "{}"),
                    "attribution": attribution_now, "evidence_ref": evidence_sha,
                    "evidence_truncated": bool(evidence_truncated),
                    "evidence_status": ("resolved" if _store.evidence_blob_resolves(evidence_sha, conn=conn)
                                        else "unavailable"),
                    "reason": reason})
    finally:
        conn.close()
    selected.sort(key=lambda o: (o["order_basis"] != "capture",
                                 o["captured_at"] if o["captured_at"] is not None else o["ingested_at"]))
    bases = {o["order_basis"] for o in selected}
    order_basis = "none" if not bases else (next(iter(bases)) if len(bases) == 1 else "mixed")
    digest = hashlib.sha256(json.dumps({
        "selected": [[o["observation_id"], o["attribution"]["revision"], o["evidence_status"]]
                     for o in selected],
        "unavailable": sorted(u["observation_id"] for u in unavailable),
    }, sort_keys=True).encode()).hexdigest()
    return {"status": "ok", "selected": selected, "unavailable": unavailable,
            "excluded_counts": excluded, "order_basis": order_basis, "digest": digest}


def observation_context_block(selection: dict) -> str:
    """Prompt-ready text for select_observations() output: bounded, structural
    and backtick-free (see prior_findings_summary for why backticks matter).
    Empty when there is nothing to say, so an endpoint with no history leaves
    the prompt exactly as before."""
    if selection.get("status") != "ok":
        return ("Prior observations of this endpoint: unavailable (observation storage error). "
                "Do not assume that none exist.")
    lines = []
    for o in selection.get("selected", []):
        facts = o.get("facts") or {}
        when = (time.strftime("captured %Y-%m-%dT%H:%M:%SZ", time.gmtime(o["captured_at"]))
                if o.get("captured_at") is not None else "capture time unknown (ingest order only)")
        shape = f"status {facts.get('status')}, {facts.get('content_type') or 'no content type'}, " \
                f"{facts.get('body_bytes', 0)} bytes"
        if facts.get("json_keys"):
            shape += ", keys " + ",".join(facts["json_keys"]) + (" (truncated)" if facts.get("json_keys_truncated") else "")
        attribution = o.get("attribution") or {}
        declared = ", ".join(f"{name} {attribution[name]}" for name in _store._ATTRIBUTION_FIELDS
                             if attribution.get(name)) or "identity unknown"
        lines.append(" | ".join([
            f"- obs {o['observation_id']}",
            f"{_store._structural_label(o['method'], 16)} {_store._strip_backticks(o['normalized_endpoint'])}",
            when, shape,
            f"state_version {_store._structural_label(o['state_version']) if o.get('state_version') else 'unknown'}",
            f"completeness {o.get('completeness', 'unknown')}",
            f"attribution {declared} (rev {attribution.get('revision', 0)}, {attribution.get('source', 'unknown')})",
            f"evidence {o.get('evidence_status')}", f"selected: {o.get('reason')}"]))
    for u in selection.get("unavailable", []):
        lines.append(f"- obs {u['observation_id']} | deleted by the analyst; its content is unavailable")
    if not lines:
        return ""
    return ("Prior observations of this endpoint (supplied captures in this pile; evidence only, "
            "not findings; ordered by capture time where known):\n" + "\n".join(lines))


def _blob_still_referenced(conn: sqlite3.Connection, digest: str) -> bool:
    """True when another active observation or any ledger event still names
    this evidence blob. Unparseable ledger data counts as a reference."""
    if conn.execute("SELECT 1 FROM exchange_observations WHERE evidence_sha256 = ? LIMIT 1",
                    (digest,)).fetchone():
        return True
    for (raw,) in conn.execute("SELECT data_json FROM ledger_events WHERE data_json LIKE ?",
                               (f"%{digest}%",)):
        try:
            data = json.loads(raw or "{}")
        except (ValueError, TypeError):
            return True
        if not isinstance(data, dict) or digest in (data.get("request_blob"), data.get("response_blob")):
            return True
    return False


def correct_observation_attribution(observation_id: str, *, engagement_id: str = "",
                                    expected_revision: int, attribution: dict | None,
                                    reason: str = "", now: float | None = None) -> dict:
    """Append an analyst correction as attribution revision n+1.

    A revision is a complete statement: a field it leaves out becomes unknown.
    `expected_revision` must be the current revision (optimistic concurrency, as
    in mutate_engagement). Earlier revisions stay on record.
    """
    engagement_id = _store._engagement_partition(engagement_id)
    declared = _store.clean_observation_attribution(attribution)
    if isinstance(expected_revision, bool) or not isinstance(expected_revision, int):
        raise ValueError("expected_revision must be an integer")
    from harness import security
    reason = security.sanitize_text(str(reason or "").strip())[:200]
    now = time.time() if now is None else now
    conn = _store._connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT status FROM exchange_observations WHERE observation_id = ? "
                           "AND engagement_id = ?", (observation_id, engagement_id)).fetchone()
        if row is None:
            raise LookupError("no such observation in this pile")
        if row[0] == "deleted":
            raise _store.ObservationDeleted("the observation was deleted")
        current = conn.execute("SELECT COALESCE(MAX(revision), 0) FROM observation_attributions "
                               "WHERE observation_id = ?", (observation_id,)).fetchone()[0]
        if current != expected_revision:
            raise _store.ObservationRevisionConflict(
                f"attribution revision is {current}, not {expected_revision}")
        conn.execute(
            "INSERT INTO observation_attributions (observation_id, revision, engagement_id, "
            "principal_ref, role, tenant, session_ref, source, reason, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 'analyst', ?, ?)",
            (observation_id, current + 1, engagement_id,
             *(declared[name] for name in _store._ATTRIBUTION_FIELDS), reason, now))
        conn.commit()
        return {"observation_id": observation_id, "revision": current + 1, "attribution": declared}
    finally:
        if conn.in_transaction:
            conn.rollback()
        conn.close()


def delete_observation(observation_id: str, *, engagement_id: str = "",
                       now: float | None = None) -> dict:
    """Analyst deletion: the observation becomes a tombstone (scope, method,
    endpoint, times, keyed digest and attribution labels remain; facts, state
    label, URL and evidence go). The evidence blob is deleted unless another
    observation or a ledger event still references it. A tombstone is never
    selected again and its id resolves as deleted."""
    engagement_id = _store._engagement_partition(engagement_id)
    now = time.time() if now is None else now
    conn = _store._connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT status, evidence_sha256 FROM exchange_observations "
                           "WHERE observation_id = ? AND engagement_id = ?",
                           (observation_id, engagement_id)).fetchone()
        if row is None:
            raise LookupError("no such observation in this pile")
        if row[0] == "deleted":
            return {"observation_id": observation_id, "status": "deleted",
                    "already_deleted": True, "evidence_deleted": False}
        conn.execute(
            "UPDATE exchange_observations SET status = 'deleted', deleted_at = ?, facts_json = '{}', "
            "state_version = NULL, url_redacted = '', evidence_sha256 = '', evidence_truncated = 0 "
            "WHERE observation_id = ?", (now, observation_id))
        evidence_deleted = False
        if row[1] and not _store._blob_still_referenced(conn, row[1]):
            evidence_deleted = conn.execute("DELETE FROM evidence_blobs WHERE sha256 = ?",
                                            (row[1],)).rowcount > 0
        conn.commit()
        return {"observation_id": observation_id, "status": "deleted",
                "already_deleted": False, "evidence_deleted": evidence_deleted}
    finally:
        if conn.in_transaction:
            conn.rollback()
        conn.close()


def resolve_observation_refs(observation_ids: list[str], *, engagement_id: str = "") -> dict[str, str]:
    """Citation check: each id -> resolved | evidence_unavailable | deleted |
    unknown, within one pile. An id from another pile is unknown here."""
    engagement_id = _store._engagement_partition(engagement_id)
    ids = [i for i in dict.fromkeys(observation_ids) if i]
    out = {i: "unknown" for i in ids}
    if not ids:
        return out
    conn = _store._connect()
    try:
        marks = ",".join("?" for _ in ids)
        for oid, status, evidence_sha in conn.execute(
                f"SELECT observation_id, status, evidence_sha256 FROM exchange_observations "
                f"WHERE observation_id IN ({marks}) AND engagement_id = ?", [*ids, engagement_id]):
            if status == "deleted":
                out[oid] = "deleted"
            else:
                out[oid] = ("resolved" if _store.evidence_blob_resolves(evidence_sha, conn=conn)
                            else "evidence_unavailable")
    finally:
        conn.close()
    return out


def get_observation(observation_id: str, *, engagement_id: str = "") -> dict | None:
    """One observation within its pile, with its attribution history; a
    tombstone shows only that it was deleted. None when unknown here."""
    engagement_id = _store._engagement_partition(engagement_id)
    conn = _store._connect()
    try:
        row = conn.execute(
            "SELECT observation_id, method, normalized_endpoint, captured_at, ingested_at, "
            "capture_source, completeness, state_version, facts_json, evidence_sha256, "
            "evidence_truncated, status, deleted_at FROM exchange_observations "
            "WHERE observation_id = ? AND engagement_id = ?", (observation_id, engagement_id)).fetchone()
        if row is None:
            return None
        if row[11] == "deleted":
            return {"observation_id": row[0], "status": "deleted", "deleted_at": row[12]}
        history = [{"revision": r[0], "principal_ref": r[1], "role": r[2], "tenant": r[3],
                    "session_ref": r[4], "source": r[5], "reason": r[6], "created_at": r[7]}
                   for r in conn.execute(
                       "SELECT revision, principal_ref, role, tenant, session_ref, source, reason, "
                       "created_at FROM observation_attributions WHERE observation_id = ? "
                       "ORDER BY revision", (observation_id,))]
        return {"observation_id": row[0], "status": "active", "method": row[1],
                "normalized_endpoint": row[2], "captured_at": row[3], "ingested_at": row[4],
                "capture_source": row[5], "completeness": row[6], "state_version": row[7],
                "facts": json.loads(row[8] or "{}"),
                "evidence_status": ("resolved" if _store.evidence_blob_resolves(row[9], conn=conn)
                                    else "unavailable"),
                "evidence_truncated": bool(row[10]),
                "attribution": history[-1] if history else _store._unknown_attribution(),
                "attribution_history": history}
    finally:
        conn.close()


# The facade, bound last: the functions above read harness.store names through it at call
# time, and binding it here lets this module be imported before harness.store.
from harness import store as _store  # noqa: E402
