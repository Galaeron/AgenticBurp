"""
Second-order confirmation primitives (V22 second-order SQLi, V17 second-order IDOR).

The confirmation legs in this harness share one shape: replay ~one request under a
different condition and diff against a baseline. That structurally cannot catch a
second-order bug, where a value is stored safely by request A and reused unsafely
by a DIFFERENT request B on an unrelated path (HARNESS_IMPROVEMENT_NOTES #3).
sqlmap is single-request; the cross-identity leg replays one request. Neither
models plant-A -> trigger-B.

This module supplies the missing plant->trigger DIFFERENTIALS as pure-ish
primitives over injected async callables, so the (A, B) pair the chain composer
identifies (chaining.py's second_order_* rules) can be actively confirmed without
baking the network into the oracle -- and the oracle is unit-tested with simulated
vulnerable/safe B endpoints, no live target.

  - confirm_second_order_sqli: plant a boolean-TRUE vs boolean-FALSE SQL marker
    via A, trigger B each time; if B's response depends on the planted boolean,
    the stored value reaches a SQL query on B -> confirmed second-order SQLi.
  - confirm_second_order_idor: plant a unique marker object as identity 1 via A,
    read via B as identity 2; if identity 2 sees identity 1's planted marker, the
    stored object crosses the identity boundary -> confirmed second-order IDOR.

Deterministic given the injected callables. The orchestrator supplies real,
scope-gated, gated (allow_mutating_replay) send callables; the plant is a mutating
write, so this only runs under the mutating opt-in.
"""
from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass

log = logging.getLogger("harness.second_order")

# Boolean markers whose only difference is the truth of the injected condition.
# A value stored verbatim and later concatenated into `... WHERE x='<value>'`
# makes the TRUE variant return the row set and the FALSE variant return nothing.
_TRUE_SUFFIX = "' OR '1'='1"
_FALSE_SUFFIX = "' OR '1'='2"


@dataclass
class SecondOrderResult:
    confirmed: bool
    reason: str
    evidence: str = ""


async def send_through_run(run_context, method: str, url: str, *, allowed_hosts,
                           config, capability: str, headers=None, body=None,
                           case_ref: str = ""):
    """ARCH-2: the one send path the second-order plant AND read use.

    Routes through the OWNING run's single TargetTransport when a run_context is
    supplied (owned_context is None -> the borrowed run is never closed here);
    otherwise builds and closes one standalone context. This puts every
    second-order write/read on the single policy path -- scope + gate + request
    budget + evidence -- under the run's TLS trust, instead of a separate client
    with an unconditional verify=False that bypassed all of it. Returns the
    transport's ExecutionOutcome (``.ok``/``.status``/``.outcome``/``.body``).
    """
    from harness.run_context import transport_for
    _tt, _owned = transport_for(run_context, allowed_hosts=allowed_hosts, config=config)
    try:
        return await _tt.send_creds(method, url, capability=capability,
                                    headers=headers, body=body, case_ref=case_ref,
                                    max_redirects=0)
    finally:
        if _owned is not None:
            await _owned.aclose()


def _similar(a: str, b: str) -> float:
    """Cheap response-similarity in [0,1] on length + shared-token overlap -- used
    to tell 'B's response changed with the planted boolean' from 'identical'."""
    a, b = a or "", b or ""
    if not a and not b:
        return 1.0
    la, lb = len(a), len(b)
    length_sim = min(la, lb) / max(la, lb) if max(la, lb) else 1.0
    ta, tb = set(a.split()), set(b.split())
    tok_sim = len(ta & tb) / len(ta | tb) if (ta | tb) else 1.0
    return 0.5 * length_sim + 0.5 * tok_sim


def _mask_reflection(text: str, *markers: str) -> str:
    """Neutralise any REFLECTION of the planted markers themselves (R12).

    A second-order boolean-SQLi test plants two DIFFERENT literal strings (the
    only difference being '1'='1' vs '1'='2'). If B merely ECHOES the stored
    value, its two responses differ solely because the echoed text differs -- that
    is display, not SQL evaluation, and must NOT confirm. Masking every occurrence
    of each planted marker (and its common HTML-escaped forms) to a constant means
    only a difference in the RESULT SET (data-driven, SQL-dependent) survives to
    the similarity comparison."""
    out = text or ""
    for m in markers:
        if not m:
            continue
        for variant in (m, m.replace("'", "&#39;"), m.replace("'", "&#x27;"),
                        m.replace("'", "&#039;"), m.replace("'", "%27")):
            out = out.replace(variant, "<MARK>")
    return out


async def confirm_second_order_sqli(
    *,
    plant,          # async plant(marker_value) -> None: perform write A storing marker_value
    trigger,        # async trigger() -> str: perform read B, return its response text
    reset=None,     # optional async reset() -> None between plants
    base_marker: str | None = None,
    similarity_threshold: float = 0.9,
) -> SecondOrderResult:
    """Boolean-based second-order SQLi differential.

    Plants a TRUE and a FALSE boolean SQL marker via `plant` (write A), triggering
    `trigger` (read B) after each. If B's response is (near-)identical for both,
    the stored value is inert on B (not confirmed). If B's response differs
    materially between the TRUE and FALSE plant, the stored value is being
    interpreted as SQL on B -- confirmed second-order SQLi.

    A per-run nonce namespaces the marker so this never collides with real data."""
    base = base_marker or ("so" + secrets.token_hex(4))
    true_val = f"{base}{_TRUE_SUFFIX}"
    false_val = f"{base}{_FALSE_SUFFIX}"

    if reset:
        await reset()
    await plant(true_val)
    resp_true = await trigger() or ""

    if reset:
        await reset()
    await plant(false_val)
    resp_false = await trigger() or ""

    # Mask any literal reflection of the planted markers before comparing (R12):
    # a plain echo of the two different payloads is display, not SQL evaluation,
    # and must not confirm. Only a data-driven difference in the RESULT SET
    # survives the mask.
    masked_true = _mask_reflection(resp_true, true_val, false_val, base)
    masked_false = _mask_reflection(resp_false, true_val, false_val, base)
    raw_sim = _similar(resp_true, resp_false)
    sim = _similar(masked_true, masked_false)
    reflection_only = raw_sim < similarity_threshold <= sim
    if sim < similarity_threshold:
        return SecondOrderResult(
            confirmed=True,
            reason="second-order SQLi confirmed: the read's response depends on a boolean SQL "
                   "condition planted via the write (difference persists after masking the "
                   "reflected payload -- it is in the result set, not the echo)",
            evidence=(f"Planted TRUE marker ({true_val!r}) then FALSE ({false_val!r}) via the write; "
                      f"after masking the reflected payload the read's response STILL differed "
                      f"materially (masked similarity {sim:.2f} < {similarity_threshold}; raw {raw_sim:.2f}). "
                      f"A stored value that changes the read's result set by flipping '1'='1' vs "
                      f"'1'='2' is being concatenated into a SQL query on the read path."))
    if reflection_only:
        return SecondOrderResult(
            confirmed=False,
            reason="no second-order SQLi: the read's responses differed ONLY by the reflected "
                   "payload text (display/echo), not by any SQL-dependent change in the result set",
            evidence=(f"Raw responses differed (similarity {raw_sim:.2f}) but became near-identical "
                      f"once the planted markers were masked (masked similarity {sim:.2f}) -- the "
                      f"difference is a literal echo of the two payloads, not SQL evaluation."))
    return SecondOrderResult(
        confirmed=False,
        reason="no second-order SQLi: the read's response did not depend on the planted SQL boolean",
        evidence=f"TRUE vs FALSE plant produced near-identical read responses (masked similarity {sim:.2f}).")


async def auto_confirm_candidates(candidates, *, confirm_sqli, confirm_idor,
                                  is_allowed=None, cap: int = 12) -> list[dict]:
    """Drive live confirmation over the composed (A,B) pairs from
    chaining.second_order_candidates. `confirm_sqli(a_url, b_url)` and
    `confirm_idor(a_url, b_url)` are injected async callables returning a
    SecondOrderResult (the orchestrator wires them to gated sends; tests inject
    fakes). `is_allowed(url)` scope-gates the plant target. Returns a list of
    CONFIRMED finding dicts (empty when nothing bites). Bounded by `cap`; a pair
    that raises is skipped, never fatal."""
    out: list[dict] = []
    seen: set[tuple] = set()
    ran = 0
    for cand in candidates or []:
        if ran >= cap:
            break
        a_url = (cand.get("a") or {}).get("url")
        b_url = (cand.get("b") or {}).get("url")
        if not a_url or not b_url:
            continue
        key = (cand.get("signature"), a_url, b_url)
        if key in seen:
            continue
        seen.add(key)
        if is_allowed is not None and not is_allowed(a_url):
            continue
        ran += 1
        try:
            if cand.get("kind") == "sqli":
                res = await confirm_sqli(a_url, b_url)
            else:
                res = await confirm_idor(a_url, b_url)
        except Exception as e:  # a pair blowing up must not sink the rest
            log.debug("auto_confirm_candidates: %s failed: %s", cand.get("signature"), e)
            continue
        if res is not None and getattr(res, "confirmed", False):
            out.append({
                "vulnerability_class": cand["signature"],
                "url": b_url,
                "confirmed": True,
                "confidence": 0.9,
                "severity": "critical" if cand.get("kind") == "sqli" else "high",
                "summary": res.reason,
                "evidence": res.evidence,
                "basis": "derived",
            })
    return out


async def confirm_second_order_idor(
    *,
    plant,          # async plant(marker) -> None: create an object carrying marker as identity 1
    read_as_other,  # async read_as_other() -> str: read the object as identity 2, return text
    marker: str | None = None,
) -> SecondOrderResult:
    """Plant-then-cross-identity-read confirmation. Identity 1 stores an object
    carrying a unique marker via `plant` (write A); identity 2 reads via B
    (`read_as_other`). If identity 2's response contains identity 1's marker, the
    stored object crosses the identity boundary -> confirmed second-order IDOR."""
    mark = marker or ("SOIDOR" + secrets.token_hex(6))
    await plant(mark)
    seen = await read_as_other() or ""
    if mark in seen:
        return SecondOrderResult(
            confirmed=True,
            reason="second-order IDOR confirmed: an object planted by one identity was read back "
                   "by a different identity",
            evidence=(f"Identity 1 stored a unique marker {mark!r} via the write; identity 2's read "
                      f"returned it -- the stored object is not scoped to its creator."))
    return SecondOrderResult(
        confirmed=False,
        reason="no second-order IDOR: the other identity did not see the planted marker",
        evidence=f"Marker {mark!r} planted as identity 1 was absent from identity 2's read.")
