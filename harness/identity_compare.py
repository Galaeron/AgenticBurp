from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

"""
Python port of burp-extension's IdentityCompareLogic.java (cross_identity_compare
/ authorization_boundary_compare decision logic). Direct, line-for-line port --
not a redesign -- so the already-proven design (source/candidate/attempt/anon
4-probe comparison with an anonymous-baseline check to rule out "this is just
a public resource") carries over exactly. Keep this in sync with the Java
original by hand; there is no shared source of truth between the two, the
same class of risk this project's own comments already flag elsewhere
(e.g. exchange_fingerprint()/exchangeFingerprint(), HarnessPanel.java's
IMPLEMENTED_BURP_CAPABILITIES).
"""


class Verdict(str, Enum):
    CONFIRMED = "CONFIRMED"
    SUPPORTED = "SUPPORTED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    INVALID = "INVALID"


# Similarity at/above this is treated as "materially the same response".
# Same value and same calibration rationale as the Java original: a
# same-resource response differing only in one volatile token (session id,
# CSRF token, timestamp) scores 0.77-0.92 trigram-Jaccard depending on body
# length, while two genuinely different resources sharing the same JSON
# shape/boilerplate score 0.43-0.50.
MATCH_THRESHOLD = 0.70


@dataclass
class Probe:
    """One observed HTTP outcome: status code + response body."""
    status: int
    body: str = ""
    # The run's exchange artifact behind this outcome ("" when it was not sent
    # through a run); never part of a comparison.
    artifact_id: str = field(default="", compare=False)

    def __post_init__(self) -> None:
        if self.body is None:
            self.body = ""


@dataclass(frozen=True)
class Evidence:
    verdict: Verdict
    confidence: float
    confirmed: bool
    summary: str
    detail: str


def _same_status(a: Probe, b: Probe) -> bool:
    return a.status == b.status


def _detail_of(*kv: object) -> str:
    parts: list[str] = []
    for i in range(0, len(kv), 2):
        v = kv[i + 1]
        vs = f"{v:.3f}" if isinstance(v, float) else str(v)
        parts.append(f"{kv[i]}={vs}")
    return " ".join(parts)


def _shingles(s: str) -> set[str]:
    n = 3
    if len(s) < n:
        return {s}
    return {s[i:i + n] for i in range(len(s) - n + 1)}


def similarity(a: Optional[str], b: Optional[str]) -> float:
    """Trigram Jaccard similarity -- see IdentityCompareLogic.similarity()'s
    own comment for why this metric was chosen over a prefix/length-ratio
    heuristic (tolerant of a single differing token like a CSRF/session
    value anywhere in the body, without scoring two different bodies of
    equal length as automatically 50% similar)."""
    if a is None:
        a = ""
    if b is None:
        b = ""
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    ga = _shingles(a)
    gb = _shingles(b)
    if not ga or not gb:
        return 0.0
    inter = ga & gb
    union = ga | gb
    return len(inter) / len(union) if union else 0.0


def evaluate(
    capability: str,
    identifier_changed: bool,
    source: Probe,
    candidate: Probe,
    attempt: Probe,
    anon: Optional[Probe],
) -> Evidence:
    """
    capability:          "cross_identity_compare" or "authorization_boundary_compare"
    identifier_changed:  whether source/candidate reference different object
                          identifiers. Required true for cross_identity_compare;
                          irrelevant for authorization_boundary_compare (same URL
                          is expected there -- there is no identifier to swap).
    source:               identity A's own original captured response. Accepted
                          for parity with the Java original but never referenced
                          below -- the Java method doesn't use it either.
    candidate:            identity B's own original captured response.
    attempt:              identity A's credentials used against B's resource.
    anon:                 unauthenticated probe of the same resource, or None if
                          one could not be sent (e.g. no way to strip auth cleanly).
    """
    if capability == "cross_identity_compare" and not identifier_changed:
        return Evidence(
            Verdict.INVALID, 0.0, False,
            "IDOR test requires the candidate to reference a different object "
            "identifier than the source request; none was found.",
            "",
        )

    if anon is None:
        matches = _same_status(attempt, candidate) and similarity(attempt.body, candidate.body) >= MATCH_THRESHOLD
        if matches:
            return Evidence(
                Verdict.SUPPORTED, 0.55, False,
                "Identity A's credentials returned a response materially matching identity B's, "
                "but no unauthenticated baseline could be captured, so a public/non-personalized "
                "resource cannot be ruled out. Treat as supporting evidence only.",
                _detail_of("statusAttempt", attempt.status, "statusCandidate", candidate.status,
                           "bodySimilarity", similarity(attempt.body, candidate.body)),
            )
        return Evidence(
            Verdict.REJECTED, 0.6, False,
            "Identity A's credentials did not reproduce identity B's response.",
            _detail_of("statusAttempt", attempt.status, "statusCandidate", candidate.status,
                       "bodySimilarity", similarity(attempt.body, candidate.body)),
        )

    anon_vs_candidate = similarity(anon.body, candidate.body)
    anon_looks_denied = (not _same_status(anon, candidate)) or anon_vs_candidate < MATCH_THRESHOLD

    if not anon_looks_denied:
        return Evidence(
            Verdict.INCONCLUSIVE, 0.3, False,
            "An unauthenticated request received materially the same response as identity B; "
            "this resource appears to be public rather than access-controlled, so a matching "
            "response from identity A is not evidence of an authorization failure.",
            _detail_of("statusAnon", anon.status, "statusCandidate", candidate.status,
                       "bodySimilarity", anon_vs_candidate),
        )

    attempt_vs_candidate = similarity(attempt.body, candidate.body)
    attempt_vs_anon = similarity(attempt.body, anon.body)
    attempt_matches_candidate = _same_status(attempt, candidate) and attempt_vs_candidate >= MATCH_THRESHOLD
    attempt_matches_anon = _same_status(attempt, anon) and attempt_vs_anon >= MATCH_THRESHOLD

    if attempt_matches_candidate and not attempt_matches_anon:
        return Evidence(
            Verdict.CONFIRMED, 0.91, True,
            "Identity A's own credentials, applied to identity B's resource, returned a response "
            "materially matching identity B's protected access. An unauthenticated probe of the "
            "same resource was denied, ruling out a public resource.",
            _detail_of("statusAttempt", attempt.status, "statusCandidate", candidate.status,
                       "statusAnon", anon.status, "attemptVsCandidate", attempt_vs_candidate,
                       "attemptVsAnon", attempt_vs_anon, "anonVsCandidate", anon_vs_candidate),
        )

    if attempt_matches_anon:
        return Evidence(
            Verdict.REJECTED, 0.8, False,
            "Identity A's attempt against identity B's resource matched the unauthenticated/denied "
            "response, not identity B's protected response -- access appears correctly restricted.",
            _detail_of("statusAttempt", attempt.status, "statusAnon", anon.status,
                       "attemptVsAnon", attempt_vs_anon),
        )

    return Evidence(
        Verdict.INCONCLUSIVE, 0.4, False,
        "Identity A's attempt matched neither identity B's protected response nor the "
        "unauthenticated baseline.",
        _detail_of("statusAttempt", attempt.status, "attemptVsCandidate", attempt_vs_candidate,
                   "attemptVsAnon", attempt_vs_anon),
    )
