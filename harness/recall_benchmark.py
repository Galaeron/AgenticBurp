"""
Recall benchmark harness -- Phase 0.3.

Scores a pipeline run against a KNOWN, self-authored ground-truth set of planted
vulnerabilities, so recall is measured rather than assumed -- the recall
counterpart to the precision floor. For each planted vuln it reports one of:

  - confirmed:            a matching finding the harness actively CONFIRMED
  - detected_unconfirmed: a matching finding, but only a hypothesis (no leg proved it)
  - missed:               no matching finding at all

and, for each confirmed item, a PROVENANCE verdict:

  - earned: confirmed via the leg the vuln was MEANT to be confirmed by
  - lucky:  confirmed via some OTHER leg (e.g. cross_identity catching an IDOR by
            sequential-id coincidence rather than the intended log-leak path)

Counting "was this class confirmed anywhere in the report" overstates recall;
provenance keeps it honest -- a lucky confirm proves the bug exists but not that
the intended detection path works.

Ground truth is authored by hand against a fixture you control -- NEVER read from
a blind target's answer key (hazard #2). Pure and deterministic: no network, no
model. Matching reuses categories.canonicalize (class) and engagement.normalize_path
(endpoint), so a finding labelled "insecure direct object reference" on
/api/tickets/7 matches a planted "idor" on /api/tickets/{id}.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from harness import categories
from harness.engagement import normalize_path

CONFIRMED = "confirmed"
DETECTED = "detected_unconfirmed"
MISSED = "missed"

EARNED = "earned"
LUCKY = "lucky"
# Weakness #6: a confirmation whose leg provenance is NOT known (nothing named a
# leg in the evidence) is UNKNOWN -- it must not be called "lucky" (which claims an
# OTHER leg proved it). Unknown means the metadata is missing, not that the intended
# path failed.
UNKNOWN = "unknown"

# "|| cross-identity CONFIRMED: ..." is how a leg stamps its own confirmation into
# a finding's evidence (orchestrator._apply). Recover the leg name from that.
_LEG_RX = re.compile(r"\b([a-z][a-z0-9]*(?:-[a-z0-9]+)*)\s+CONFIRMED\b")
# hyphenated evidence names -> the underscored leg/class tokens used elsewhere.
_LEG_ALIASES = {
    "cross-identity": "cross_identity", "browser-xss": "browser_xss",
    "jwt-forge": "jwt_forge", "command-injection": "command_injection",
    "path-traversal": "path_traversal", "open-redirect": "open_redirect",
}


@dataclass(frozen=True)
class PlantedVuln:
    """One vulnerability a fixture is known to contain. `intended_confirmation`
    is the leg that SHOULD confirm it (the provenance oracle) -- e.g.
    "cross_identity", "sqlmap", "xxe"; leave empty to skip the earned/lucky
    judgment. `aliases` are extra acceptable class labels beyond what
    categories.canonicalize already folds together."""
    id: str
    vulnerability_class: str
    path: str
    intended_confirmation: str = ""
    aliases: tuple[str, ...] = ()


@dataclass
class ScoredItem:
    planted: PlantedVuln
    status: str                       # CONFIRMED | DETECTED | MISSED
    matched: list = field(default_factory=list)   # the finding dicts that matched
    provenance: str = ""              # EARNED | LUCKY | "" (only when CONFIRMED)
    provenance_reason: str = ""

    def to_dict(self) -> dict:
        return {"id": self.planted.id, "class": self.planted.vulnerability_class,
                "path": self.planted.path, "status": self.status,
                "provenance": self.provenance, "provenance_reason": self.provenance_reason,
                "matched_findings": len(self.matched)}


@dataclass
class RecallScore:
    items: list = field(default_factory=list)   # ScoredItem, one per planted vuln

    @property
    def total(self) -> int:
        return len(self.items)

    def _count(self, status: str) -> int:
        return sum(1 for it in self.items if it.status == status)

    @property
    def confirmed(self) -> int:
        return self._count(CONFIRMED)

    @property
    def detected_unconfirmed(self) -> int:
        return self._count(DETECTED)

    @property
    def missed(self) -> int:
        return self._count(MISSED)

    @property
    def lucky_confirms(self) -> int:
        return sum(1 for it in self.items if it.status == CONFIRMED and it.provenance == LUCKY)

    @property
    def unknown_provenance_confirms(self) -> int:
        # #6: confirmed but with no leg named -- distinct from lucky.
        return sum(1 for it in self.items if it.status == CONFIRMED and it.provenance == UNKNOWN)

    @property
    def earned(self) -> int:
        """2026-09-17 coverage-recovery plan, Step 4: the honest headline
        number -- confirmed via the SPECIFIC leg the planted vuln was meant to
        be confirmed by, not "confirmed by something, anything." Reported
        `confirmed` counts have repeatedly overstated this (a run reporting
        9/13 confirmed had only 4/13 earned once lucky/unknown-provenance
        confirms were excluded) -- `earned` is what a claim of real detection-
        path coverage should be measured against, not `confirmed`.

        Also excludes a class with NO automated exploit-confirmation leg at
        all (confirmation_gate.leg_tier == "none" -- CORS, CSP, verbose-error,
        ...): a passive header/content observation is real and stays visible
        as CONFIRMED/EARNED-provenance on its own item, but it never counts
        toward earned EXPLOIT recall, regardless of what a ground-truth entry
        happens to declare as its "intended" leg."""
        from harness.confirmation_gate import leg_tier
        return sum(1 for it in self.items
                  if it.status == CONFIRMED and it.provenance == EARNED
                  and leg_tier(it.planted.vulnerability_class) != "none")

    def summary_line(self) -> str:
        n = self.total
        s = (f"{self.earned}/{n} earned, {self.confirmed}/{n} confirmed, {self.detected_unconfirmed}/{n} "
             f"detected-unconfirmed, {self.missed}/{n} missed")
        if self.lucky_confirms:
            s += f" ({self.lucky_confirms} confirmed by luck, not the intended path)"
        if self.unknown_provenance_confirms:
            s += f" ({self.unknown_provenance_confirms} confirmed with UNKNOWN provenance)"
        return s

    def to_dict(self) -> dict:
        return {"total": self.total, "earned": self.earned, "confirmed": self.confirmed,
                "detected_unconfirmed": self.detected_unconfirmed, "missed": self.missed,
                "lucky_confirms": self.lucky_confirms,
                "unknown_provenance_confirms": self.unknown_provenance_confirms,
                "summary": self.summary_line(),
                "items": [it.to_dict() for it in self.items]}


def _canon_class(raw: str | None) -> str:
    """Canonical class if recognised, else a stable lowercased fallback so two
    identical-but-unmapped labels still compare equal."""
    return categories.canonicalize(raw) or (raw or "").strip().lower()


def _finding_dict(f) -> dict:
    if isinstance(f, dict):
        return f
    if hasattr(f, "model_dump"):
        return f.model_dump()
    return dict(getattr(f, "__dict__", {}) or {})


def _finding_path(f: dict) -> str:
    return normalize_path(f.get("path") or f.get("url") or "")


def _class_matches(planted: PlantedVuln, f: dict) -> bool:
    fc = _canon_class(f.get("vulnerability_class"))
    if not fc:
        return False
    accepted = {_canon_class(planted.vulnerability_class)}
    accepted.update(_canon_class(a) for a in planted.aliases)
    return fc in accepted


def _matches(planted: PlantedVuln, f: dict) -> bool:
    return (_finding_path(f) == normalize_path(planted.path)) and _class_matches(planted, f)


def confirmation_leg_of(f: dict) -> str:
    """The confirmation leg that proved a finding.

    Prefers the STRUCTURED `confirmed_by_leg` field (2026-09-17 coverage-
    recovery plan, Step 4), stamped by _validate_findings/
    coverage_confirmation_finding at the same moment as proof_id -- reliable
    regardless of how a leg happened to phrase its evidence text. Falls back,
    for legacy findings with no structured stamp, to the evidence stamp
    ("... || cross-identity CONFIRMED: ..."), an explicit proactive_leg field,
    or a validation_hints prefix. Empty when nothing names a leg. Normalised
    to the underscored token form (cross_identity, jwt_forge)."""
    structured = f.get("confirmed_by_leg")
    if structured:
        leg = str(structured).strip().lower()
        return _LEG_ALIASES.get(leg, leg)
    ev = f.get("evidence") or ""
    m = _LEG_RX.search(ev)
    if m:
        leg = m.group(1).lower()
        return _LEG_ALIASES.get(leg, leg)
    pl = f.get("proactive_leg")
    if pl:
        return str(pl).strip().lower()
    for h in f.get("validation_hints", []) or []:
        if isinstance(h, str) and ":" in h:
            return h.split(":", 1)[0].strip().lower()
    return ""


def _provenance(planted: PlantedVuln, confirming: dict) -> tuple[str, str]:
    intended = (planted.intended_confirmation or "").strip().lower()
    if not intended:
        return "", "no intended-confirmation leg declared for this planted vuln"
    leg = confirmation_leg_of(confirming)
    if not leg:
        # Weakness #6: missing leg provenance is UNKNOWN, not lucky.
        return UNKNOWN, (f"confirmed, but no leg is named in the evidence -- provenance UNKNOWN "
                         f"(cannot say whether the intended '{intended}' path proved it)")
    if leg == intended:
        return EARNED, f"confirmed via the intended leg '{intended}'"
    return LUCKY, (f"confirmed via '{leg}', not the intended '{intended}' "
                   f"-- the bug is real but the intended detection path is unproven")


def _best_proof(planted: PlantedVuln, confirmed: list[dict]) -> dict:
    """Deterministic best-proof selection among several confirming findings (#6):
    prefer one proven by the INTENDED leg (earned), then any with a KNOWN leg
    (lucky over unknown), else the first -- so scoring never hinges on list order."""
    intended = (planted.intended_confirmation or "").strip().lower()
    earned = [f for f in confirmed if confirmation_leg_of(f) == intended and intended]
    if earned:
        return earned[0]
    known = [f for f in confirmed if confirmation_leg_of(f)]
    return known[0] if known else confirmed[0]


def score_run(ground_truth, findings) -> RecallScore:
    """Score a set of run findings against the planted ground truth. `findings`
    are finding dicts (or Finding objects) each carrying a url/path and a
    vulnerability_class; use the findings_from_* adapters to extract them from an
    AnalysisResponse or an investigate_engagement worklist."""
    fs = [_finding_dict(f) for f in (findings or [])]
    items: list[ScoredItem] = []
    for pv in ground_truth:
        matched = [f for f in fs if _matches(pv, f)]
        confirmed = [f for f in matched if f.get("confirmed")]
        if confirmed:
            prov, reason = _provenance(pv, _best_proof(pv, confirmed))
            items.append(ScoredItem(pv, CONFIRMED, matched, prov, reason))
        elif matched:
            items.append(ScoredItem(pv, DETECTED, matched))
        else:
            items.append(ScoredItem(pv, MISSED, []))
    return RecallScore(items)


# --- adapters: pull url-stamped finding dicts from real run outputs -----------

def findings_from_analysis(exchange, resp) -> list[dict]:
    """Findings from an AnalysisResponse, each stamped with the analyzed
    exchange's url (Finding carries no url of its own, but the scorer needs the
    endpoint context to match a planted vuln)."""
    url = getattr(exchange, "url", "") or ""
    out: list[dict] = []
    for report in getattr(resp, "agent_reports", []) or []:
        for f in report.findings:
            d = _finding_dict(f)
            d.setdefault("url", url)
            out.append(d)
    return out


def findings_from_engagement(result: dict) -> list[dict]:
    """Findings from an investigate_engagement result dict: flatten the worklist
    endpoints' findings, stamping each with its endpoint path."""
    out: list[dict] = []
    for ep in (result or {}).get("worklist", []) or []:
        path = ep.get("path", "")
        for fd in ep.get("findings", []) or []:
            d = dict(fd)
            d.setdefault("path", path)
            out.append(d)
    return out
