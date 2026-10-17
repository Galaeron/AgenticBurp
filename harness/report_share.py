"""SC-15: evidence-first report polish + retest classification.

Presentation only, built on the SAME canonical export the rest of the reporting
stack uses -- :func:`harness.report_generator.export_issues_for_host` /
:func:`harness.report_generator.issue_exports`, which run findings through the
SC-5 report policy and :func:`harness.issues.export_issue` (redacted, secret-free,
verification state AUDITED against the proof ledger, never LLM prose). This module
adds two shareable renderings and a retest classifier over those export dicts; it
introduces no new evidence, no verification-state decision, and no store write:

* :func:`render_offline_html` -- a self-contained, single-file HTML report (inline
  CSS, no external assets, no scripts) suitable for sharing. Every field it shows
  comes from the export dict, so it agrees issue-for-issue with every other format
  and cannot promote prose to evidence.
* :func:`render_http_exports` -- a ``.http`` evidence export (VS Code REST Client /
  Burp Repeater import). Session values are placeholders, never real secrets, and
  each request is annotated with its stable issue id and expected-vs-observed note.
* :func:`classify_retests` -- classifies each original issue on a retest as
  ``fixed`` / ``still_vulnerable`` / ``inconclusive`` / ``not_run``, matched to the
  ORIGINAL issue by its stable, run-independent ``issue_id`` (so a patched-fixture
  retest links to the same issue). "fixed" requires an executed clean control
  (``controlled_negative``), per SC-1 -- a skipped/blocked/error retest is
  inconclusive, never fixed.

Because both renderers and the classifier consume the canonical export list, all
formats agree on which issues are reportable (SC-5 parity), secret-canary
fixtures stay redacted (redaction is upstream in export_issue), and unproved
prose never changes verification state (the export's audited state is rendered
verbatim). Nothing in the default pipeline calls this yet; wiring it into a live
``/report`` route or the CLI is a separate, deferred step.
"""
from __future__ import annotations

import html
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


def reportable_issue_ids(exports: list) -> list:
    """The stable issue ids in an export list, in order -- the single source of
    truth every rendered format must agree with."""
    return [e.get("issue_id", "") for e in exports]


# --------------------------------------------------------------------------
# Shareable single-file HTML
# --------------------------------------------------------------------------
_HTML_STYLE = """
:root{--fg:#1a1a1a;--muted:#5b6570;--line:#e2e6ea;--bg:#ffffff;--card:#f7f9fb;
--verified:#0a7d33;--candidate:#8a6d00;--crit:#b3261e;--accent:#0b5fff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.55 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:920px;margin:0 auto;padding:24px 16px}
h1{font-size:22px;margin:0 0 4px}
.sub{color:var(--muted);font-size:13px;margin-bottom:16px}
.banner{background:#fff8e6;border:1px solid #f0dfa8;border-radius:8px;
padding:10px 12px;font-size:13px;margin-bottom:20px}
.issue{border:1px solid var(--line);border-radius:10px;background:var(--card);
padding:16px 18px;margin:0 0 16px}
.issue h2{font-size:17px;margin:0 0 8px;line-height:1.35}
.id{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--muted)}
.badges{margin:6px 0 12px}
.badge{display:inline-block;font-size:12px;font-weight:600;border-radius:999px;
padding:2px 10px;margin:0 6px 6px 0;border:1px solid transparent}
.b-verified{background:#e7f5ec;color:var(--verified);border-color:#bfe6cd}
.b-candidate{background:#fbf3d9;color:var(--candidate);border-color:#ecdca0}
.b-sev{background:#fde8e6;color:var(--crit);border-color:#f3c4bf}
.b-plain{background:#eef1f4;color:var(--muted);border-color:#dde3e8}
.kv{margin:10px 0}.kv .k{color:var(--muted);font-size:12px;text-transform:uppercase;
letter-spacing:.03em;margin-bottom:2px}
.mono{font:12.5px ui-monospace,SFMono-Regular,Menlo,monospace;
white-space:pre-wrap;word-break:break-word;background:#fff;border:1px solid var(--line);
border-radius:6px;padding:8px 10px}
ul{margin:6px 0;padding-left:20px}li{margin:2px 0}
.ctrl-fail{color:var(--candidate)}.ctrl-ok{color:var(--verified)}
.foot{color:var(--muted);font-size:12px;margin-top:24px;border-top:1px solid var(--line);
padding-top:12px}
"""


def _esc(value) -> str:
    return html.escape("" if value is None else str(value))


def _verification_badge(export: dict) -> str:
    state = export.get("verification_state", "candidate")
    cls = "b-verified" if state == "verified" else "b-candidate"
    return f'<span class="badge {cls}">{_esc(state)}</span>'


def _controls_html(export: dict) -> str:
    refs = export.get("proof_references", []) or []
    if not refs:
        return '<div class="mono">No structured control/proof attempt is linked.</div>'
    rows = []
    for r in refs:
        verdict = (r.get("verdict") or "").strip().lower() or "no-verdict"
        clean = verdict in ("confirmed", "controlled_negative")
        cls = "ctrl-ok" if clean else "ctrl-fail"
        label = verdict if r.get("verdict") is not None else "no recorded verdict (inconclusive)"
        rows.append(f'<li><span class="{cls}">{_esc(label)}</span> '
                    f'— case <span class="id">{_esc(r.get("case_id", ""))}</span> '
                    f'proof <span class="id">{_esc(r.get("proof_id", ""))}</span></li>')
    return "<ul>" + "".join(rows) + "</ul>"


def _issue_html(export: dict) -> str:
    ev = export.get("expected_vs_observed", {}) or {}
    parts = [f'<section class="issue">',
             f'<h2>{_esc(export.get("title", "Issue"))}</h2>',
             f'<div class="id">issue {_esc(export.get("issue_id", ""))}</div>',
             '<div class="badges">',
             _verification_badge(export),
             f'<span class="badge b-sev">{_esc(export.get("severity", "info"))}</span>',
             f'<span class="badge b-plain">confidence {_esc(export.get("confidence", 0))}</span>',
             f'<span class="badge b-plain">{_esc(export.get("authorization_boundary", ""))}</span>',
             '</div>']

    def kv(label, value_html):
        return f'<div class="kv"><div class="k">{_esc(label)}</div>{value_html}</div>'

    parts.append(kv("Impact", f'<div>{_esc(export.get("impact", ""))}</div>'))
    parts.append(kv("Expected", f'<div>{_esc(ev.get("expected", ""))}</div>'))
    parts.append(kv("Observed", f'<div class="mono">{_esc(ev.get("observed", ""))}</div>'))
    parts.append(kv("Reproduction", "<ul>" + "".join(
        f"<li>{_esc(s)}</li>" for s in export.get("request_sequence", []) or []) + "</ul>"))
    parts.append(kv("Controls / proofs", _controls_html(export)))
    parts.append(kv("Redacted evidence", f'<div class="mono">{_esc(export.get("evidence", ""))}</div>'))
    parts.append(kv("Affected instances", "<ul>" + "".join(
        f'<li class="mono">{_esc(u)}</li>' for u in export.get("affected_instances", []) or []) + "</ul>"))
    parts.append(kv("Limitations", "<ul>" + "".join(
        f"<li>{_esc(x)}</li>" for x in export.get("limitations", []) or []) + "</ul>"))
    artifacts = export.get("artifacts", {}) or {}
    parts.append(kv("Artifacts", "<ul>"
                    + f'<li>replayable: {_esc(bool(artifacts.get("replayable")))}</li>'
                    + "".join(f"<li>{_esc(m)}</li>" for m in artifacts.get("missing", []) or [])
                    + "</ul>"))
    parts.append(kv("Retest", f'<div>{_esc(export.get("retest", ""))}</div>'))
    parts.append("</section>")
    return "".join(parts)


def render_offline_html(exports: list, *, host: str = "", generated_at: datetime | None = None,
                        title: str = "Security assessment") -> str:
    """A self-contained, shareable HTML report of the given issue exports. No
    external assets or scripts; every value is HTML-escaped and comes straight
    from the (redacted, policy-gated, verification-audited) export dict."""
    ts = (generated_at or datetime.now(timezone.utc)).isoformat(timespec="seconds")
    issues_html = "".join(_issue_html(e) for e in exports) or \
        '<section class="issue"><h2>No reportable issues</h2></section>'
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        f"<title>{_esc(title)}</title><style>{_HTML_STYLE}</style></head><body><div class=\"wrap\">"
        f"<h1>{_esc(title)}</h1>"
        f'<div class="sub">Host {_esc(host or "(unspecified)")} · generated {_esc(ts)} · '
        f'{len(exports)} reportable issue(s)</div>'
        '<div class="banner"><strong>Authorized scope only.</strong> Findings are shown with '
        'their audited verification state (<em>verified</em> = an executed control reproduced it; '
        '<em>candidate</em> = not oracle-verified). Unproved leads are excluded by the report '
        'policy. Evidence is redacted; replay from the linked proof artifacts using your own '
        'session values.</div>'
        f"{issues_html}"
        '<div class="foot">Rendered from the canonical issue export (SC-5 policy). '
        'Verification state is audited against the proof ledger, not derived from model prose.</div>'
        "</div></body></html>"
    )


# --------------------------------------------------------------------------
# .http evidence export (REST Client / Burp Repeater import)
# --------------------------------------------------------------------------
def _http_block(export: dict) -> str:
    ev = export.get("expected_vs_observed", {}) or {}
    instances = export.get("affected_instances", []) or []
    target = instances[0] if instances else (
        f'{export.get("host", "")}{export.get("endpoint_family", "") or "/"}')
    if not target.lower().startswith(("http://", "https://")):
        target = "https://" + target.lstrip("/") if target else "https://REPLACE-HOST/"
    method = (export.get("method") or "GET").upper()
    aliases = export.get("principal_aliases", {}) or {}
    alias = next(iter(aliases), "P1")
    lines = [
        f'### issue {export.get("issue_id", "")} — {export.get("title", "")}',
        f'# class: {export.get("vulnerability_class", "")}  severity: {export.get("severity", "")}'
        f'  verification: {export.get("verification_state", "")}  confidence: {export.get("confidence", "")}',
        f'# impact: {export.get("impact", "")}',
        f'# expected: {ev.get("expected", "")}',
        f'# observed: {ev.get("observed", "")}',
        '# NOTE: raw request bytes are not stored; replay from the linked proof/exchange.',
        f'# Fill <<SESSION:{alias}>> with your OWN authorized session value (never a captured secret).',
        f'{method} {target}',
        f'Authorization: <<SESSION:{alias}>>',
        '',
    ]
    # Strip any stray newlines from interpolated fields so the .http stays well-formed.
    return "\n".join(ln.replace("\n", " ").replace("\r", " ") for ln in lines)


def render_http_exports(exports: list, *, host: str = "",
                        generated_at: datetime | None = None) -> str:
    """A ``.http`` evidence file (one request block per issue) importable into a
    REST client or Burp Repeater. Session values are placeholders; nothing here
    carries a captured secret (the source export is already redacted)."""
    ts = (generated_at or datetime.now(timezone.utc)).isoformat(timespec="seconds")
    header = (f"# Evidence export (.http) — host {host or '(unspecified)'} — generated {ts}\n"
              f"# {len(exports)} reportable issue(s). Authorized scope only; "
              f"fill session placeholders with your own credentials.\n")
    if not exports:
        return header + "\n# No reportable issues.\n"
    return header + "\n" + "\n".join(_http_block(e) for e in exports)


# --------------------------------------------------------------------------
# Retest classification
# --------------------------------------------------------------------------
class RetestOutcome(str, Enum):
    FIXED = "fixed"
    STILL_VULNERABLE = "still_vulnerable"
    INCONCLUSIVE = "inconclusive"
    NOT_RUN = "not_run"


@dataclass
class RetestResult:
    issue_id: str
    outcome: RetestOutcome
    basis: str
    retest_verdicts: list = field(default_factory=list)
    original_verification_state: str = ""
    covered: bool = False

    def to_dict(self) -> dict:
        return {
            "issue_id": self.issue_id, "outcome": self.outcome.value, "basis": self.basis,
            "retest_verdicts": list(self.retest_verdicts), "covered": self.covered,
            "original_verification_state": self.original_verification_state,
        }


def classify_retest_issue(retest_export: dict, *,
                          original_verification_state: str = "") -> RetestResult:
    """Classify ONE issue's retest from its canonical export (same stable
    issue_id as the original). Precedence mirrors the append-only proof ledger:
    a single re-confirmation outranks a clean control, which outranks an
    inconclusive attempt. "fixed" requires an executed clean control
    (controlled_negative) -- a blocked/error/skipped retest is inconclusive."""
    issue_id = retest_export.get("issue_id", "")
    refs = retest_export.get("proof_references", []) or []
    verdicts = [(r.get("verdict") or "").strip().lower() for r in refs if r.get("verdict")]
    confirmed_flag = bool(retest_export.get("confirmed"))

    if confirmed_flag or any(v == "confirmed" for v in verdicts):
        outcome, basis = RetestOutcome.STILL_VULNERABLE, "a leg re-confirmed the issue on retest"
    elif any(v == "controlled_negative" for v in verdicts):
        outcome, basis = RetestOutcome.FIXED, "an executed control was clean on retest (no reproduction)"
    elif verdicts:
        outcome = RetestOutcome.INCONCLUSIVE
        basis = f"retest attempts were inconclusive: {sorted(set(verdicts))}"
    else:
        outcome = RetestOutcome.INCONCLUSIVE
        basis = "issue re-observed on retest but no executed control was recorded"
    return RetestResult(issue_id, outcome, basis, verdicts,
                        original_verification_state=original_verification_state, covered=True)


def classify_retests(original_exports: list, retest_exports: list) -> list:
    """Classify every ORIGINAL issue against a retest run's exports, matched by
    the stable, run-independent issue_id (so a patched-fixture retest -- new
    case/proof ids, same coordinates -- links to the same issue). An original
    issue with no matching retest export is ``not_run``. Returns one
    :class:`RetestResult` per original issue, in the original order."""
    by_id = {e.get("issue_id", ""): e for e in retest_exports}
    results = []
    for original in original_exports:
        iid = original.get("issue_id", "")
        retest = by_id.get(iid)
        if retest is None:
            results.append(RetestResult(
                iid, RetestOutcome.NOT_RUN, "no retest covered this issue",
                original_verification_state=original.get("verification_state", ""), covered=False))
        else:
            results.append(classify_retest_issue(
                retest, original_verification_state=original.get("verification_state", "")))
    return results
