"""HU-5: the end-of-run handoff and the target change log.

Two records per run, both pure bookkeeping: nothing here sends a request.

* `ChangeLog` -- every non-read send (POST/PUT/PATCH/DELETE/...) whose exchange
  ended 2xx: method, path, object ref, capability, case, and its restore status.
  `TargetTransport.execute` records into the run's log (always on, in memory); the
  workflow engine marks a write `restored` or `restore_failed` when the cleanup step
  that undoes it runs. A failed restore is an error-level entry: it is logged at
  ERROR, published on the activity feed at level error, and listed first in the
  handoff and the report section.

* `RunHandoff` -- what the run did NOT test, ranked by value, written to disk at
  every phase boundary so a cancelled or timed-out run still leaves one:
  unreviewed captures (by review tier), untouched worklist nodes (worklist rank),
  legs skipped with the reason (count), and the phases that never ran (run order).
  `lead_recommendations` is a named slot for the manual checks HU-2's leads give;
  this module fills nothing there itself.

Artifacts (beside the run manifest, in `runs.output_dir`):
  <run_id>.handoff.json   rewritten atomically on each update
  <run_id>.changes.json   the change log, rewritten atomically on each change

Defaults: recording is always on (no traffic, small). Persisting needs an output
directory, which the server attaches per investigation job. The Markdown report
section is OFF unless `reporting.handoff_section` is true, so a default report is
unchanged.
"""
from __future__ import annotations

import contextlib
import contextvars
import json
import logging
import os
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

log = logging.getLogger("harness.run_handoff")

__all__ = ["ChangeLog", "RunHandoff", "RUN_PHASES", "attach", "finish", "for_run",
           "restore_scope", "mark_restore", "report_section", "latest_for_host"]

SCHEMA_VERSION = 1

# The phases investigate_engagement opens with `_instr.phases.begin(...)`, in run
# order (test_run_handoff checks this list against orchestrator_chain's source).
RUN_PHASES = ("discovery", "header_audit", "business_context", "experiments", "worklist",
              "recrawl", "capture_review", "chain_rounds", "second_order", "coverage_drive",
              "retry_rounds", "final_pass", "experiments_final", "finalise")
# Opened only when their feature is on (engagement.recrawl / engagement.retry_rounds /
# engagement.final_pass), or, for experiments_final, only while its deadline (the
# coverage deadline, and the investigation deadline less the finalise reserve) has
# not passed; otherwise it is recorded as skipped, with why (R11-4b).
CONDITIONAL_PHASES = frozenset({"recrawl", "retry_rounds", "final_pass", "experiments_final"})
TERMINAL_PHASE = "finalise"
# Sends after this phase begins count as testing a worklist node.
_TESTING_FROM = "worklist"

READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})

RESTORE_NONE = "none_declared"      # the write has no registered cleanup
RESTORED = "restored"
RESTORE_FAILED = "restore_failed"   # error level
RESTORE_SEND = "restore_send"       # this send IS a cleanup step

_LIST_CAP = 200          # per untested category kept in the handoff file
_SAMPLE_PATHS = 5

_restoring: contextvars.ContextVar[str] = contextvars.ContextVar("harness_restore_scope", default="")


@contextlib.contextmanager
def restore_scope(ref: str = "cleanup"):
    """Sends made in this block are cleanup sends (recorded as `restore_send`)."""
    token = _restoring.set(ref or "cleanup")
    try:
        yield
    finally:
        _restoring.reset(token)


def _redacted_path(url: str) -> str:
    try:
        from harness import security
        url = security.redact_secrets_in_url(url or "")
    except Exception:
        pass
    try:
        return urlsplit(url).path or "/"
    except Exception:
        return "/"


def _netloc(url: str) -> str:
    try:
        return (urlsplit(url or "").netloc or "").lower()
    except Exception:
        return ""


def object_ref(path: str, response_body: str | None = None) -> str:
    """The object a write touched: the last id-shaped path segment (the same rule
    engagement.normalize_path collapses to {id}), else a top-level scalar `id` in a
    JSON response (a create), else ""."""
    try:
        from harness.engagement import template_object_ids
        concrete = (path or "").split("/")
        templ = template_object_ids(path or "").split("/")
        if len(concrete) == len(templ):
            ids = [c for c, t in zip(concrete, templ) if t == "{id}" and c != "{id}"]
            if ids:
                return ids[-1]
    except Exception:
        pass
    if response_body:
        try:
            data = json.loads(response_body[:65536])
        except Exception:
            data = None
        if isinstance(data, dict):
            inner = data.get("data") if isinstance(data.get("data"), dict) else data
            value = inner.get("id")
            if isinstance(value, (int, str)) and not isinstance(value, bool) and str(value):
                return f"created:{str(value)[:64]}"
    return ""


def _atomic_write(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# Change log
# ---------------------------------------------------------------------------

class ChangeLog:
    """The run's target change log. Thread-safe; never raises into a send."""

    def __init__(self, run_id: str = ""):
        self.run_id = run_id
        self._entries: list[dict] = []
        self._lock = threading.Lock()
        self.path: Path | None = None   # set by attach(); None keeps it in memory

    def record_send(self, *, method: str, url: str, status: int | None, capability: str = "",
                    case_ref: str = "", artifact_id: str = "", principal: str = "",
                    final_url: str = "", response_body: str | None = None) -> dict | None:
        """Record one answered send if it is a non-read method that ended 2xx."""
        method = (method or "GET").upper()
        if method in READ_METHODS or status is None or not 200 <= int(status) < 300:
            return None
        path = _redacted_path(url)
        restoring = _restoring.get()
        entry = {
            "ts": time.time(), "run_id": self.run_id, "method": method, "path": path,
            "host": _netloc(url), "object_ref": object_ref(path, response_body),
            "capability": capability or "", "case_ref": case_ref or "",
            "artifact_id": artifact_id or "", "principal": principal or "", "status": int(status),
            "restore_status": RESTORE_SEND if restoring else RESTORE_NONE,
            "restore_detail": restoring or "", "level": "info",
        }
        if final_url and final_url != url:
            entry["redirected_to"] = _redacted_path(final_url)
        with self._lock:
            entry["seq"] = len(self._entries) + 1
            self._entries.append(entry)
        self._persist()
        return entry

    def mark_restore(self, artifact_ids, *, ok: bool, detail: str = "") -> int:
        """Set the restore status of the writes made by `artifact_ids`. Returns the
        number of entries changed. A failed restore is logged at ERROR."""
        ids = {a for a in (artifact_ids or ()) if a}
        if not ids:
            return 0
        changed: list[dict] = []
        with self._lock:
            for entry in self._entries:
                if entry["artifact_id"] in ids and entry["restore_status"] in (RESTORE_NONE, RESTORE_FAILED):
                    entry["restore_status"] = RESTORED if ok else RESTORE_FAILED
                    entry["restore_detail"] = (detail or "")[:300]
                    entry["level"] = "info" if ok else "error"
                    changed.append(dict(entry))
        for entry in changed:
            if entry["level"] == "error":
                msg = (f"RESTORE FAILED: {entry['method']} {entry['path']} "
                       f"(object {entry['object_ref'] or '?'}, {entry['capability']}) "
                       f"was not undone: {entry['restore_detail'] or 'cleanup did not complete'}")
                log.error(msg)
                try:
                    from harness import activity_feed
                    activity_feed.publish("note", msg, level="error", change=entry)
                except Exception:
                    pass
        if changed:
            self._persist()
        return len(changed)

    def note_object(self, artifact_ids, *, object_ref: str = "", detail: str = "") -> int:
        """Name the object the writes made by `artifact_ids` created when the send's
        own answer did not (`object_ref`), and why a write with no registered
        cleanup was left in place (`detail`). The restore status is unchanged."""
        ids = {a for a in (artifact_ids or ()) if a}
        if not ids or not (object_ref or detail):
            return 0
        changed = 0
        with self._lock:
            for entry in self._entries:
                if entry["artifact_id"] not in ids:
                    continue
                if object_ref and not entry["object_ref"]:
                    entry["object_ref"] = object_ref[:300]
                if detail and entry["restore_status"] == RESTORE_NONE:
                    entry["restore_detail"] = detail[:300]
                changed += 1
        if changed:
            self._persist()
        return changed

    def entries(self) -> list[dict]:
        with self._lock:
            return [dict(e) for e in self._entries]

    def failed_restores(self) -> list[dict]:
        return [e for e in self.entries() if e["restore_status"] == RESTORE_FAILED]

    def summary(self) -> dict:
        counts: dict[str, int] = {}
        for e in self.entries():
            counts[e["restore_status"]] = counts.get(e["restore_status"], 0) + 1
        return {"writes": sum(counts.values()), "by_restore_status": counts,
                "restore_failed": counts.get(RESTORE_FAILED, 0)}

    def _persist(self) -> None:
        if self.path is None:
            return
        try:
            _atomic_write(self.path, {"schema_version": SCHEMA_VERSION, "run_id": self.run_id,
                                      "entries": self.entries()})
        except Exception as exc:   # bookkeeping; never fail the send
            log.warning("change log persistence failed (%s)", type(exc).__name__)


# ---------------------------------------------------------------------------
# Handoff
# ---------------------------------------------------------------------------

class RunHandoff:
    """The untested surface of one run, persisted as it changes."""

    def __init__(self, run_id: str, *, host: str = "", base_url: str = "",
                 output_dir: Path | str | None = None, change_log: ChangeLog | None = None,
                 clock=time.time):
        self.run_id = run_id
        self.host = (host or "").lower()
        self.base_url = base_url or ""
        self.netloc = _netloc(base_url)
        self.change_log = change_log if change_log is not None else ChangeLog(run_id)
        self.path = Path(output_dir) / f"{run_id}.handoff.json" if output_dir else None
        self._clock = clock
        self._lock = threading.RLock()
        self.started_at = clock()
        self.status = "running"
        self._phases_begun: list[str] = []
        self._phases_ended: set[str] = set()
        self._phases_aborted: set[str] = set()
        self._phases_skipped: dict[str, str] = {}   # phase -> why it was passed over
        self._captures: dict[str, dict] = {}     # observation key -> pending capture
        self._captures_enumerated = False
        self._state = None
        self._touched: set[tuple[str, str]] = set()
        self._skipped: dict[tuple[str, str], dict] = {}
        self._worklist_skipped: list[dict] = []
        self.lead_recommendations: dict = {
            "status": "not_provided",
            "note": "Slot for the manual checks HU-2's leads recommend "
                    "(GET /engagement/{host}/leads); not filled by this run.",
            "items": []}
        self._last_write = 0.0

    # -- events -------------------------------------------------------------

    def phase_event(self, event: str, name: str, reason: str | None = None) -> None:
        with self._lock:
            if event == "skip":
                self._phases_skipped[name] = reason or ""
            elif event == "begin":
                if name not in self._phases_begun:
                    self._phases_begun.append(name)
            elif event == "end":
                self._phases_ended.add(name)
                self._phases_aborted.discard(name)
            elif event == "abort":
                self._phases_aborted.add(name)
        self.persist()

    def attach_state(self, state) -> None:
        """The engagement state whose worklist the untouched nodes are read from."""
        self._state = state

    def note_captures(self, captured, seen=None) -> None:
        """Captures not yet reviewed: every capture of `captured` that review_frontier
        would still offer, minus those in `seen` (reviewed or covered)."""
        try:
            from harness.assessment_health import capture_tier, observation_key, review_frontier, TIER_NAMES
            from harness.models import HttpExchange
        except Exception:
            return
        seen_set = set(seen or ())
        pending: dict[str, dict] = {}
        for cap in review_frontier(list(captured or []), seen=set(seen_set)):
            try:
                ex = cap if isinstance(cap, HttpExchange) else HttpExchange(**cap)
            except Exception:
                continue
            tier = capture_tier(ex)
            pending[observation_key(ex)] = {
                "method": (ex.method or "GET").upper(), "path": _redacted_path(ex.url),
                "status": ex.response_status, "tier": tier, "tier_name": TIER_NAMES[tier]}
        with self._lock:
            for key in seen_set:
                self._captures.pop(key, None)
            self._captures.update(pending)
            self._captures_enumerated = True
        self.persist()

    def note_send(self, *, method: str, url: str, executed: bool, outcome: str = "",
                  reason: str = "", capability: str = "") -> None:
        method = (method or "GET").upper()
        if executed:
            with self._lock:
                testing = _TESTING_FROM in self._phases_begun
            if testing:
                try:
                    from harness.engagement import normalize_path
                    key = (method, normalize_path(url))
                except Exception:
                    return
                with self._lock:
                    self._touched.add(key)
            return
        why = (reason or outcome or "not sent").strip()[:200]
        key = (capability or "unknown", why)
        with self._lock:
            row = self._skipped.setdefault(key, {"capability": key[0], "reason": why,
                                                 "outcome": outcome, "count": 0, "examples": []})
            row["count"] += 1
            example = f"{method} {_redacted_path(url)}"
            if len(row["examples"]) < _SAMPLE_PATHS and example not in row["examples"]:
                row["examples"].append(example)
        self.persist(throttle=1.0)

    def set_lead_recommendations(self, items: list[dict], *, source: str = "") -> None:
        self.lead_recommendations = {"status": "provided", "source": source,
                                     "items": list(items or [])}
        self.persist()

    def finish(self, status: str, result: dict | None = None) -> None:
        with self._lock:
            self.status = status
            summary = (result or {}).get("worklist_summary") or {}
            self._worklist_skipped = [
                {"method": (s.get("method") or "GET").upper(), "path": s.get("path") or "",
                 "reason": s.get("reason") or ""}
                for s in (summary.get("skipped") or []) if isinstance(s, dict)][:_LIST_CAP]
        self.persist()

    # -- views --------------------------------------------------------------

    @property
    def completed(self) -> bool:
        return TERMINAL_PHASE in self._phases_ended

    def _phases(self) -> dict:
        begun = list(self._phases_begun)
        ended = set(self._phases_ended)
        known = [p for p in begun if p in RUN_PHASES]
        interrupted = [p for p in begun if p not in ended or p in self._phases_aborted]
        skipped = {p: why for p, why in self._phases_skipped.items() if p not in begun}
        passed = set(begun) | set(skipped)
        if self.completed:
            not_run: list[dict] = []
            not_applicable = [p for p in RUN_PHASES if p not in passed]
        else:
            last = max((RUN_PHASES.index(p) for p in [*known, *skipped] if p in RUN_PHASES),
                       default=-1)
            not_run = [{"phase": p, "conditional": p in CONDITIONAL_PHASES}
                       for p in RUN_PHASES[last + 1:]]
            not_applicable = [p for p in RUN_PHASES[:last + 1] if p not in passed]
        return {"begun": begun, "completed": sorted(ended & set(begun), key=begun.index),
                "interrupted": interrupted, "not_run": not_run,
                "not_applicable": not_applicable,
                # Passed over, with why (R11-4b: experiments_final past its deadline).
                "skipped": [{"phase": p, "reason": why} for p, why in skipped.items()],
                "run_completed": self.completed}

    def _untouched_nodes(self) -> list[dict]:
        state = self._state
        if state is None:
            return []
        try:
            nodes = state.worklist(max(1, len(getattr(state, "endpoints", {}) or {})))
        except Exception:
            return []
        with self._lock:
            touched = set(self._touched)
        out = []
        for rank, node in enumerate(nodes, 1):
            key = ((node.get("method") or "GET").upper(), node.get("path") or "/")
            if key in touched or node.get("status") == "validated":
                continue
            out.append({"method": key[0], "path": key[1], "worklist_rank": rank,
                        "status": node.get("status"),
                        "findings": len(node.get("findings") or [])})
        return out[:_LIST_CAP]

    def snapshot(self) -> dict:
        with self._lock:
            captures = sorted(self._captures.values(),
                              key=lambda c: (c["tier"], c["method"] in READ_METHODS, c["path"]))
            skipped = sorted(self._skipped.values(), key=lambda r: (-r["count"], r["capability"]))
            phases = self._phases()
            enumerated = self._captures_enumerated
            worklist_skipped = list(self._worklist_skipped)
        changes = self.change_log.summary()
        failed = self.change_log.failed_restores()
        return {
            "schema_version": SCHEMA_VERSION, "run_id": self.run_id, "host": self.host,
            "netloc": self.netloc, "base_url": self.base_url, "status": self.status,
            "started_at": self.started_at, "updated_at": self._clock(),
            "phases": phases,
            # Ranked by value, highest first within each list; the lists themselves are
            # in the order a tester should pick up the work.
            "untested": {
                "unreviewed_captures": {"enumerated": enumerated, "count": len(captures),
                                        "items": captures[:_LIST_CAP]},
                "untouched_worklist_nodes": self._untouched_nodes(),
                "skipped_legs": skipped[:_LIST_CAP],
                "worklist_skipped": worklist_skipped,
                "phases_not_run": phases["not_run"],
            },
            "lead_recommendations": self.lead_recommendations,
            "changes": {**changes, "failed_restores": failed,
                        "log": str(self.change_log.path) if self.change_log.path else None},
        }

    def persist(self, *, throttle: float = 0.0) -> None:
        if self.path is None:
            return
        now = time.monotonic()
        if throttle and now - self._last_write < throttle:
            return
        self._last_write = now
        try:
            _atomic_write(self.path, self.snapshot())
        except Exception as exc:
            log.warning("handoff persistence failed (%s)", type(exc).__name__)


# ---------------------------------------------------------------------------
# Run wiring (RunContext attributes: change_log, handoff)
# ---------------------------------------------------------------------------

def _run(run_context=None):
    if run_context is not None:
        return run_context
    try:
        from harness.run_context import current_run_context
        return current_run_context()
    except Exception:
        return None


def for_run(run_context=None) -> RunHandoff | None:
    return getattr(_run(run_context), "handoff", None)


def attach(run_context, *, host: str = "", base_url: str = "",
           output_dir: Path | str | None = None) -> RunHandoff:
    """Give `run_context` a persisted handoff (and persist its change log)."""
    log_ = getattr(run_context, "change_log", None)
    if log_ is None:
        log_ = ChangeLog(run_context.run_id)
        run_context.change_log = log_
    log_.run_id = run_context.run_id
    if output_dir:
        log_.path = Path(output_dir) / f"{run_context.run_id}.changes.json"
        log_._persist()
    handoff = RunHandoff(run_context.run_id, host=host, base_url=base_url,
                         output_dir=output_dir, change_log=log_)
    run_context.handoff = handoff
    handoff.persist()
    return handoff


def finish(run_context, status: str, result: dict | None = None) -> None:
    handoff = for_run(run_context)
    if handoff is None:
        return
    try:
        handoff.finish(status, result)
    except Exception as exc:
        log.warning("handoff finish failed (%s)", type(exc).__name__)


def observe_execution(ctx, request, outcome, *, capability: str, case_ref: str = "") -> None:
    """TargetTransport.execute's one hook: change log + handoff. Never raises."""
    try:
        runs = [ctx]
        ambient = _run(None)
        if ambient is not None and ambient is not ctx:
            runs.append(ambient)
        method = (getattr(request, "method", "") or "GET").upper()
        url = getattr(request, "url", "") or ""
        executed = bool(getattr(outcome, "executed", False))
        for rc in runs:
            log_ = getattr(rc, "change_log", None)
            if log_ is not None and outcome.outcome == "ok" and outcome.status is not None:
                session = None
                try:
                    session = rc.sessions.get(getattr(outcome.artifact, "session_ref", None) or None)
                except Exception:
                    pass
                log_.record_send(
                    method=method, url=url, status=outcome.status, capability=capability,
                    case_ref=case_ref, artifact_id=getattr(outcome.artifact, "artifact_id", "") or "",
                    principal=getattr(session, "principal_id", "") or "",
                    final_url=outcome.final_url or "", response_body=outcome.body)
            handoff = getattr(rc, "handoff", None)
            if handoff is not None:
                handoff.note_send(method=method, url=url, executed=executed,
                                  outcome=outcome.outcome, reason=outcome.error or "",
                                  capability=capability)
    except Exception:
        log.debug("observe_execution failed", exc_info=True)


def mark_restore(run_context, artifact_ids, *, ok: bool, detail: str = "") -> int:
    """Record the result of a cleanup that undoes the writes made by `artifact_ids`."""
    total = 0
    seen = set()
    for rc in (run_context, _run(None)):
        log_ = getattr(rc, "change_log", None)
        if log_ is None or id(log_) in seen:
            continue
        seen.add(id(log_))
        try:
            total += log_.mark_restore(artifact_ids, ok=ok, detail=detail)
        except Exception:
            log.debug("mark_restore failed", exc_info=True)
    handoff = for_run(run_context)
    if handoff is not None and total:
        handoff.persist()
    return total


def note_object(run_context, artifact_ids, *, object_ref: str = "", detail: str = "") -> int:
    """Name what the writes made by `artifact_ids` created, or why they stay."""
    total = 0
    seen = set()
    for rc in (run_context, _run(None)):
        log_ = getattr(rc, "change_log", None)
        if log_ is None or id(log_) in seen:
            continue
        seen.add(id(log_))
        try:
            total += log_.note_object(artifact_ids, object_ref=object_ref, detail=detail)
        except Exception:
            log.debug("note_object failed", exc_info=True)
    handoff = for_run(run_context)
    if handoff is not None and total:
        handoff.persist()
    return total


# ---------------------------------------------------------------------------
# Reading persisted runs (report section, server route)
# ---------------------------------------------------------------------------

def output_dir_for(config: dict | None) -> Path:
    runs = (config or {}).get("runs") or {}
    return Path(runs.get("output_dir") or Path(__file__).parent / "run-output")


def _matches(doc: dict, host: str) -> bool:
    host = (host or "").lower()
    return bool(host) and host in {doc.get("host") or "", doc.get("netloc") or "",
                                   (doc.get("netloc") or "").split(":")[0]}


def handoffs_for_host(host: str, output_dir: Path | str) -> list[dict]:
    """Every persisted handoff for `host` (host or host:port), newest first."""
    out = []
    for path in Path(output_dir).glob("*.handoff.json"):
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(doc, dict) and _matches(doc, host):
            out.append(doc)
    out.sort(key=lambda d: d.get("started_at") or 0, reverse=True)
    return out


def changes_for_run(run_id: str, output_dir: Path | str) -> list[dict]:
    path = Path(output_dir) / f"{run_id}.changes.json"
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []
    return list(doc.get("entries") or []) if isinstance(doc, dict) else []


def latest_for_host(host: str, output_dir: Path | str) -> dict:
    """{handoff, changes} for the newest run on `host`, plus every run's changes."""
    docs = handoffs_for_host(host, output_dir)
    changes = []
    for doc in docs:
        changes.extend(changes_for_run(doc.get("run_id") or "", output_dir))
    return {"host": host, "handoff": docs[0] if docs else None, "runs": len(docs),
            "changes": changes}


def _md_escape(text) -> str:
    return str(text if text is not None else "").replace("|", "\\|").replace("\n", " ")


def render_markdown(bundle: dict, *, limit: int = 25) -> str:
    handoff = bundle.get("handoff")
    changes = bundle.get("changes") or []
    lines = ["", "## Run handoff: what was not tested and what changed", ""]
    failed = [c for c in changes if c.get("restore_status") == RESTORE_FAILED]
    if failed:
        lines.append(f"> **ERROR: {len(failed)} write(s) on the target were NOT restored.** "
                     "Clean these up by hand before handing the target back.")
        lines.append("")
        for c in failed:
            lines.append(f"> - `{_md_escape(c.get('method'))} {_md_escape(c.get('path'))}` "
                         f"object `{_md_escape(c.get('object_ref') or '?')}` "
                         f"({_md_escape(c.get('capability'))}, run {_md_escape(c.get('run_id'))}): "
                         f"{_md_escape(c.get('restore_detail') or 'cleanup did not complete')}")
        lines.append("")
    if handoff:
        phases = handoff.get("phases") or {}
        untested = handoff.get("untested") or {}
        lines.append(f"Latest run `{_md_escape(handoff.get('run_id'))}`: status "
                     f"**{_md_escape(handoff.get('status'))}**, "
                     f"{'completed every phase' if phases.get('run_completed') else 'did not complete'}.")
        lines.append("")
        not_run = phases.get("not_run") or []
        if not_run:
            lines.append("**Phases not run:** " + ", ".join(
                f"{p['phase']}{' (if enabled)' if p.get('conditional') else ''}" for p in not_run))
            lines.append("")
        if phases.get("interrupted"):
            lines.append("**Phases interrupted:** " + ", ".join(phases["interrupted"]))
            lines.append("")
        caps = untested.get("unreviewed_captures") or {}
        if caps.get("count"):
            lines.append(f"**Unreviewed captures ({caps['count']}), highest value first:**")
            for c in (caps.get("items") or [])[:limit]:
                lines.append(f"- `{_md_escape(c['method'])} {_md_escape(c['path'])}` ({c['tier_name']})")
            lines.append("")
        nodes = untested.get("untouched_worklist_nodes") or []
        if nodes:
            lines.append(f"**Untouched worklist nodes ({len(nodes)}), by worklist rank:**")
            for n in nodes[:limit]:
                lines.append(f"- `{_md_escape(n['method'])} {_md_escape(n['path'])}` (rank {n['worklist_rank']})")
            lines.append("")
        legs = untested.get("skipped_legs") or []
        if legs:
            lines.append("**Legs skipped (capability, reason, count):**")
            for r in legs[:limit]:
                lines.append(f"- {_md_escape(r['capability'])}: {_md_escape(r['reason'])} x{r['count']}")
            lines.append("")
    if changes:
        lines.append(f"### Target change log ({len(changes)} write(s))")
        lines.append("")
        lines.append("| Run | Method | Path | Object | Capability | Status | Restore |")
        lines.append("|---|---|---|---|---|---|---|")
        for c in changes[:500]:
            lines.append("| " + " | ".join(_md_escape(v) for v in (
                c.get("run_id"), c.get("method"), c.get("path"), c.get("object_ref"),
                c.get("capability"), c.get("status"),
                ("**" + RESTORE_FAILED.upper() + "**") if c.get("restore_status") == RESTORE_FAILED
                else c.get("restore_status"))) + " |")
        lines.append("")
    elif handoff is not None:
        lines.append("_No writes recorded on the target._")
        lines.append("")
    if handoff is None and not changes:
        lines.append("_No run handoff recorded for this host._")
        lines.append("")
    return "\n".join(lines)


def report_section(host: str, config: dict | None) -> str:
    """The report's handoff section, or "" unless `reporting.handoff_section` is on."""
    reporting = (config or {}).get("reporting") or {}
    if reporting.get("handoff_section", False) is not True:
        return ""
    try:
        text = render_markdown(latest_for_host(host, output_dir_for(config)))
        from harness import security
        return security.sanitize_text(text)
    except Exception as exc:
        log.warning("handoff report section failed (%s)", type(exc).__name__)
        return ""
