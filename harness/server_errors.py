"""Server errors the run provoked itself, and the follow-up they deserve.

The transport sees every response to the run's own sends. Until now a 5xx answer
fed only the route circuit (run_context.TransportHealth) and was otherwise dropped:
the model review and the verbose-error detector read captured (proxy / crawler)
exchanges, never the harness's own probes. The 10 h Juice Shop run of 2026-11-05
(r5) drew 3,779 server errors that way -- 251 of 509 product searches, 82 POST
logins -- and examined none of them.

`ServerErrorLedger` is the passive record. Per route (method, origin, template) it
keeps the response and 5xx counts, the capabilities whose sends drew the errors,
and, for the first `max_scans` 5xx bodies of the route, the verbose-error pattern
names (validators.verbose_error_validator), the database-error signatures, the
names of the parameters that carried suspect input, and one short redacted snippet.
It keeps no request value and no body: parameter names only.

`findings()` turns the ledger into findings for the engagement state:

- `verbose_error_disclosure`, confirmed by `verbose_error_validator` exactly as a
  captured exchange's stack trace is: the response is the proof.
- `sql_injection` / `nosql_injection` leads, unconfirmed, where a database error
  answered a request that carried suspect input. investigate_engagement hands each
  lead to the deterministic leg for its class (sqlmap, the nosql validator) with
  the route's captured template, so the error is followed up in the same run.

Passive: the ledger never sends. The legs a lead reaches are the run's own,
under their own configuration.
"""
from __future__ import annotations

import json
import re
import threading
from collections import Counter
from dataclasses import dataclass, field
from types import SimpleNamespace
from urllib.parse import parse_qsl, urlsplit

# A database engine's error text in a server error. An injection lead, never proof.
_SQL_ERROR = re.compile(
    r"SQLITE_ERROR|SQLITE_[A-Z]+:|SequelizeDatabaseError|sqlite3\.OperationalError|"
    r"You have an error in your SQL syntax|SQLSTATE\[|ORA-\d{5}|PG::\w*Error|"
    r"syntax error at or near|unterminated quoted string|unclosed quotation mark|"
    r"quoted string not properly terminated|Microsoft OLE DB Provider|"
    r"ODBC SQL Server Driver", re.I)
_NOSQL_ERROR = re.compile(
    r"MongoError|MongoServerError|MongoParseError|BSONTypeError|unknown operator: \$|"
    r"CastError: Cast to ObjectId", re.I)
SIGNALS = {"sql_error": ("sql_injection", _SQL_ERROR),
           "nosql_error": ("nosql_injection", _NOSQL_ERROR)}

# Input that is there to break a query or a parser: a quote, an operator, a comment.
_SUSPECT = re.compile(r"['\"`\\$]|--|/\*|;|\{")

_SEV = {"info": 0, "low": 1, "medium": 2, "high": 3}
_SNIPPET = 200


def _redact(text: str) -> str:
    """A snippet for the record: SQL literals (an echoed query's values, a hash of a
    supplied password), tokens and long hex strings are masked; the error's own
    message stays (a JSON error carries it in double quotes, so those are kept)."""
    text = re.sub(r"eyJ[\w-]+\.[\w-]+\.[\w-]*", "<token>", text)
    text = re.sub(r"\b[0-9a-fA-F]{16,}\b", "<hex>", text)
    text = re.sub(r"'[^'\n]{1,200}'", "'***'", text)
    return " ".join(text.split())[:_SNIPPET]


def _value_suspect(value) -> bool:
    if isinstance(value, str):
        return bool(_SUSPECT.search(value))
    if isinstance(value, dict):   # an operator object: {"$ne": null}
        return any(str(k).startswith("$") for k in value) or any(
            _value_suspect(v) for v in value.values())
    if isinstance(value, list):
        return any(_value_suspect(v) for v in value)
    return False


def suspect_parameters(url: str, body, content_type: str = "") -> list[tuple[str, str]]:
    """(location, name) of each query or top-level body parameter whose value looks
    like an injection probe. Names only; the values are never returned."""
    out: list[tuple[str, str]] = []
    for name, value in parse_qsl(urlsplit(url or "").query, keep_blank_values=True):
        if _value_suspect(value):
            out.append(("query", name))
    if isinstance(body, (bytes, bytearray)):
        body = body.decode("utf-8", errors="replace")
    if isinstance(body, str) and body.strip():
        parsed = None
        if "json" in (content_type or "").lower() or body.lstrip()[:1] in "{[":
            try:
                parsed = json.loads(body)
            except ValueError:
                parsed = None
        if isinstance(parsed, dict):
            out.extend(("body", str(k)) for k, v in parsed.items() if _value_suspect(v))
        elif parsed is None and "=" in body:
            out.extend(("body", k) for k, v in parse_qsl(body, keep_blank_values=True)
                       if _value_suspect(v))
    return out


@dataclass
class _Route:
    responses: int = 0
    errors_5xx: int = 0
    capabilities: Counter = field(default_factory=Counter)
    scanned: int = 0
    patterns: set = field(default_factory=set)
    severity: str = ""
    snippet: str = ""
    signals: dict = field(default_factory=dict)   # signal -> {"count", "snippet", "params"}


class ServerErrorLedger:
    """Per-run record of the server errors the run's own sends drew (module
    docstring). Shared by every transport of the run; thread-safe."""

    def __init__(self, *, max_scans: int = 3, max_routes: int = 500,
                 max_body_chars: int = 200_000):
        self.max_scans = max(0, int(max_scans))
        self.max_routes = max(1, int(max_routes))
        self.max_body_chars = max(1, int(max_body_chars))
        self._routes: dict[tuple, _Route] = {}
        self._overflow_5xx = 0
        self._lock = threading.Lock()

    def observe(self, *, method: str, url: str, status, capability: str = "",
                body_fn=None, request_body=None, content_type: str = "") -> None:
        """Count one response. A 5xx among the route's first `max_scans` has its body
        scanned; nothing else is read. Never raises into the send path."""
        try:
            self._observe(method, url, status, capability, body_fn, request_body, content_type)
        except Exception:   # the ledger is a report layer -- never fail a send
            pass

    def _observe(self, method, url, status, capability, body_fn, request_body, content_type):
        from harness import engagement   # lazy: the one route-template normalizer
        if not isinstance(status, int):
            return
        parts = urlsplit(url or "")
        key = ((method or "GET").upper(), f"{parts.scheme}://{parts.netloc}",
               engagement.normalize_path(url or "/"))
        is_5xx = 500 <= status <= 599
        with self._lock:
            route = self._routes.get(key)
            if route is None:
                if len(self._routes) >= self.max_routes:
                    self._overflow_5xx += int(is_5xx)
                    return
                route = self._routes[key] = _Route()
            route.responses += 1
            if not is_5xx:
                return
            route.errors_5xx += 1
            route.capabilities[capability or "unlabelled"] += 1
            if route.scanned >= self.max_scans or body_fn is None:
                return
            route.scanned += 1
        body = body_fn() if callable(body_fn) else body_fn
        if isinstance(body, (bytes, bytearray)):
            body = body.decode("utf-8", errors="replace")
        body = (body or "")[: self.max_body_chars]
        if not body:
            return
        from harness.validators.verbose_error_validator import scan_exchange
        matches = scan_exchange(SimpleNamespace(response_body=body, response_headers={},
                                                response_status=status))
        found = {}
        for name, (_cls, pattern) in SIGNALS.items():
            m = pattern.search(body)
            if m:
                found[name] = _redact(body[max(0, m.start() - 40): m.end() + 120])
        params = suspect_parameters(url, request_body, content_type) if found else []
        with self._lock:
            for name, sev, snippet in matches:
                route.patterns.add(name)
                if _SEV.get(sev, 0) > _SEV.get(route.severity, -1):
                    route.severity = sev
                if not route.snippet:
                    route.snippet = _redact(snippet)
            for name, snippet in found.items():
                sig = route.signals.setdefault(name, {"count": 0, "snippet": snippet,
                                                      "params": Counter()})
                sig["count"] += 1
                sig["params"].update(params)

    def report(self) -> dict:
        """Plain data for the run result: every route that answered 5xx, worst first."""
        with self._lock:
            rows = []
            for (method, origin, template), r in self._routes.items():
                if not r.errors_5xx:
                    continue
                rows.append({
                    "route": f"{method} {template}", "origin": origin,
                    "errors_5xx": r.errors_5xx, "responses": r.responses,
                    "all_5xx": r.errors_5xx == r.responses,
                    "capabilities": dict(r.capabilities.most_common(5)),
                    "scanned": r.scanned, "disclosure": sorted(r.patterns),
                    "signals": {k: {"count": v["count"],
                                    "parameters": [f"{loc}:{n}" for (loc, n), _ in
                                                   v["params"].most_common(5)]}
                                for k, v in r.signals.items()},
                })
            rows.sort(key=lambda x: (-len(x["signals"]), -len(x["disclosure"]), -x["errors_5xx"]))
            return {"routes_with_5xx": len(rows),
                    "errors_5xx": sum(x["errors_5xx"] for x in rows) + self._overflow_5xx,
                    "untracked_5xx": self._overflow_5xx,
                    "routes": rows}

    def findings(self) -> list[dict]:
        """Findings for the engagement state, one per route and class (module
        docstring). A lead names its parameter only when exactly one parameter
        carried suspect input across the route's database errors."""
        out: list[dict] = []
        with self._lock:
            items = list(self._routes.items())
        for (method, origin, template), r in items:
            url = origin + template
            ratio = f"{r.errors_5xx} of {r.responses}"
            if r.patterns:
                out.append({
                    "vulnerability_class": "verbose_error_disclosure", "method": method,
                    "url": url, "severity": r.severity or "low", "confidence": 0.9,
                    "summary": (f"Server errors disclose internals ({', '.join(sorted(r.patterns))}); "
                                f"{ratio} responses to this run's requests were 5xx"),
                    "evidence": r.snippet, "basis": "observed", "confirmed": True,
                    "confirmation_method": "verbose_error_validator",
                    "validator": "verbose_error_validator",
                    "suggested_test": "Review the error page for paths, versions and query text",
                })
            for name, sig in r.signals.items():
                cls = SIGNALS[name][0]
                lead = {
                    "vulnerability_class": cls, "method": method, "url": url,
                    "severity": "high", "confidence": 0.6, "basis": "observed",
                    "confirmed": False, "source": "server_error",
                    "summary": (f"A database error answered {sig['count']} input-bearing "
                                f"request(s) with a 5xx ({ratio} responses were 5xx): an "
                                f"injection lead"),
                    "evidence": sig["snippet"],
                    "suggested_test": f"Run the {cls.replace('_', ' ')} leg on the parameter "
                                      f"that drew the error",
                }
                params = sig["params"]
                if len(params) == 1:
                    (loc, pname), = params.keys()
                    lead["parameter_location"], lead["parameter_name"] = loc, pname
                out.append(lead)
        return out
