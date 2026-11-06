"""
Content Exposure Validator -- the AV-EXPOSURE-01 coverage adapter.

Passive: judges the captured response it is handed and sends nothing. r5 reached
/ftp (a directory index), /metrics (a Prometheus exposition) and
/rest/user/whoami?callback= (JSONP) but only the recon check applied to them, and
recon is not a verdict. This adapter decides on the response itself.

A capture is judged only when it is a 2xx response to a GET whose body was kept.
It is confirmed when the body is:
- a web-server directory index (Apache/nginx "Index of /", Python "Directory
  listing for /", Express serve-index "listing directory /");
- a Prometheus/OpenMetrics exposition (a `# HELP` line and a `# TYPE` line naming
  a metric type);
- a JSONP wrapper: the request named a callback parameter and the body calls that
  exact value, so another origin can read the response with a script tag.
A judged response with none of them is not_confirmed. Anything else is skipped,
never a negative: no captured response, a non-2xx status, a non-GET method, or a
body that was not kept (an access-matrix probe keeps only its digest).

It routes no agent finding (empty finding_classes).
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl, urlsplit

from .base import Validator, ValidationResult

if TYPE_CHECKING:
    from harness.models import Finding, HttpExchange

_LISTING = re.compile(
    r"<title>\s*(?:Index of /|Directory listing for /|listing directory /)", re.I)
_PROM_HELP = re.compile(r"^# HELP [A-Za-z_:][\w:]* ", re.M)
_PROM_TYPE = re.compile(r"^# TYPE [A-Za-z_:][\w:]* (?:counter|gauge|histogram|summary|untyped|info|stateset)\b", re.M)
_CALLBACK_PARAMS = ("callback", "jsonp", "cb")


def _jsonp_callback(url: str, body: str) -> str | None:
    """The callback value when `body` calls the callback the request named."""
    for name, value in parse_qsl(urlsplit(url or "").query, keep_blank_values=False):
        if name.lower() not in _CALLBACK_PARAMS or not value:
            continue
        cb = re.escape(value)
        wrapped = re.compile(
            rf"^\s*(?:/\*\*/\s*)?(?:typeof\s+{cb}\s*===?\s*['\"]function['\"]\s*&&\s*)?{cb}\s*\(")
        if wrapped.match(body):
            return value
    return None


def audit_exposure(exchange: "HttpExchange") -> dict:
    """Decide AV-EXPOSURE-01 on one captured response.

    Returns {"verdict": "fail" | "pass" | "skip", "reason": str, "matches":
    [(name, snippet)]}."""
    status = getattr(exchange, "response_status", None)
    body = getattr(exchange, "response_body", "") or ""
    url = getattr(exchange, "url", "") or ""

    def skip(reason):
        return {"verdict": "skip", "reason": reason, "matches": []}
    if not isinstance(status, int):
        return skip("no captured response for this request")
    if not 200 <= status < 300:
        return skip(f"captured response is {status}; only a served 2xx body can expose content")
    if (getattr(exchange, "method", "") or "GET").upper() != "GET":
        return skip("only a GET response is judged")
    if not body:
        return skip("the response body was not kept with this capture")
    matches = []
    if _LISTING.search(body[:4000]):
        matches.append(("directory_listing", " ".join(body[:200].split())))
    if _PROM_HELP.search(body) and _PROM_TYPE.search(body):
        matches.append(("metrics_exposition", " ".join(_PROM_TYPE.search(body).group(0).split())))
    callback = _jsonp_callback(url, body)
    if callback is not None:
        matches.append(("jsonp_callback", " ".join(body[:120].split())))
    if not matches:
        return {"verdict": "pass", "matches": [],
                "reason": f"{status} response is no directory index, metrics exposition or JSONP wrapper"}
    return {"verdict": "fail", "matches": matches,
            "reason": f"{status} response is " + ", ".join(m[0] for m in matches)}


class ContentExposureValidator(Validator):
    """Passive AV-EXPOSURE-01 oracle over a captured 2xx response."""

    name = "content_exposure_validator"
    finding_classes: set[str] = set()   # coverage dispatch only; see the module docstring
    active = False

    def get_name(self) -> str:
        return self.name

    def get_capability(self) -> str:
        return "content_exposure"

    def get_execution_plane(self) -> str:
        return "local_analysis"

    async def validate(self, finding: "Finding", exchange: "HttpExchange") -> ValidationResult:
        audit = audit_exposure(exchange)
        target = f"{(exchange.method or 'GET').upper()} {exchange.url}"
        if audit["verdict"] == "skip":
            return ValidationResult(self.name, "skipped", finding.vulnerability_class,
                                    summary=f"AV-EXPOSURE-01 not judged: {audit['reason']}")
        if audit["verdict"] == "pass":
            return ValidationResult(self.name, "not_confirmed", finding.vulnerability_class,
                                    confidence=0.9, summary=f"AV-EXPOSURE-01 held: {audit['reason']}")
        return ValidationResult(self.name, "confirmed", finding.vulnerability_class,
                                confidence=0.95, confirmed=True, severity="medium",
                                summary=f"AV-EXPOSURE-01 fails on {target}: {audit['reason']}",
                                evidence="; ".join(f"{name}: {snippet}" for name, snippet in audit["matches"]))
