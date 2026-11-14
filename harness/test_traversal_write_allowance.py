"""A path-traversal leg on a write request plans within the finding's write allowance (r9 review).

r9 ran with `validators.max_mutating_requests_per_finding: 20`. On a write request
with several file-shaped inputs the path-traversal leg planned (inputs x 8 encodings
x 2 files) payloads, sent them input by input, and the 21st was refused by the
per-finding mutating ceiling (R16): 203 legs ended on a blocked send, and the inputs
after the first one or two were never tried. The leg now reads the finding's
remaining allowance before sending, gives every input its strongest encodings first,
sends no more than the allowance and reports the check as partial.

Caller: PathTraversalValidator.validate through a real RunContext (its own gate, the
executor, the R16 accounting) against a loopback MockTransport target. Controls: the
allowance planning removed (the r9 behaviour), a spent allowance, and a safe method.
"""
from __future__ import annotations

import asyncio
import unittest
from urllib.parse import parse_qsl, urlsplit, unquote
from unittest.mock import patch

import httpx

from harness.models import Finding, HttpExchange
from harness.run_context import RunContext
from harness.validators import path_traversal_validator as ptv
from harness.validators.path_traversal_validator import PathTraversalValidator

HOST = "t.test"
INPUTS = ("file", "doc", "path", "template")      # four file-shaped inputs + the path segment
CEILING = 20
_PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:"


def _finding(fid="f-write"):
    return Finding(vulnerability_class="path traversal", confidence=0.5, severity="high",
                   summary="file read", evidence="e", suggested_test="t", basis="derived",
                   finding_id=fid)


def _exchange(method="POST"):
    form = "&".join(f"{name}=report{i}.pdf" for i, name in enumerate(INPUTS))
    if method == "GET":
        return HttpExchange(url=f"http://{HOST}/api/export?{form}", method="GET",
                            request_headers={}, request_body="", response_status=200,
                            response_body="ok")
    return HttpExchange(url=f"http://{HOST}/api/export", method="POST",
                        request_headers={"Content-Type": "application/x-www-form-urlencoded"},
                        request_body=form, response_status=200, response_body="ok")


def _injected(request: httpx.Request) -> tuple[str, str]:
    """(input, payload) a probe carried: the input whose value is a traversal payload."""
    values = dict(parse_qsl(urlsplit(str(request.url)).query, keep_blank_values=True))
    if request.content:
        values.update(parse_qsl(request.content.decode(), keep_blank_values=True))
    for name, value in values.items():
        if "passwd" in value or "win.ini" in value:
            return name, value
    return "path segment", unquote(urlsplit(str(request.url)).path)


class _Target:
    """Loopback target: answers 404, or a passwd read on the `vulnerable` input."""

    def __init__(self, vulnerable: str = ""):
        self.vulnerable = vulnerable
        self.sent: list[tuple[str, str]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        name, value = _injected(request)
        self.sent.append((name, value))
        if name == self.vulnerable and value.endswith("etc/passwd") and ".." in value:
            return httpx.Response(200, text=_PASSWD)
        return httpx.Response(404, text="not found")


def _run(target: _Target, *, method="POST", spend=0, fid="f-write"):
    async def run():
        context = RunContext.create(
            allowed_hosts=[HOST], max_requests=500,
            gate_config={"active_enabled": True, "allow_mutating_replay": True,
                         "max_mutating_requests_per_finding": CEILING},
            config={"validators": {"active_enabled": True, "allow_mutating_replay": True,
                                   "max_mutating_requests_per_finding": CEILING}})
        context._default_client = httpx.AsyncClient(transport=httpx.MockTransport(target),
                                                     follow_redirects=False)
        if spend:
            context.gate._reserve_mutating(fid, spend, "path_traversal")
        try:
            result = await PathTraversalValidator(allowed_hosts=[HOST], run_context=context
                                                  ).validate(_finding(fid), _exchange(method))
            return result, context.gate.mutating_headroom(fid, "path_traversal")
        finally:
            await context.aclose()
    return asyncio.run(run())


class WriteAllowanceTests(unittest.TestCase):

    def test_a_write_leg_sends_within_the_allowance_and_tries_every_input(self):
        target = _Target()
        result, headroom = _run(target)
        self.assertEqual(len(target.sent), CEILING)
        self.assertEqual(headroom, (0, CEILING, CEILING))          # spent, never exceeded
        self.assertEqual({name for name, _ in target.sent}, {*INPUTS, "path segment"})
        self.assertEqual(result.status, "inconclusive")
        self.assertIn("partial", result.summary)
        self.assertIn("mutating-request ceiling (R16) left room for", result.summary)
        self.assertIn("of 80 probe(s)", result.summary)
        self.assertIn("could not be sent", result.evidence)        # backslash path segments
        self.assertNotIn("blocked", result.summary + result.evidence)

    def test_every_input_gets_the_strongest_encoding_first(self):
        target = _Target()
        _run(target)
        first = ptv._PREFIXES[0]
        firsts = target.sent[:2 * (len(INPUTS) + 1)]                # both files, every input
        self.assertTrue(all(first in value or name == "path segment" for name, value in firsts))
        self.assertEqual({name for name, _ in firsts}, {*INPUTS, "path segment"})

    def test_a_late_vulnerable_input_is_confirmed(self):
        target = _Target(vulnerable=INPUTS[-1])
        result, _ = _run(target)
        self.assertEqual(result.status, "confirmed")
        self.assertLessEqual(len(target.sent), CEILING)

    def test_control_without_the_planning_the_ceiling_refuses_and_inputs_go_untried(self):
        target = _Target(vulnerable=INPUTS[-1])
        with patch.object(PathTraversalValidator, "_write_allowance", lambda *a: None):
            result, headroom = _run(target)
        self.assertEqual(len(target.sent), CEILING)                 # the 21st was refused
        self.assertEqual(headroom[0], 0)
        self.assertLess({name for name, _ in target.sent}, {*INPUTS, "path segment"})
        self.assertEqual(result.status, "inconclusive")             # the r9 outcome
        self.assertIn("blocked", result.summary)

    def test_control_a_spent_allowance_sends_nothing(self):
        target = _Target()
        result, headroom = _run(target, spend=CEILING)
        self.assertEqual(target.sent, [])
        self.assertEqual(result.status, "skipped")
        self.assertIn("ceiling (R16) is spent", result.summary)
        self.assertEqual(headroom, (0, CEILING, CEILING))

    def test_control_a_read_request_is_not_limited(self):
        target = _Target()
        result, headroom = _run(target, method="GET")
        # every planned probe but the two backslash path segments no URL can carry
        self.assertEqual(len(target.sent), 78)
        self.assertIn("2 payload(s) could not be sent", result.evidence)
        self.assertEqual(result.status, "not_confirmed")
        self.assertEqual(headroom, (CEILING, 0, CEILING))


if __name__ == "__main__":
    unittest.main()
