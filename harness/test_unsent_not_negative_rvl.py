"""Code review 02, batch RV-L: a check whose sends were refused or failed is not
a negative, and an execution or size signal must be the one the check controls.

L1 ssrf, L2 open_redirect, L3 ssti and L4 api_security returned a negative when
no probe was answered. L5 confirmed an unbounded limit from response bytes
alone. L6 moves ssti's restore-affordability check onto a public, read-only
SafetyGate accessor. L7 replaces the nonce-substring check in browser_xss and
dom_xss with a computed challenge. L8 stops an anonymous 5xx, 404 or transport
error from counting as the MFA-bypass denial.

Each test drives the production caller, ``Orchestrator._validate_findings``,
with the transport faked below the gated client (so the gate and the run budget
still decide), or against an owned loopback app. Every reproduction has a
control that must keep its old result.
"""
import asyncio
import html
import json
import re
import secrets
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from urllib.parse import parse_qs, parse_qsl, unquote_plus, urlsplit

import httpx

from harness import browser_driver, safety_gate
from harness.browser_driver import ExecutionObservation
from harness.models import AgentReport
from harness.orchestrator import Orchestrator
from harness.run_context import RunContext
from harness.safety_gate import SafetyGate, SafetyGateConfig
from harness.test_confirmation_soundness_rve import (_CallerBase, _finding, _json_exchange,
                                                     _verdicts)
from harness.test_default_history_caller import _config, _exchange
from harness.validators import browser_xss_validator, dom_xss_validator
from harness.validators.api_security_validator import ApiSecurityValidator
from harness.validators.auth_sequence_validator import AuthSequenceValidator
from harness.validators.browser_xss_validator import BrowserXssValidator
from harness.validators.dom_xss_validator import DomXssValidator
from harness.validators.open_redirect_validator import OpenRedirectValidator
from harness.validators.ssrf_validator import SsrfValidator
from harness.validators.ssti_validator import SstiValidator


def _text(reports):
    return " ".join(f"{r.summary} {r.evidence}" for r in reports)


def _response(method, url, status=200, text="ok", headers=None):
    return httpx.Response(status, text=text, headers=headers or {}, request=httpx.Request(method, url))


def _refuse_all(sent):
    async def request(client, method, url, **kwargs):
        sent.append((method, str(url)))
        raise httpx.ConnectError("synthetic refused connection", request=httpx.Request(method, url))
    return request


# unittest.TestCase is named explicitly (already in _CallerBase's MRO) so the
# static collection guard in test_no_orphan_test_files sees these as test cases.
class _RvlBase(_CallerBase, unittest.TestCase):
    def _in_run(self, key, validator, finding, exchange, *, max_requests, fake_request,
                mutating=True, hosts=("shop.invalid",), extra_gate=None):
        """One validator through _validate_findings inside an explicit run whose
        budget and gate the test sets (max_requests=0 refuses every send)."""
        orch = self._orch(hosts=hosts)
        orch.validator_registry.validators = {key: validator}
        gate_config = {"active_enabled": True, "allow_mutating_replay": mutating, **(extra_gate or {})}

        async def go():
            async with RunContext.create(allowed_hosts=list(hosts), max_requests=max_requests,
                                         gate_config=gate_config) as run:
                return await orch._validate_findings(
                    exchange, [AgentReport(agent=key, model="fake", findings=[finding])],
                    run_context=run)
        with patch.object(httpx.AsyncClient, "request", fake_request):
            reports, _proofs = asyncio.run(go())
        self.assertTrue(reports, "the validator was not dispatched")
        return reports

    def _assert_not_negative(self, reports, status):
        self.assertFalse(any(r.confirmed for r in reports), _verdicts(reports))
        self.assertEqual([r.status for r in reports], [status], _verdicts(reports))
        self.assertIn("not a negative", _text(reports))


# ------------------------------------------------------------------ L1 ssrf
class _Collaborator:
    """Collaborator double. The fake target 'fetches' by recording a hit for a
    token it finds in a request; wait_for_hit then reports it."""

    def __init__(self):
        self.issued, self.hits = [], set()

    def token(self):
        tok = secrets.token_hex(6)
        self.issued.append(tok)
        return tok

    def url(self, token):
        return f"http://oob.collab.invalid/{token}"

    async def wait_for_hit(self, token, timeout=0.0):
        return token in self.hits


def _ssrf_target(collab, sent, *, fail=lambda url: False, fetches=False):
    async def request(client, method, url, **kwargs):
        u = unquote_plus(str(url))
        sent.append((method, u))
        if fail(u):
            raise httpx.ConnectError("synthetic refused connection", request=httpx.Request(method, url))
        if fetches:
            collab.hits.update(t for t in collab.issued if t in u)
        return _response(method, url, text="<p>preview unavailable</p>")
    return request


class SsrfUnsentTests(_RvlBase):
    """L1: no callback after sends that never reached the target is not a negative."""

    URL = "http://shop.invalid/fetch?url=http%3A%2F%2Fexample.com%2Fa"

    def _run(self, fake=None, *, max_requests=None, collab=None):
        collab = collab or _Collaborator()
        v = SsrfValidator(allowed_hosts=["shop.invalid"], timeout=1.0, collaborator=collab)
        if max_requests is not None:
            return self._in_run("ssrf", v, _finding("ssrf"), _exchange(self.URL),
                                max_requests=max_requests, fake_request=fake)
        return self._validate("ssrf", v, _finding("ssrf"), _exchange(self.URL), fake)

    def test_every_send_failing_is_not_a_negative(self):
        sent = []
        reports = self._run(_refuse_all(sent))
        self.assertTrue(sent, "nothing was attempted -- vacuous")
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("ConnectError", _text(reports))

    def test_every_send_refused_by_the_budget_reads_as_blocked(self):
        sent = []
        reports = self._run(_refuse_all(sent), max_requests=0)
        self.assertEqual(sent, [], "a refused send reached the target")
        self._assert_not_negative(reports, "blocked")
        self.assertIn("budget_exhausted", _text(reports))

    def test_failed_out_of_band_send_after_answered_in_band_reads_is_inconclusive(self):
        sent, collab = [], _Collaborator()
        reports = self._run(_ssrf_target(collab, sent, fail=lambda u: "oob.collab.invalid" in u),
                            collab=collab)
        self.assertTrue(any("127.0.0.1" in u for _, u in sent), "the in-band reads never ran")
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("out-of-band", _text(reports))

    def test_callback_confirms(self):
        sent, collab = [], _Collaborator()
        reports = self._run(_ssrf_target(collab, sent, fetches=True), collab=collab)
        self.assertEqual([r.status for r in reports], ["confirmed"], _verdicts(reports))

    def test_completed_probes_without_callback_stay_negative(self):
        sent, collab = [], _Collaborator()
        reports = self._run(_ssrf_target(collab, sent), collab=collab)
        self.assertEqual([r.status for r in reports], ["not_confirmed"], _verdicts(reports))


# ---------------------------------------------------------- L2 open redirect
def _redirector(sent, *, off_origin=False, fail=lambda nxt: False):
    async def request(client, method, url, **kwargs):
        nxt = httpx.URL(str(url)).params.get("next", "")
        sent.append((method, nxt))
        if fail(nxt):
            raise httpx.ConnectError("synthetic refused connection", request=httpx.Request(method, url))
        return _response(method, url, 302, "", {"Location": nxt if off_origin else "/home"})
    return request


class OpenRedirectUnsentTests(_RvlBase):
    """L2: no off-origin redirect after sends that never got an answer is not a negative."""

    URL = "http://shop.invalid/leave?next=/home"

    def _run(self, fake, *, max_requests=None):
        v = OpenRedirectValidator(allowed_hosts=["shop.invalid"])
        if max_requests is not None:
            return self._in_run("open_redirect", v, _finding("open_redirect"), _exchange(self.URL),
                                max_requests=max_requests, fake_request=fake)
        return self._validate("open_redirect", v, _finding("open_redirect"), _exchange(self.URL), fake)

    def test_every_send_failing_is_not_a_negative(self):
        sent = []
        reports = self._run(_refuse_all(sent))
        self.assertEqual(len(sent), 4, sent)
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("ConnectError", _text(reports))

    def test_every_send_refused_by_the_budget_reads_as_blocked(self):
        sent = []
        reports = self._run(_refuse_all(sent), max_requests=0)
        self.assertEqual(sent, [])
        self._assert_not_negative(reports, "blocked")
        self.assertIn("budget_exhausted", _text(reports))
        self.assertNotIn("allow_mutating_replay", _text(reports), "the refusal names the wrong cause")

    def test_partly_failed_sends_are_inconclusive(self):
        sent = []
        reports = self._run(_redirector(sent, fail=lambda nxt: nxt.startswith("//")))
        self.assertEqual(len(sent), 4, sent)
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("1 of 4", _text(reports))

    def test_off_origin_redirect_confirms(self):
        reports = self._run(_redirector([], off_origin=True))
        self.assertEqual([r.status for r in reports], ["confirmed"], _verdicts(reports))

    def test_answered_same_origin_redirects_stay_negative(self):
        reports = self._run(_redirector([]))
        self.assertEqual([r.status for r in reports], ["not_confirmed"], _verdicts(reports))


# ------------------------------------------------------------------ L3 ssti
def _template_page(sent, *, evaluate=False, fail=lambda name: False):
    async def request(client, method, url, **kwargs):
        name = httpx.URL(str(url)).params.get("name", "")
        sent.append((method, name))
        if fail(name):
            raise httpx.ConnectError("synthetic refused connection", request=httpx.Request(method, url))
        if evaluate:
            name = name.replace("{{89*97}}", "8633")
        return _response(method, url, text=f"<p>Hello {html.escape(name)}</p>")
    return request


class SstiUnsentTests(_RvlBase):
    """L3: an SSTI check whose sends all failed is not a negative."""

    URL = "http://shop.invalid/greet?name=bob"

    def _run(self, fake):
        return self._validate("ssti", SstiValidator(allowed_hosts=["shop.invalid"]), _finding("ssti"),
                              _exchange(self.URL), fake)

    def test_every_send_failing_is_not_a_negative(self):
        sent = []
        reports = self._run(_refuse_all(sent))
        self.assertEqual(len(sent), 6, sent)
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("6 of 6", _text(reports))

    def test_partly_failed_sends_are_inconclusive(self):
        sent = []
        reports = self._run(_template_page(sent, fail=lambda name: "${" in name))
        self.assertEqual(len(sent), 6, sent)
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("2 of 6", _text(reports))

    def test_literal_reflection_stays_negative(self):
        reports = self._run(_template_page([]))
        self.assertEqual([r.status for r in reports], ["not_confirmed"], _verdicts(reports))

    def test_evaluated_expression_confirms(self):
        reports = self._run(_template_page([], evaluate=True))
        self.assertEqual([r.status for r in reports], ["confirmed"], _verdicts(reports))


# ---------------------------------------------------- L4/L5 api_security
def _profile_api(sent, *, readback_fails=False):
    """A profile endpoint that ignores unknown fields. The read-back GET (the
    second GET) can be made to fail."""
    gets = []

    async def request(client, method, url, **kwargs):
        sent.append(method)
        if method == "GET":
            gets.append(1)
            if readback_fails and len(gets) > 1:
                raise httpx.ConnectError("synthetic refused connection", request=httpx.Request(method, url))
        return _response(method, url, text='{"name": "Alice"}', headers={"Content-Type": "application/json"})
    return request


class ApiSecurityUnsentTests(_RvlBase):
    """L4: a refused or failed api_security probe reads as blocked, never as passed."""

    LIST = "http://shop.invalid/api/items?limit=10"
    PROFILE = "http://shop.invalid/api/profile"

    def _limit(self, fake, *, max_requests=None):
        v, f = ApiSecurityValidator(), _finding("unbounded resource consumption")
        if max_requests is not None:
            return self._in_run("api_security", v, f, _exchange(self.LIST),
                                max_requests=max_requests, fake_request=fake)
        return self._validate("api_security", v, f, _exchange(self.LIST), fake)

    def _profile(self, fake, *, mutating=True):
        return self._in_run("api_security", ApiSecurityValidator(), _finding("mass_assignment"),
                            _json_exchange(self.PROFILE, "POST", '{"name": "Alice"}'),
                            max_requests=50, fake_request=fake, mutating=mutating)

    def test_limit_probe_refused_by_the_budget_reads_as_blocked(self):
        sent = []
        reports = self._limit(_refuse_all(sent), max_requests=0)
        self.assertEqual(sent, [])
        self._assert_not_negative(reports, "blocked")
        self.assertIn("budget_exhausted", _text(reports))

    def test_limit_probe_that_failed_is_inconclusive(self):
        sent = []
        reports = self._limit(_refuse_all(sent))
        self.assertTrue(sent)
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("ConnectError", _text(reports))

    def test_mass_assignment_write_refused_by_the_gate_reads_as_blocked(self):
        sent = []
        reports = self._profile(_profile_api(sent), mutating=False)
        self.assertNotIn("POST", sent, "the gate let the write through")
        self._assert_not_negative(reports, "blocked")

    def test_accepted_write_whose_read_back_failed_is_inconclusive(self):
        sent = []
        reports = self._profile(_profile_api(sent, readback_fails=True))
        self.assertEqual(sent, ["GET", "POST", "GET"], sent)
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("read-back", _text(reports))

    def test_executed_safe_probes_still_pass(self):
        sent = []
        reports = self._profile(_profile_api(sent))
        self.assertEqual(sent, ["GET", "POST", "GET"], sent)
        self.assertEqual([r.status for r in reports], ["not_confirmed"], _verdicts(reports))
        reports = self._limit(_list_api(lambda limit: _items(min(limit, 50))))
        self.assertEqual([r.status for r in reports], ["not_confirmed"], _verdicts(reports))


def _items(n, **extra):
    return [{"id": i, "name": f"item {i}", **extra} for i in range(n)]


def _list_api(make_body, sent=None):
    async def request(client, method, url, **kwargs):
        limit = int(httpx.URL(str(url)).params.get("limit", "10"))
        if sent is not None:
            sent.append(limit)
        return _response(method, url, text=json.dumps(make_body(limit)),
                         headers={"Content-Type": "application/json"})
    return request


class UnboundedLimitStructureTests(_RvlBase):
    """L5: response bytes alone are a candidate. Confirmation needs the item
    count to follow the requested limit past any cap: many items for the huge
    limit, at most two for limit=2."""

    URL = "http://shop.invalid/api/items?limit=10"

    def _run(self, make_body, sent=None):
        return self._validate("api_security", ApiSecurityValidator(),
                              _finding("unbounded resource consumption"), _exchange(self.URL),
                              _list_api(make_body, sent))

    def _assert_candidate(self, reports):
        self.assertFalse(any(r.confirmed for r in reports), _text(reports))
        self.assertEqual([r.status for r in reports], ["inconclusive"], _verdicts(reports))

    def test_padded_items_under_a_cap_are_a_candidate(self):
        # 20 items, each padded to 30 KB: 600 KB without any unbounded list.
        self._assert_candidate(self._run(lambda limit: {"items": _items(min(limit, 20), pad="x" * 30000)}))

    def test_capping_server_with_large_items_is_a_candidate(self):
        self._assert_candidate(self._run(lambda limit: {"items": _items(min(limit, 100), blob="y" * 6000)}))

    def test_response_growing_for_another_reason_is_a_candidate(self):
        # A capped list beside a large audit trail of timestamps that never
        # follows the limit: the size does not come from the requested count.
        audit = [f"2026-10-20T00:{i // 60 % 60:02d}:{i % 60:02d}Z" for i in range(30000)]
        self._assert_candidate(self._run(lambda limit: {"items": _items(min(limit, 20)), "audit": audit}))

    def test_uncapped_list_that_follows_the_limit_confirms(self):
        sent = []
        reports = self._run(lambda limit: {"items": _items(min(limit, 5000))}, sent)
        self.assertEqual([r.status for r in reports], ["confirmed"], _text(reports))
        self.assertEqual(sent, [999999, 2])

    def test_uncapped_large_response_still_confirms(self):
        reports = self._run(lambda limit: {"items": _items(min(limit, 5000), desc="z" * 150)})
        self.assertEqual([r.status for r in reports], ["confirmed"], _text(reports))

    def test_small_dataset_stays_negative(self):
        reports = self._run(lambda limit: {"items": _items(min(limit, 50))})
        self.assertEqual([r.status for r in reports], ["not_confirmed"], _verdicts(reports))

    def test_declared_cap_the_list_respects_is_not_confirmed(self):
        reports = self._run(lambda limit: {"limit": min(limit, 2000), "items": _items(min(limit, 2000))})
        self.assertFalse(any(r.confirmed for r in reports), _text(reports))


# ------------------------------------------------- L6 SafetyGate headroom
class MutatingHeadroomAccessorTests(unittest.TestCase):
    """L6: a public, read-only view of a finding's remaining mutating sends."""

    def test_headroom_reports_remaining_used_and_ceiling(self):
        gate = SafetyGate(SafetyGateConfig(max_mutating_requests_per_finding=3))
        self.assertEqual(gate.mutating_headroom("f1"), (3, 0, 3))
        self.assertTrue(gate._reserve_mutating("f1", 2)[0])
        self.assertEqual(gate.mutating_headroom("f1"), (1, 2, 3))

    def test_reading_headroom_reserves_nothing(self):
        gate = SafetyGate(SafetyGateConfig(max_mutating_requests_per_finding=2))
        for _ in range(5):
            gate.mutating_headroom("f1")
        self.assertEqual(gate._mutating_counts, {})
        self.assertTrue(gate._reserve_mutating("f1", 2)[0])

    def test_per_check_ceiling_and_hard_maximum_apply(self):
        gate = SafetyGate(SafetyGateConfig(max_mutating_requests_per_finding=1,
                                           mutating_ceiling_by_check={"ssti": 500}))
        self.assertEqual(gate.mutating_headroom("f1", "ssti"),
                         (safety_gate.HARD_MAX_MUTATING_REQUESTS_PER_FINDING, 0,
                          safety_gate.HARD_MAX_MUTATING_REQUESTS_PER_FINDING))
        self.assertEqual(gate.mutating_headroom("f1", "other")[2], 1)


class SstiUsesPublicHeadroomTests(_RvlBase):
    """L6: the stored-SSTI affordability check reads the public accessor and
    fails closed when it cannot."""

    ORIGIN = "http://shop.invalid"

    def _stored(self, ceiling=2):
        cfg = _config()
        cfg["server"]["allowed_hosts"] = ["shop.invalid"]
        cfg["validators"].update(active_enabled=True, allow_mutating_replay=True,
                                 mutating_ceiling_by_check={"ssti": ceiling})
        orch = Orchestrator(cfg)
        orch.validator_registry.validators = {
            "ssti": SstiValidator(allowed_hosts=["shop.invalid"], readback_urls=[self.ORIGIN + "/page"])}
        ex = _exchange(self.ORIGIN + "/settings", {"Content-Type": "application/x-www-form-urlencoded"})
        ex.method, ex.request_body = "POST", "display=original"
        state, sent = {"display": "original"}, []

        async def request(client, method, url, **kwargs):
            sent.append(method)
            if method == "POST":
                body = kwargs.get("content") or ""
                body = body.decode() if isinstance(body, bytes) else body
                state["display"] = parse_qs(body)["display"][0]
            text = "8633" if method == "GET" and state["display"] == "89*97" else "fixture"
            return _response(method, url, text=text)
        with patch.object(httpx.AsyncClient, "request", request):
            reports, _ = asyncio.run(orch._validate_findings(
                ex, [AgentReport(agent="ssti", model="fake", findings=[_finding("ssti")])]))
        return reports, state, sent

    def test_accessor_reporting_too_little_headroom_refuses_the_plant(self):
        with patch.object(SafetyGate, "mutating_headroom", lambda self, fid, name=None: (1, 1, 2),
                          create=True):
            reports, state, sent = self._stored()
        self.assertNotIn("POST", sent, "the plant was written without room for its restore")
        self.assertEqual(state["display"], "original")
        self.assertEqual([r.status for r in reports], ["blocked"], _verdicts(reports))
        self.assertIn("1 more mutating send", _text(reports))

    def test_unreadable_accessor_fails_closed(self):
        def broken(self, fid, name=None):
            raise RuntimeError("accounting unavailable")
        with patch.object(SafetyGate, "mutating_headroom", broken, create=True):
            reports, state, sent = self._stored()
        self.assertNotIn("POST", sent)
        self.assertEqual([r.status for r in reports], ["blocked"], _verdicts(reports))
        self.assertIn("cannot be read", _text(reports))

    def test_affordable_plant_still_confirms_and_restores(self):
        reports, state, sent = self._stored()
        self.assertEqual([r.status for r in reports], ["confirmed"], _verdicts(reports))
        self.assertEqual(sent.count("POST"), 2, sent)
        self.assertEqual(state["display"], "original")


# --------------------------------------------- L7 browser_xss and dom_xss
def _evaluate_logged(source: str) -> list[str]:
    """What a browser logs when a console.log(a*b) payload runs: the product."""
    return [str(int(a) * int(b)) for a, b in re.findall(r"console\.log\((\d+)\*(\d+)\)", source)]


def _injected(url: str, part: str) -> str:
    parts = urlsplit(url)
    return unquote_plus(parts.fragment if part == "fragment" else parts.query)


class _SourceEchoDriver:
    """A page that prints the injected text without running it: debug logging,
    an alert of the search term, an error message quoting the input."""

    def __init__(self, part, sinks=("console", "dialogs", "page_errors")):
        self.part, self.sinks, self.visits = part, sinks, []

    async def visit(self, url, **kwargs):
        self.visits.append(url)
        text = _injected(url, self.part)
        return ExecutionObservation(url=url, **{s: [text] for s in self.sinks})


class _DialogOnlyDriver(_SourceEchoDriver):
    """A page whose alert fired with the computed product, but whose console
    stayed silent (RV-O O8: was an alert of the nonce, which the payloads no
    longer carry)."""

    async def visit(self, url, **kwargs):
        self.visits.append(url)
        products = re.findall(r"alert\((\d+)\*(\d+)\)", _injected(url, self.part))
        return ExecutionObservation(url=url, dialogs=[f"alert:{int(a) * int(b)}" for a, b in products])


class _ComputingDriver(_SourceEchoDriver):
    """A page that runs the payload: its console carries the computed product."""

    async def visit(self, url, **kwargs):
        self.visits.append(url)
        return ExecutionObservation(url=url, console=_evaluate_logged(_injected(url, self.part)))


class ExecutionChallengeTests(_RvlBase):
    """L7: only an exact console event equal to the product a*b confirms (RV-O
    O8 added an exact dialog). The payload carries the operands, never the
    product, so an echo cannot match."""

    def _browser(self, driver):
        return self._validate("browser_xss", BrowserXssValidator(allowed_hosts=["shop.invalid"], driver=driver),
                              _finding("xss"), _exchange("http://shop.invalid/search?q=hello"))

    def _dom(self, driver):
        return self._validate("dom_xss", DomXssValidator(allowed_hosts=["shop.invalid"], driver=driver),
                              _finding("dom_xss"), _exchange("http://shop.invalid/page?ref=1"))

    # RV-O O8, owner decision 2026-10-21: an echo in a dialog, or a page error,
    # is a candidate to check by hand (inconclusive), no longer not_confirmed.
    # A console echo keeps its verdict, and no echo ever confirms.
    _ECHO = {"console": "not_confirmed", "dialogs": "inconclusive", "page_errors": "inconclusive"}

    def _assert_unconfirmed(self, reports, driver, status="not_confirmed"):
        self.assertTrue(driver.visits, "no page was visited -- vacuous")
        self.assertFalse(any(r.confirmed for r in reports), _text(reports))
        self.assertEqual([r.status for r in reports], [status], _verdicts(reports))

    def test_browser_xss_echo_of_payload_source_is_not_execution(self):
        for sinks in (("console",), ("dialogs",), ("page_errors",)):
            with self.subTest(sinks=sinks):
                d = _SourceEchoDriver("query", sinks)
                self._assert_unconfirmed(self._browser(d), d, self._ECHO[sinks[0]])

    def test_dom_xss_echo_of_payload_source_is_not_execution(self):
        for sinks in (("console",), ("dialogs",), ("page_errors",)):
            with self.subTest(sinks=sinks):
                d = _SourceEchoDriver("fragment", sinks)
                self._assert_unconfirmed(self._dom(d), d, self._ECHO[sinks[0]])

    def test_browser_xss_dialog_alone_with_the_product_confirms(self):
        # RV-O O8, owner decision 2026-10-21 (was
        # test_browser_xss_dialog_alone_does_not_confirm, which wanted
        # not_confirmed): a dialog showing exactly the computed product is
        # execution, and the report says it was shown by the dialog only.
        d = _DialogOnlyDriver("query")
        reports = self._browser(d)
        self.assertEqual([r.status for r in reports], ["confirmed"], _text(reports))
        self.assertIn("dialog only", reports[0].summary)

    def test_browser_xss_computed_product_confirms(self):
        reports = self._browser(_ComputingDriver("query"))
        self.assertEqual([r.status for r in reports], ["confirmed"], _text(reports))

    def test_dom_xss_computed_product_confirms(self):
        reports = self._dom(_ComputingDriver("fragment"))
        self.assertEqual([r.status for r in reports], ["confirmed"], _text(reports))

    def test_payloads_carry_the_operands_never_the_product(self):
        for _ in range(50):
            for mod in (browser_xss_validator, dom_xss_validator):
                a, b, expected = mod._challenge()
                self.assertEqual(expected, str(a * b))
                payloads = (mod._payloads(a, b) if mod is browser_xss_validator  # RV-O O8: no nonce
                            else mod._fragment_payloads(a, b))
                for payload in payloads:
                    self.assertNotIn(expected, payload)
                    self.assertEqual(_evaluate_logged(payload), [expected], payload)


class _XssApp:
    """Owned loopback pages: /reflect echoes q raw into HTML; /echo escapes q and
    logs it to the console; /dom writes the fragment to innerHTML; /dom-log logs
    the fragment to the console."""

    def __init__(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                parts = urlsplit(self.path)
                q = dict(parse_qsl(parts.query)).get("q", "")
                logged = json.dumps(q).replace("<", "\\u003c")
                pages = {
                    "/reflect": f"<html><body>hello {q}</body></html>",
                    "/echo": (f"<html><body>hello {html.escape(q)}"
                              f"<script>console.log({logged})</script></body></html>"),
                    "/dom": ("<html><body><div id=out></div><script>document.getElementById('out')"
                             ".innerHTML = decodeURIComponent(location.hash.slice(1));</script></body></html>"),
                    "/dom-log": ("<html><body><script>console.log(decodeURIComponent("
                                 "location.hash.slice(1)));</script></body></html>"),
                }
                body = pages.get(parts.path)
                data = (body or "not found").encode("utf-8")
                self.send_response(200 if body else 404)
                self.send_header("Content-Type", "text/html" if body else "text/plain")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self._thread.join(5)


@unittest.skipUnless(browser_driver.playwright_available(), "playwright not installed")
class ExecutionChallengeRealBrowserTests(_RvlBase):
    """L7 with a real headless Chromium against the owned loopback pages."""

    def _run(self, key, cls, path, finding):
        app = _XssApp()
        self.addCleanup(app.close)
        v = cls(allowed_hosts=["127.0.0.1"], wait_ms=400)
        return self._validate(key, v, _finding(finding), _exchange(app.base + path), hosts=("127.0.0.1",))

    def test_browser_xss_raw_reflection_confirms(self):
        reports = self._run("browser_xss", BrowserXssValidator, "/reflect?q=hello", "xss")
        self.assertEqual([r.status for r in reports], ["confirmed"], _text(reports))

    def test_browser_xss_logged_payload_source_is_not_execution(self):
        reports = self._run("browser_xss", BrowserXssValidator, "/echo?q=hello", "xss")
        self.assertFalse(any(r.confirmed for r in reports), _text(reports))
        self.assertEqual([r.status for r in reports], ["not_confirmed"], _verdicts(reports))

    def test_dom_xss_hash_to_inner_html_confirms(self):
        reports = self._run("dom_xss", DomXssValidator, "/dom?ref=1", "dom_xss")
        self.assertEqual([r.status for r in reports], ["confirmed"], _text(reports))

    def test_dom_xss_logged_fragment_is_not_execution(self):
        reports = self._run("dom_xss", DomXssValidator, "/dom-log?ref=1", "dom_xss")
        self.assertFalse(any(r.confirmed for r in reports), _text(reports))
        self.assertEqual([r.status for r in reports], ["not_confirmed"], _verdicts(reports))


# ------------------------------------------- L8 MFA-bypass anonymous control
class _MfaApp:
    """Owned loopback app whose second factor is not enforced: the step-1
    session cookie already reaches the account page. The answer to a request
    without the session is set per test."""

    def __init__(self, anonymous):
        class Handler(BaseHTTPRequestHandler):
            def _send(self, status, body="", headers=None):
                data = body.encode("utf-8")
                self.send_response(status)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                self._send(302, headers={"Location": "/2fa/verify", "Set-Cookie": "sid=partial; Path=/"})

            def do_GET(self):
                if urlsplit(self.path).path == "/2fa/verify":
                    return self._send(200, "<html>Enter your verification code</html>")
                if "sid=partial" in (self.headers.get("Cookie") or ""):
                    return self._send(200, "<html>Account of alice. <a href='/logout'>Log out</a></html>")
                if anonymous == "drop":
                    self.close_connection = True  # no answer at all: a transport error
                    return None
                status, headers, body = anonymous
                return self._send(status, body, headers)

            def log_message(self, *args):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/login"
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self._thread.join(5)


class MfaAnonymousControlTests(_RvlBase):
    """L8: the MFA-bypass control needs an answer that denies the anonymous
    caller. A 5xx, a 404 or a transport error is not one, so the step-1
    session's access is a candidate naming the control's answer."""

    def _run(self, anonymous):
        app = _MfaApp(anonymous)
        self.addCleanup(app.close)
        return self._validate("auth_sequence", AuthSequenceValidator(allowed_hosts=["127.0.0.1"]),
                              _finding("2fa_bypass"),
                              _json_exchange(app.url, "POST", '{"username": "alice", "password": "pw"}'),
                              hosts=("127.0.0.1",))

    def _assert_candidate(self, reports, names):
        self.assertFalse(any(r.confirmed for r in reports), _text(reports))
        self.assertEqual([r.status for r in reports], ["inconclusive"], _verdicts(reports))
        self.assertIn(names, _text(reports))

    def test_anonymous_500_is_not_a_denial(self):
        self._assert_candidate(self._run((500, {}, "upstream failure")), "HTTP 500")

    def test_anonymous_503_is_not_a_denial(self):
        self._assert_candidate(self._run((503, {}, "maintenance")), "HTTP 503")

    def test_anonymous_404_is_not_a_denial(self):
        self._assert_candidate(self._run((404, {}, "not found")), "HTTP 404")

    def test_anonymous_transport_error_is_not_a_denial(self):
        self._assert_candidate(self._run("drop"), "Error")

    def test_anonymous_401_and_403_still_confirm(self):
        for status in (401, 403):
            with self.subTest(status=status):
                reports = self._run((status, {}, "login required"))
                self.assertEqual([r.status for r in reports], ["confirmed"], _text(reports))

    def test_step_up_redirect_is_unchanged(self):
        # Owner decision recorded in the RV-L handoff: a 302 to the 2FA step is
        # still read as a denial, as the leg fixture's /my-account does.
        reports = self._run((302, {"Location": "/2fa/verify"}, ""))
        self.assertEqual([r.status for r in reports], ["confirmed"], _text(reports))

    def test_public_page_is_negative(self):
        reports = self._run((200, {}, "<html>Account of alice. <a href='/logout'>Log out</a></html>"))
        self.assertEqual([r.status for r in reports], ["not_confirmed"], _verdicts(reports))


if __name__ == "__main__":
    unittest.main()
