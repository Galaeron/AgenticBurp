"""Code review 02, batch RV-P: validators whose broad ``except`` swallowed a
failed send. RV-L's record-only sweep could not reach these validators (their
preconditions declined its exchanges), so each test here first builds an
exchange that passes the validator's preconditions.

The rule, as RV-L: every send failing is ``blocked`` (refused by scope, gate or
budget) or inconclusive (transport failure), naming the failed sends; a partial
failure that leaves a confirming probe unsent is inconclusive, never a negative
or a pass. A real positive still confirms and completed probes with no finding
stay an executed negative.

Every test drives the production caller, ``Orchestrator._validate_findings``,
inside an explicit run seeded with the captured session as production
``analyze()`` does, with the transport faked below the gated client and the
executor so the gate and the run budget decide.
"""
import asyncio
import base64
import json
import pickle
import re
import secrets
import unittest
from unittest.mock import patch
from urllib.parse import parse_qsl, unquote_plus, urlsplit

import httpx

from harness import browser_driver, safety_gate
from harness.models import AgentReport
from harness.run_context import _CREDENTIAL_HEADERS, RunContext, ScopePolicy
from harness.test_confirmation_soundness_rve import _finding, _json_exchange, _verdicts
from harness.test_default_history_caller import _exchange
from harness.test_unsent_not_negative_rvl import _Collaborator, _RvlBase, _refuse_all, _response, _text
from harness.validators.client_trust_validator import ClientTrustValidator
from harness.validators.csrf_validator import CsrfValidator
from harness.validators.deserialization_oob_validator import DeserializationOobValidator
from harness.validators.file_upload_validator import FileUploadValidator
from harness.validators.jwt_forge_validator import JwtForgeValidator
from harness.validators.path_traversal_validator import PathTraversalValidator
from harness.validators.rate_limit_validator import RateLimitValidator
from harness.validators.reset_token_validator import ResetTokenValidator
from harness.validators.toctou_validator import ToctouValidator
from harness.validators.verb_tamper_validator import VerbTamperValidator

_HOSTS = ["shop.invalid"]


def _body(kwargs) -> str:
    raw = kwargs.get("content")
    if isinstance(raw, bytes):
        return raw.decode("utf-8", "replace")
    return raw or ""


def _connect_error(method, url):
    return httpx.ConnectError("synthetic refused connection", request=httpx.Request(method, url))


# unittest.TestCase is named explicitly so the static orphan-test guard collects these.
class _RvpBase(_RvlBase, unittest.TestCase):
    BURST = 5

    def _orch(self, hosts=("shop.invalid",)):
        orch = super()._orch(hosts)
        # The burst legs (rate_limit, toctou) need a burst ceiling above the safe default of 1.
        orch.config["validators"]["max_burst_size"] = self.BURST
        safety_gate.get_default_gate().config.max_burst_size = self.BURST
        return orch

    def _run_in(self, key, validator, finding, exchange, fake, *, max_requests=500, mutating=True):
        """As production analyze(): an explicit run seeded with the captured
        session (orchestrator_detect registers it before validation), so a
        credential-bearing replay binds to it instead of failing closed."""
        orch = self._orch()
        orch.validator_registry.validators = {key: validator}
        gate_config = {"active_enabled": True, "allow_mutating_replay": mutating,
                       "max_burst_size": self.BURST}

        async def go():
            async with RunContext.create(allowed_hosts=list(_HOSTS), max_requests=max_requests,
                                         gate_config=gate_config) as run:
                creds = {k: v for k, v in (exchange.request_headers or {}).items()
                         if k.lower() in _CREDENTIAL_HEADERS}
                if creds:
                    run.sessions.register("captured", "captured", creds, name="captured",
                                          allowed_origins=[ScopePolicy.origin_of(exchange.url)])
                return await orch._validate_findings(
                    exchange, [AgentReport(agent=key, model="fake", findings=[finding])],
                    run_context=run)
        with patch.object(httpx.AsyncClient, "request", fake):
            reports, _proofs = asyncio.run(go())
        self.assertTrue(reports, "the validator was not dispatched")
        return reports

    def _assert_negative(self, reports):
        self.assertEqual([r.status for r in reports], ["not_confirmed"], _verdicts(reports))
        self.assertFalse(any(r.confirmed for r in reports), _verdicts(reports))

    def _assert_confirmed(self, reports):
        self.assertEqual([r.status for r in reports], ["confirmed"], _verdicts(reports))
        self.assertTrue(all(r.confirmed for r in reports), _verdicts(reports))


# ------------------------------------------------------------- P1 client_trust
def _shop(sent, *, fail=lambda method, url: False, token=None, stores=True):
    """A cart whose add-to-cart write either stores the client's price
    (stores=True, the bug) or re-derives its own. With `token`, the write needs
    that CSRF token, which the source page /cart/add renders in a form."""
    state = {"cents": None}

    async def request(client, method, url, **kwargs):
        u = str(url)
        sent.append((method, u))
        if fail(method, u):
            raise _connect_error(method, u)
        path = urlsplit(u).path
        if method == "POST":
            fields = dict(parse_qsl(_body(kwargs), keep_blank_values=True))
            if token is not None and fields.get("csrf") != token:
                return _response(method, u, 403, "invalid csrf token")
            if stores:
                state["cents"] = int(fields["price"])
            return _response(method, u, text="added to cart")
        if path == "/cart/add":
            return _response(method, u, text=(
                '<html><form action="/cart/add" method="post">'
                f'<input name="csrf" value="{token or "t"}"><input name="price" value="1999">'
                '</form></html>'), headers={"content-type": "text/html"})
        if path == "/cart":
            cents = state["cents"] if state["cents"] is not None else 1999
            return _response(method, u, text=f"<p>Total: ${cents // 100}.{cents % 100:02d}</p>")
        return _response(method, u, text="<p>nothing here</p>")
    return request


class ClientTrustUnsentTests(_RvpBase):
    """P1: a tamper whose read-backs never answered is not a negative."""

    def _ex(self, body="productId=1&price=1999&quantity=1"):
        ex = _exchange("http://shop.invalid/cart/add",
                       {"Cookie": "session=abc", "Content-Type": "application/x-www-form-urlencoded"})
        ex.method, ex.request_body = "POST", body
        return ex

    def _run(self, fake, ex=None, **run):
        v = ClientTrustValidator(allowed_hosts=_HOSTS, timeout=1.0)
        return self._run_in("client_trust", v, _finding("business_logic"), ex or self._ex(), fake, **run)

    def test_read_backs_failing_after_an_accepted_write_are_not_a_negative(self):
        sent = []
        reports = self._run(_shop(sent, fail=lambda m, u: m == "GET"))
        self.assertTrue(any(m == "POST" for m, _ in sent), "the write was never attempted -- vacuous")
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("ConnectError", _text(reports))

    def test_one_read_back_failing_is_not_a_negative(self):
        sent = []
        reports = self._run(_shop(sent, stores=False, fail=lambda m, u: u.endswith("/cart")))
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("/cart", _text(reports))

    def test_read_backs_refused_by_the_run_budget_are_not_a_negative(self):
        # The write spends the only request; every read-back is refused.
        reports = self._run(_shop([]), max_requests=1)
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("refused", _text(reports))

    def test_csrf_refresh_failing_before_a_rejected_write_is_not_a_negative(self):
        sent = []
        ex = self._ex("csrf=stale&productId=1&price=1999")
        reports = self._run(_shop(sent, token="fresh", fail=lambda m, u: m == "GET"), ex)
        self.assertIn("POST", [m for m, _ in sent])
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("csrf", _text(reports).lower())

    def test_every_send_failing_is_still_an_error(self):
        sent = []
        reports = self._run(_refuse_all(sent))
        self.assertTrue(sent)
        self.assertEqual([r.status for r in reports], ["error"], _verdicts(reports))

    # -- controls
    def test_stored_client_price_still_confirms(self):
        self._assert_confirmed(self._run(_shop([])))

    def test_refreshed_csrf_token_still_confirms(self):
        self._assert_confirmed(self._run(_shop([], token="fresh"), self._ex("csrf=stale&productId=1&price=1999")))

    def test_answered_read_backs_without_the_sentinel_stay_negative(self):
        self._assert_negative(self._run(_shop([], stores=False)))

    def test_answered_rejection_with_a_refreshed_token_stays_negative(self):
        # The source page answers but carries no matching token: the harness did
        # what it could, so the rejection is an executed negative.
        async def fake(client, method, url, **kwargs):
            if method == "POST":
                return _response(method, str(url), 403, "forbidden")
            return _response(method, str(url), text="<p>no form</p>", headers={"content-type": "text/html"})
        reports = self._run(fake, self._ex("csrf=stale&productId=1&price=1999"))
        self._assert_negative(reports)


# --------------------------------------------------------------------- P2 csrf
class _PocDriver:
    def __init__(self, error=None, result=None):
        self.error, self.result, self.calls = error, result, 0

    async def cross_site_submit(self, **kwargs):
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.result


async def _accept(client, method, url, **kwargs):
    return _response(method, str(url), text="saved")


class CsrfSwallowedPocTests(_RvpBase):
    """P2: the swallowed cross-site PoC failure never produced a negative. The
    replay's own failures already end `error` or `skipped`, and a PoC that
    errored falls back to the same NEEDS-MANUAL-CHECK observation as a PoC that
    is off. Sound; these tests hold that evidence (no code change)."""

    def _ex(self):
        ex = _exchange("http://shop.invalid/account/email",
                       {"Cookie": "session=abc", "Content-Type": "application/x-www-form-urlencoded"})
        ex.method, ex.request_body = "POST", "email=alice%40example.com&csrf=tok123"
        return ex

    def _run(self, fake, driver=None, poc=True):
        v = CsrfValidator(allowed_hosts=_HOSTS, timeout=1.0, cross_site_poc_enabled=poc,
                          cross_site_readback_url=lambda u: "http://shop.invalid/account")
        with patch.object(browser_driver, "default_driver", return_value=driver):
            return self._run_in("csrf", v, _finding("csrf"), self._ex(), fake)

    def test_errored_poc_gives_the_same_observation_as_no_poc(self):
        driver = _PocDriver(error=RuntimeError("browser crashed"))
        errored = self._run(_accept, driver)
        off = self._run(_accept, None, poc=False)
        self.assertEqual(driver.calls, 1, "the PoC was not attempted -- vacuous")
        for reports in (errored, off):
            self.assertEqual([(r.status, r.confirmed) for r in reports], [("not_confirmed", False)])
            self.assertIn("OBSERVATION (not confirmed)", reports[0].summary)
            self.assertIn("NEEDS MANUAL CHECK", reports[0].evidence + _manual(reports))
        self.assertEqual([r.summary for r in errored], [r.summary for r in off])

    def test_every_replay_send_failing_is_an_error_not_a_negative(self):
        sent = []
        reports = self._run(_refuse_all(sent), _PocDriver(error=RuntimeError("unused")))
        self.assertTrue(sent)
        self.assertEqual([r.status for r in reports], ["error"], _verdicts(reports))


def _manual(reports):
    return " ".join(r.manual_verification or "" for r in reports)


# --------------------------------------------------------- P3 deserialization_oob
def _pickle_cookie():
    return base64.b64encode(pickle.dumps({"user": "alice", "role": "user"})).decode()


def _unpickling_target(collab, sent, *, executes=True, fail=lambda i, url: None):
    """The target 'unpickles' the session cookie: a beacon carrying a collaborator
    token records a hit. `fail(i, url)` may return an exception class to raise
    for send i (after the hit when the exception is a read-side failure)."""
    async def request(client, method, url, **kwargs):
        u = str(url)
        sent.append((method, u))
        i = len(sent)
        headers = {k.lower(): v for k, v in (kwargs.get("headers") or {}).items()}
        cookie = headers.get("cookie", "")
        exc = fail(i, u)
        if exc is httpx.ConnectError:
            raise _connect_error(method, u)
        if executes:
            for part in cookie.split(";"):
                _, _, value = part.strip().partition("=")
                try:
                    raw = base64.b64decode(value + "===")
                except Exception:
                    continue
                collab.hits.update(t for t in collab.issued if t.encode() in raw)
        if exc is not None:
            raise exc("synthetic read failure", request=httpx.Request(method, u))
        return _response(method, u, text="<p>welcome back</p>")
    return request


class DeserializationOobUnsentTests(_RvpBase):
    """P3: no callback after beacons that never reached the target is not a negative."""

    def _ex(self):
        return _exchange("http://shop.invalid/profile", {"Cookie": f"session={_pickle_cookie()}"})

    def _run(self, fake, collab, **run):
        v = DeserializationOobValidator(allowed_hosts=_HOSTS, timeout=0.05, collaborator=collab)
        return self._run_in("deserialization_oob", v, _finding("deserialization"), self._ex(), fake, **run)

    def test_every_beacon_failing_is_not_a_negative(self):
        sent = []
        reports = self._run(_refuse_all(sent), _Collaborator())
        self.assertEqual(len(sent), 2)
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("ConnectError", _text(reports))

    def test_every_beacon_refused_is_blocked(self):
        reports = self._run(_refuse_all([]), _Collaborator(), max_requests=0)
        self._assert_not_negative(reports, "blocked")

    def test_one_beacon_failing_is_not_a_negative(self):
        collab = _Collaborator()
        fake = _unpickling_target(collab, [], executes=False,
                                  fail=lambda i, u: httpx.ConnectError if i == 1 else None)
        self._assert_not_negative(self._run(fake, collab), "inconclusive")

    def _direct(self, fake, collab):
        """Outside a run (a direct validate() caller): the transport's exception
        class reaches the validator. Inside a run the gated client re-raises
        every transport error as ConnectError (safety_gate keeps only the
        message), so the in-run tests below cannot tell a timed-out beacon
        from one that never connected."""
        self._orch()
        v = DeserializationOobValidator(allowed_hosts=_HOSTS, timeout=0.05, collaborator=collab)
        with patch.object(httpx.AsyncClient, "request", fake):
            return [asyncio.run(v.validate(_finding("deserialization"), self._ex()))]

    def test_a_delivered_beacon_whose_response_timed_out_still_confirms(self):
        collab = _Collaborator()
        fake = _unpickling_target(collab, [], fail=lambda i, u: httpx.ReadTimeout)
        self._assert_confirmed(self._direct(fake, collab))

    def test_a_timed_out_beacon_without_callback_is_inconclusive(self):
        collab = _Collaborator()
        fake = _unpickling_target(collab, [], executes=False, fail=lambda i, u: httpx.ReadTimeout)
        reports = self._direct(fake, collab)
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("ReadTimeout", _text(reports))
        self.assertIn("still waited on", _text(reports))

    def test_a_timed_out_beacon_in_a_run_is_inconclusive(self):
        collab = _Collaborator()
        fake = _unpickling_target(collab, [], executes=False, fail=lambda i, u: httpx.ReadTimeout)
        self._assert_not_negative(self._run(fake, collab), "inconclusive")

    def test_a_refused_connection_is_not_waited_on(self):
        collab = _Collaborator()
        waited = []
        real_wait = collab.wait_for_hit

        async def wait(token, timeout=0.0):
            waited.append(token)
            return await real_wait(token, timeout)
        collab.wait_for_hit = wait
        reports = self._direct(_refuse_all([]), collab)
        self._assert_not_negative(reports, "inconclusive")
        self.assertEqual(waited, [])

    # -- controls
    def test_callback_confirms(self):
        collab = _Collaborator()
        self._assert_confirmed(self._run(_unpickling_target(collab, []), collab))

    def test_answered_beacons_without_callback_stay_negative(self):
        collab = _Collaborator()
        self._assert_negative(self._run(_unpickling_target(collab, [], executes=False), collab))


# --------------------------------------------------------------- P4 rate_limit
def _login(sent, *, fail=lambda i: False, throttle_at=None):
    async def request(client, method, url, **kwargs):
        u = str(url)
        sent.append((method, u))
        i = len(sent)
        if fail(i):
            raise _connect_error(method, u)
        if throttle_at is not None and i >= throttle_at:
            return _response(method, u, 429, "too many requests")
        return _response(method, u, text='{"ok": true}')
    return request


class RateLimitUnsentTests(_RvpBase):
    """P4: failed attempts are never counted as 'not rate limited'."""

    def _ex(self):
        ex = _exchange("http://shop.invalid/login", {"Content-Type": "application/x-www-form-urlencoded"})
        ex.method, ex.request_body = "POST", "user=alice&pass=pw"
        return ex

    def _run(self, fake, **run):
        v = RateLimitValidator(allowed_hosts=_HOSTS, timeout=1.0, min_attempts=5)
        return self._run_in("rate_limit", v, _finding("rate_limit"), self._ex(), fake, **run)

    def test_attempts_failing_after_answered_ones_are_not_no_throttle(self):
        sent = []
        reports = self._run(_login(sent, fail=lambda i: i > 2))
        self.assertEqual(len(sent), 5)
        self._assert_not_negative(reports, "inconclusive")
        self.assertNotIn("OBSERVATION", _text(reports))

    def test_attempts_refused_by_the_run_budget_are_not_no_throttle(self):
        reports = self._run(_login([]), max_requests=2)
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("refused", _text(reports))

    def test_every_attempt_failing_is_skipped(self):
        reports = self._run(_refuse_all([]))
        self.assertEqual([r.status for r in reports], ["skipped"], _verdicts(reports))

    # -- controls
    def test_a_429_still_counts_as_limiting_when_other_attempts_failed(self):
        reports = self._run(_login([], fail=lambda i: i in (1, 2), throttle_at=3))
        self._assert_negative(reports)
        self.assertIn("IS limited", reports[0].summary)

    def test_all_attempts_answered_without_throttle_stay_an_observation(self):
        reports = self._run(_login([]))
        self._assert_negative(reports)
        self.assertIn("OBSERVATION (not confirmed): 5 rapid", reports[0].summary)


# ------------------------------------------------------------------- P5 toctou
def _account(sent, *, vulnerable=True, fail=lambda method, i: False):
    state = {"id": 1, "name": "bob", "role": "user"}

    async def request(client, method, url, **kwargs):
        u = str(url)
        sent.append((method, u))
        if fail(method, len(sent)):
            raise _connect_error(method, u)
        if method == "GET":
            return _response(method, u, text=json.dumps(state), headers={"content-type": "application/json"})
        if vulnerable:
            state.update(json.loads(_body(kwargs) or "{}"))
        return _response(method, u, text='{"saved": true}')
    return request


class ToctouUnsentTests(_RvpBase):
    """P5: a race whose burst or verify read never answered is not a negative."""

    def _ex(self):
        return _json_exchange("http://shop.invalid/api/users/1", "PUT", '{"name": "bob"}')

    def _run(self, fake, **run):
        v = ToctouValidator(allowed_hosts=_HOSTS, timeout=1.0, burst_size=3)
        return self._run_in("toctou", v, _finding("toctou"), self._ex(), fake, **run)

    def test_every_burst_send_failing_is_not_a_negative(self):
        sent = []
        reports = self._run(_account(sent, fail=lambda m, i: m == "PUT"))
        self.assertEqual(sum(1 for m, _ in sent if m == "PUT"), 3)
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("ConnectError", _text(reports))

    def test_burst_refused_by_the_run_budget_is_blocked(self):
        # The baseline read spends the only request.
        reports = self._run(_account([]), max_requests=1)
        self._assert_not_negative(reports, "blocked")

    def test_verify_read_refused_is_not_a_negative(self):
        # Baseline + 3 burst sends spend the budget; the verify read is refused.
        reports = self._run(_account([]), max_requests=4)
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("verify read", _text(reports))

    def test_burst_partly_failing_is_not_a_negative(self):
        reports = self._run(_account([], vulnerable=False, fail=lambda m, i: m == "PUT" and i > 2))
        self._assert_not_negative(reports, "inconclusive")

    def test_flip_with_failed_burst_sends_is_not_called_a_plain_mass_assignment(self):
        reports = self._run(_account([], fail=lambda m, i: m == "PUT" and i > 2))
        self._assert_not_negative(reports, "inconclusive")

    # -- controls
    def test_flip_under_an_answered_burst_still_confirms(self):
        self._assert_confirmed(self._run(_account([])))

    def test_answered_burst_without_flip_stays_negative(self):
        self._assert_negative(self._run(_account([], vulnerable=False)))


# -------------------------------------------------------------- P6 verb_tamper
def _admin(sent, *, fail=lambda method, url: False, opens=None):
    async def request(client, method, url, **kwargs):
        u = str(url)
        sent.append((method, u))
        if fail(method, u):
            raise _connect_error(method, u)
        if method == opens:
            return _response(method, u, text='{"panel": "admin settings", "users": 42}')
        return _response(method, u, 403, "forbidden")
    return request


class VerbTamperUnsentTests(_RvpBase):
    """P6: alternate methods and overrides that never answered are not a negative."""

    def _ex(self):
        ex = _exchange("http://shop.invalid/admin/panel", {"Cookie": "session=abc"})
        ex.response_status = 403
        return ex

    def _run(self, fake, **run):
        v = VerbTamperValidator(allowed_hosts=_HOSTS, timeout=1.0)
        return self._run_in("verb_tamper", v, _finding("verb_tamper"), self._ex(), fake, **run)

    def test_every_send_failing_is_not_a_negative(self):
        sent = []
        reports = self._run(_refuse_all(sent))
        self.assertEqual(len(sent), 5)
        self._assert_not_negative(reports, "inconclusive")

    def test_every_send_refused_is_blocked(self):
        reports = self._run(_admin([]), max_requests=0)
        self._assert_not_negative(reports, "blocked")

    def test_override_posts_refused_by_the_gate_are_not_a_negative(self):
        # allow_mutating_replay off: the safe alternates answer 403, the three
        # override POSTs are refused. "No bypass ... with override headers" was
        # claimed although no override was ever sent.
        sent = []
        reports = self._run(_admin(sent), mutating=False)
        self.assertEqual(sorted(m for m, _ in sent), ["HEAD", "OPTIONS"])
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("X-HTTP-Method-Override", _text(reports))

    # -- controls
    def test_open_alternate_method_is_still_the_observation(self):
        reports = self._run(_admin([], opens="OPTIONS"))
        self._assert_negative(reports)
        self.assertIn("OBSERVATION (not confirmed)", reports[0].summary)

    def test_alternate_found_before_a_failure_is_still_the_observation(self):
        reports = self._run(_admin([], opens="HEAD", fail=lambda m, u: m == "OPTIONS"))
        self.assertIn("OBSERVATION (not confirmed)", reports[0].summary)

    def test_answered_denials_stay_negative(self):
        self._assert_negative(self._run(_admin([])))


# ----------------------------------------------------------- P7 path_traversal
def _files(sent, *, fail=lambda url: False, reads=False):
    async def request(client, method, url, **kwargs):
        u = unquote_plus(str(url))
        sent.append((method, u))
        if fail(u):
            raise _connect_error(method, u)
        if reads and "../etc/passwd" in u:
            return _response(method, u, text="root:x:0:0:root:/root:/bin/bash\n")
        return _response(method, u, 404, "not found")
    return request


class PathTraversalUnsentTests(_RvpBase):
    """P7: traversal probes that never answered are not a negative."""

    def _ex(self):
        return _exchange("http://shop.invalid/download?file=report.pdf", {"Cookie": "session=abc"})

    def _run(self, fake, **run):
        v = PathTraversalValidator(allowed_hosts=_HOSTS, timeout=1.0)
        return self._run_in("path_traversal", v, _finding("path_traversal"), self._ex(), fake, **run)

    def test_every_probe_failing_is_not_a_negative(self):
        sent = []
        reports = self._run(_refuse_all(sent))
        self.assertTrue(sent)
        self._assert_not_negative(reports, "inconclusive")

    def test_answered_probes_without_a_session_stay_negative(self):
        # RV-L's sweep shape: no captured credentials, so the scope lock (not the
        # session's origin check) refuses the backslash path-segment payload.
        sent = []
        ex = _exchange("http://shop.invalid/download?file=report.pdf", {})
        reports = self._run_in("path_traversal", PathTraversalValidator(allowed_hosts=_HOSTS, timeout=1.0),
                               _finding("path_traversal"), ex, _files(sent))
        self._assert_negative(reports)
        # 2 injection points x 8 encodings x 2 files = 32 probes; only the two
        # backslash path-segment payloads cannot be sent. Before the fix the
        # leg stopped at the first of them and reported "declined".
        self.assertEqual(len(sent), 30, "the leg stopped at the first refused payload")
        self.assertIn("could not be sent", reports[0].evidence)

    def test_every_probe_refused_is_skipped(self):
        # Kept as the declined-leg skip: test_traversal_redirect_legs pins
        # "skipped" for a leg the run refused before anything was sent, and a
        # skip is not a negative.
        reports = self._run(_files([]), max_requests=0)
        self.assertEqual([r.status for r in reports], ["skipped"], _verdicts(reports))
        self.assertFalse(any(r.confirmed for r in reports))
        self.assertIn("budget_exhausted", _text(reports))

    def test_probes_failing_after_answered_ones_are_not_a_negative(self):
        sent = []
        reports = self._run(_files(sent, fail=lambda u: len(sent) > 3))
        self._assert_not_negative(reports, "inconclusive")

    def test_budget_ending_mid_leg_is_not_a_negative(self):
        reports = self._run(_files([]), max_requests=5)
        self._assert_not_negative(reports, "inconclusive")

    # -- controls
    def test_file_read_still_confirms(self):
        self._assert_confirmed(self._run(_files([], reads=True)))

    def test_answered_probes_stay_negative(self):
        self._assert_negative(self._run(_files([])))


# -------------------------------------------------------------- P9 file_upload
def _uploads(sent, *, fail=lambda method, url: False, token=None, serves=True):
    stored = {}

    async def request(client, method, url, **kwargs):
        u = str(url)
        sent.append((method, u))
        if fail(method, u):
            raise _connect_error(method, u)
        path = urlsplit(u).path
        if method == "POST":
            # The run transport sends the multipart form already encoded.
            body = _body(kwargs)
            csrf = re.search(r'name="csrf"\r\n\r\n(.*?)\r\n', body)
            if token is not None and (csrf.group(1) if csrf else None) != token:
                return _response(method, u, 403, "invalid csrf token")
            part = re.search(r'filename="([^"]+)"\r\n[^\r\n]*\r\n\r\n(.*?)\r\n--', body, re.S)
            if part:
                stored[f"/uploads/{part.group(1)}"] = part.group(2)
                return _response(method, u, text=json.dumps({"url": f"/uploads/{part.group(1)}"}),
                                 headers={"content-type": "application/json"})
        if path in stored and serves:
            return _response(method, u, text=stored[path], headers={"content-type": "text/html"})
        if path in ("/profile", "/profile/avatar"):
            return _response(method, u, text=(
                '<html><form action="/profile/avatar" method="post" enctype="multipart/form-data">'
                f'<input type="hidden" name="csrf" value="{token or "t"}">'
                '<input type="file" name="avatar"></form></html>'), headers={"content-type": "text/html"})
        return _response(method, u, 404, "not found")
    return request


class FileUploadPartialTests(_RvpBase):
    """P9: an accepted upload whose fetch-backs never answered is not a negative;
    nor is a rejection after the in-session form (and its token) could not be read."""

    def _ex(self):
        ex = _exchange("http://shop.invalid/profile/avatar", {"Cookie": "session=abc"})
        ex.method, ex.request_body = "POST", "csrf=stale&avatar=me.png"
        return ex

    def _run(self, fake, **run):
        v = FileUploadValidator(allowed_hosts=_HOSTS, timeout=1.0)
        return self._run_in("file_upload", v, _finding("file_upload"), self._ex(), fake, **run)

    def test_fetch_backs_failing_after_an_accepted_upload_are_not_a_negative(self):
        sent = []
        reports = self._run(_uploads(sent, fail=lambda m, u: m == "GET" and "/uploads/" in u))
        self.assertIn("POST", [m for m, _ in sent])
        self._assert_not_negative(reports, "inconclusive")

    def test_source_form_unreadable_before_a_rejected_upload_is_not_a_negative(self):
        sent = []
        reports = self._run(_uploads(sent, token="fresh", fail=lambda m, u: m == "GET"))
        self.assertIn("POST", [m for m, _ in sent])
        self._assert_not_negative(reports, "inconclusive")

    def test_every_send_failing_is_still_an_error(self):
        reports = self._run(_refuse_all([]))
        self.assertEqual([r.status for r in reports], ["error"], _verdicts(reports))

    # -- controls
    def test_stored_active_html_still_confirms(self):
        self._assert_confirmed(self._run(_uploads([], token="fresh")))

    def test_unserved_upload_stays_negative(self):
        self._assert_negative(self._run(_uploads([], serves=False)))

    def test_rejection_with_the_form_read_stays_negative(self):
        async def fake(client, method, url, **kwargs):
            if method == "POST":
                return _response(method, str(url), 403, "forbidden")
            return _response(method, str(url), text="<p>no form</p>", headers={"content-type": "text/html"})
        self._assert_negative(self._run(fake))


# ---------------------------------------------------------------- P9 jwt_forge
def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


_JWT_HEAD = _b64url(b'{"alg":"HS256","typ":"JWT"}') + "." + _b64url(b'{"sub":"1","role":"user"}')
_JWT = _JWT_HEAD + "." + _b64url(b"signature-not-real")
_GARBAGE_SIG = _b64url(b"not-a-valid-signature-xxxx")


def _api(sent, *, forged="reject", garbage_ok=False, tokenless="deny", accept_none=False):
    """The real token reads a profile; the garbage-signature control is rejected
    unless `garbage_ok`. `forged` decides every other token: reject, fail."""
    async def request(client, method, url, **kwargs):
        u = str(url)
        headers = {k.lower(): v for k, v in (kwargs.get("headers") or {}).items()}
        auth = headers.get("authorization", "")
        sent.append((method, u, auth[:20]))
        profile = _response(method, u, text='{"id": 1, "email": "alice@example.com"}')
        if not auth:
            if tokenless == "fail":
                raise _connect_error(method, u)
            if tokenless == "allow":
                return profile
            return _response(method, u, 401, '{"error": "login required"}')
        tok = auth.split()[-1]
        if tok == _JWT:
            return profile
        if tok.endswith(_GARBAGE_SIG):
            return profile if garbage_ok else _response(method, u, 401, '{"error": "bad signature"}')
        if accept_none and tok.endswith("."):
            return profile
        if forged == "fail":
            raise _connect_error(method, u)
        return _response(method, u, 401, '{"error": "bad signature"}')
    return request


class JwtForgePartialTests(_RvpBase):
    """P9: forgeries or controls that never answered are not 'all rejected'."""

    def _ex(self):
        return _exchange("http://shop.invalid/api/me", {"Authorization": f"Bearer {_JWT}"})

    def _run(self, fake, **run):
        v = JwtForgeValidator(allowed_hosts=_HOSTS, timeout=1.0)
        return self._run_in("jwt_forge", v, _finding("jwt"), self._ex(), fake, **run)

    def test_forgeries_failing_after_the_control_are_not_all_rejected(self):
        sent = []
        reports = self._run(_api(sent, forged="fail"))
        self.assertGreater(len(sent), 1)
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("ConnectError", _text(reports))

    def test_forgeries_refused_by_the_run_budget_are_not_all_rejected(self):
        reports = self._run(_api([]), max_requests=2)
        self._assert_not_negative(reports, "inconclusive")

    def test_tokenless_control_failing_is_not_called_an_ungated_endpoint(self):
        reports = self._run(_api([], garbage_ok=True, tokenless="fail"))
        self._assert_not_negative(reports, "inconclusive")
        self.assertNotIn("does not gate on the token", _text(reports))

    def test_every_send_failing_is_still_an_error(self):
        reports = self._run(_refuse_all([]))
        self.assertEqual([r.status for r in reports], ["error"], _verdicts(reports))

    # -- controls
    def test_alg_none_accepted_still_confirms(self):
        self._assert_confirmed(self._run(_api([], accept_none=True)))

    def test_unverified_signature_still_confirms(self):
        self._assert_confirmed(self._run(_api([], garbage_ok=True)))

    def test_answered_rejections_stay_negative(self):
        self._assert_negative(self._run(_api([])))

    def test_ungated_endpoint_is_still_skipped(self):
        reports = self._run(_api([], garbage_ok=True, tokenless="allow"))
        self.assertEqual([r.status for r in reports], ["skipped"], _verdicts(reports))


# -------------------------------------------------------------- P9 reset_token
def _reset(sent, *, fail=lambda i: False, sequential=False):
    async def request(client, method, url, **kwargs):
        u = str(url)
        sent.append((method, u))
        i = len(sent)
        if fail(i):
            raise _connect_error(method, u)
        tok = f"{100000 + i}" if sequential else secrets.token_hex(16)
        return _response(method, u, text=json.dumps({"reset_token": tok}))
    return request


class ResetTokenPartialTests(_RvpBase):
    """P9: samples that never answered leave the entropy check incomplete."""

    def _ex(self):
        ex = _exchange("http://shop.invalid/forgot-password", {"Content-Type": "application/x-www-form-urlencoded"})
        ex.method, ex.request_body = "POST", "email=alice%40example.com"
        return ex

    def _run(self, fake):
        return self._run_in("reset_token", ResetTokenValidator(allowed_hosts=_HOSTS, timeout=1.0, samples=5),
                            _finding("reset_token"), self._ex(), fake)

    def test_samples_failing_after_answered_ones_are_not_a_negative(self):
        sent = []
        # Three answered: two numeric samples would always share a constant delta.
        reports = self._run(_reset(sent, fail=lambda i: i > 3))
        self.assertEqual(len(sent), 5)
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("ConnectError", _text(reports))

    def test_every_sample_failing_is_still_skipped(self):
        reports = self._run(_refuse_all([]))
        self.assertEqual([r.status for r in reports], ["skipped"], _verdicts(reports))

    # -- controls
    def test_random_tokens_stay_negative(self):
        self._assert_negative(self._run(_reset([])))

    def test_sequential_tokens_stay_the_observation(self):
        reports = self._run(_reset([], sequential=True))
        self._assert_negative(reports)
        self.assertIn("OBSERVATION (not confirmed)", reports[0].summary)

    def test_pattern_seen_despite_failed_samples_is_still_the_observation(self):
        reports = self._run(_reset([], sequential=True, fail=lambda i: i == 5))
        self.assertIn("OBSERVATION (not confirmed)", reports[0].summary)


if __name__ == "__main__":
    unittest.main()
