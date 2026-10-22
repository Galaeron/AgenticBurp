"""Code review 02, batch RV-U: the validators RV-P's record-only sweep found
swallowing a failed send (U1 idor_read, U2 http_request_smuggling, U3
race_condition, U4 oauth, U5 subdomain_takeover, U6 crypto).

The rule, as RV-L and RV-P: a check whose sends failed, were refused or never
ran is not a negative. Every send refused is ``blocked``; every send failing in
transport is inconclusive; both name the failed sends. A partial failure that
leaves a confirming probe unsent is inconclusive. A fully answered run keeps
today's verdict, positive or negative.

Every test drives the production caller, ``Orchestrator._validate_findings``,
standalone (``_validate``) or inside an explicit run seeded with the captured
session (``_run_in``), with the transport faked below the gated client and the
executor so the gate and the run budget decide. Crypto opens a raw TLS socket,
so its socket and TLS layer are faked inside its own module instead.
"""
import asyncio
import re
import ssl
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import parse_qs, parse_qsl, unquote_plus, urlsplit

import httpx

from harness import run_context as run_context_module
from harness.models import AgentReport
from harness.run_context import _CREDENTIAL_HEADERS, RunContext, ScopePolicy
from harness.test_confirmation_soundness_rve import _finding, _verdicts
from harness.test_default_history_caller import _exchange
from harness.test_unsent_not_negative_rvl import _refuse_all, _response, _text
from harness.test_unsent_not_negative_rvp import _RvpBase, _body, _connect_error
from harness.validators import crypto_validator
from harness.validators.crypto_validator import CryptoValidator
from harness.validators.http_request_smuggling_validator import HttpRequestSmugglingValidator
from harness.validators.idor_read_validator import IdorReadValidator
from harness.validators.oauth_validator import OAuthValidator
from harness.validators.race_condition_validator import RaceConditionValidator
from harness.validators.subdomain_takeover_validator import SubdomainTakeoverValidator

_HOSTS = ("shop.invalid",)


def _headers(kwargs) -> dict:
    return {k.lower(): v for k, v in (kwargs.get("headers") or {}).items()}


# unittest.TestCase is named explicitly so the static orphan-test guard collects these.
class _RvuBase(_RvpBase, unittest.TestCase):
    def _run_in(self, key, validator, finding, exchange, fake, *, hosts=_HOSTS,
                max_requests=500, mutating=True):
        """RV-P's explicit run (the captured session registered, as production
        analyze() does), with the scope this test needs."""
        orch = self._orch(hosts=hosts)
        orch.validator_registry.validators = {key: validator}
        gate_config = {"active_enabled": True, "allow_mutating_replay": mutating,
                       "max_burst_size": self.BURST}

        async def go():
            async with RunContext.create(allowed_hosts=list(hosts), max_requests=max_requests,
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


# ---------------------------------------------------------------- U1 idor_read
def _orders(sent, *, fail=lambda url, anon: False, protected=True, denied=False):
    """alice's session reads order 1 (hers). Orders 2 and 3 are someone else's:
    served to the session (the candidate), or refused with 403 (denied=True).
    Without a session every order redirects to the login page (protected)."""
    async def request(client, method, url, **kwargs):
        u = str(url)
        anon = "cookie" not in _headers(kwargs)
        sent.append((u, anon))
        if fail(u, anon):
            raise _connect_error(method, u)
        req = httpx.Request(method, u)
        if anon and protected:
            return httpx.Response(302, headers={"Location": "/login"}, request=req)
        last = u.rsplit("/", 1)[-1]
        owner = {"1": "alice", "2": "bob", "3": "carol"}.get(last)
        if owner is None:
            return httpx.Response(404, text="not found", request=req)
        if owner != "alice" and denied:
            return httpx.Response(403, text="Access denied", request=req)
        return httpx.Response(200, request=req, text=(
            f"Order {last} for {owner}: 3 items, total ${last}9.00, ship to {owner} street"))
    return request


class IdorReadUnsentTests(_RvuBase):
    """U1: a foreign read that got no response is not 'access control held'."""

    def _ex(self):
        return _exchange("http://shop.invalid/orders/1", {"Cookie": "session=alice"})

    def _v(self):
        return IdorReadValidator(allowed_hosts=list(_HOSTS), timeout=1.0)

    def _run(self, fake):
        return self._validate("idor_read", self._v(), _finding("idor"), self._ex(), fake)

    def _foreign(self, url, anon):
        return not anon and url.rsplit("/", 1)[-1] in ("2", "0", "3")

    def test_foreign_reads_failing_are_not_a_negative(self):
        sent = []
        reports = self._run(_orders(sent, fail=self._foreign))
        self.assertIn(("http://shop.invalid/orders/2", False), sent, "no foreign read -- vacuous")
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("orders/2", _text(reports))
        self.assertNotIn("access control held", _text(reports))

    def test_one_foreign_read_failing_among_denials_is_not_a_negative(self):
        sent = []
        reports = self._run(_orders(sent, denied=True,
                                    fail=lambda u, anon: not anon and u.endswith("/orders/2")))
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("1 of 3", _text(reports))

    def test_foreign_reads_refused_by_the_run_budget_are_blocked(self):
        # The baseline and the absent-id control spend the budget; every foreign
        # read is refused before it is sent.
        sent = []
        reports = self._run_in("idor_read", self._v(), _finding("idor"), self._ex(),
                               _orders(sent, denied=True), max_requests=2)
        self.assertEqual(len(sent), 2)
        self._assert_not_negative(reports, "blocked")
        self.assertIn("budget_exhausted", _text(reports))

    def test_baseline_refused_is_blocked(self):
        # Before the fix: error "baseline request blocked or failed".
        sent = []
        reports = self._run_in("idor_read", self._v(), _finding("idor"), self._ex(),
                               _orders(sent), max_requests=0)
        self.assertEqual(sent, [])
        self._assert_not_negative(reports, "blocked")

    # -- controls
    def test_protected_foreign_object_is_still_the_candidate(self):
        reports = self._run(_orders([]))
        self.assertEqual([r.status for r in reports], ["inconclusive"], _verdicts(reports))
        self.assertIn("second identity", reports[0].summary)

    def test_candidate_found_before_a_failed_read_is_still_the_candidate(self):
        reports = self._run(_orders([], fail=lambda u, anon: not anon and u.endswith("/orders/3")))
        self.assertEqual([r.status for r in reports], ["inconclusive"], _verdicts(reports))
        self.assertIn("second identity", reports[0].summary)

    def test_answered_denials_stay_negative(self):
        reports = self._run(_orders([], denied=True))
        self._assert_negative(reports)
        self.assertIn("access control held", _text(reports))

    def test_baseline_transport_failure_is_still_an_error(self):
        sent = []
        reports = self._run(_refuse_all(sent))
        self.assertTrue(sent)
        self.assertEqual([r.status for r in reports], ["error"], _verdicts(reports))


# --------------------------------------------------- U2 http_request_smuggling
def _shop_front(sent, *, fail=lambda method, url: False, smuggled_404=False):
    """A clean front end answers every probe 200 with an ordinary page. With
    smuggled_404 the follow-up GET answers 404, the sampler's anomaly."""
    async def request(client, method, url, **kwargs):
        u = str(url)
        sent.append((method, u))
        if fail(method, u):
            raise _connect_error(method, u)
        if method == "GET" and smuggled_404:
            return _response(method, u, 404, "<p>nothing here</p>")
        return _response(method, u, text="<p>Your cart is ready</p>")
    return request


class SmugglingUnsentTests(_RvuBase):
    """U2: a smuggling probe that was never answered is not 'no anomalies'."""

    def _v(self):
        return HttpRequestSmugglingValidator(timeout=1.0, allowed_hosts=list(_HOSTS))

    def _ex(self):
        return _exchange("http://shop.invalid/cart")

    def _run(self, fake, **run):
        if run:
            return self._run_in("http_request_smuggling", self._v(),
                                _finding("http_request_smuggling"), self._ex(), fake, **run)
        return self._validate("http_request_smuggling", self._v(),
                              _finding("http_request_smuggling"), self._ex(), fake)

    def test_every_send_failing_is_not_a_negative(self):
        sent = []
        reports = self._run(_refuse_all(sent))
        self.assertTrue(sent)
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("ConnectError", _text(reports))
        self.assertNotIn("No HTTP Request Smuggling anomalies", _text(reports))

    def test_every_probe_refused_by_the_gate_is_blocked(self):
        # allow_mutating_replay off: every POST probe is refused, nothing is sent.
        sent = []
        reports = self._run(_shop_front(sent), mutating=False)
        self.assertEqual(sent, [])
        self._assert_not_negative(reports, "blocked")
        self.assertIn("refused", _text(reports))

    def test_follow_ups_failing_after_answered_probes_are_not_a_negative(self):
        # CL.TE and TE.CL decide on the follow-up GET; it never got an answer.
        sent = []
        reports = self._run(_shop_front(sent, fail=lambda m, u: m == "GET"))
        self.assertIn("POST", [m for m, _ in sent])
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("CL_TE", _text(reports))

    def test_one_te_te_variant_failing_is_not_a_negative(self):
        calls = {"n": 0}

        def fail(method, url):
            if method != "POST":
                return False
            calls["n"] += 1
            return calls["n"] == 4  # the second TE.TE variant
        reports = self._run(_shop_front([], fail=fail))
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("TE_TE", _text(reports))

    # -- controls
    def test_answered_clean_probes_stay_negative(self):
        reports = self._run(_shop_front([]))
        self._assert_negative(reports)
        self.assertIn("No HTTP Request Smuggling anomalies detected", reports[0].summary)

    def test_smuggled_404_is_still_the_candidate(self):
        reports = self._run(_shop_front([], smuggled_404=True))
        self.assertEqual([r.status for r in reports], ["not_confirmed"], _verdicts(reports))
        self.assertIn("CANDIDATE", reports[0].summary)
        self.assertFalse(reports[0].confirmed)


# ------------------------------------------------------------ U3 race_condition
def _coupon(sent, *, fail=lambda i: False, unlimited=False):
    """A coupon that applies once; every later redemption says 'already
    redeemed' unless unlimited (the race). fail(i) raises on the i-th send."""
    state = {"n": 0}

    async def request(client, method, url, **kwargs):
        u = str(url)
        state["n"] += 1
        i = state["n"]
        sent.append((method, u))
        if fail(i):
            raise _connect_error(method, u)
        if i == 1 or unlimited:
            return _response(method, u, text="coupon applied")
        return _response(method, u, text="coupon already redeemed")
    return request


class RaceBurstUnsentTests(_RvuBase):
    """U3: burst sends that got no response are not 'no race'."""

    def _ex(self):
        ex = _exchange("http://shop.invalid/coupon/redeem",
                       {"Cookie": "session=abc", "Content-Type": "application/x-www-form-urlencoded"})
        ex.method, ex.request_body = "POST", "code=SAVE10"
        return ex

    def _run(self, fake, **run):
        v = RaceConditionValidator(timeout=1.0)
        return self._run_in("race_condition", v, _finding("race_condition"), self._ex(), fake, **run)

    def test_burst_sends_failing_are_not_a_negative(self):
        sent = []
        reports = self._run(_coupon(sent, fail=lambda i: i > 2))
        self.assertEqual(len(sent), self.BURST)
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("3 of 5", _text(reports))

    def test_burst_sends_refused_by_the_run_budget_are_not_a_negative(self):
        sent = []
        reports = self._run(_coupon(sent), max_requests=3)
        self.assertEqual(len(sent), 3)
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("budget_exhausted", _text(reports))

    def test_single_answer_with_failed_remaining_sends_is_inconclusive(self):
        reports = self._run(_coupon([], fail=lambda i: i > 1))
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("4 of 5", _text(reports))

    def test_failed_send_diagnostics_redact_url_credentials_and_query(self):
        ex = self._ex()
        from harness.validators.send_failures import SendFailures
        self.assertEqual(
            SendFailures.label("POST", "http://diagnostic-user:diagnostic-secret@shop.invalid/coupon/redeem?token=query-secret"),
            "POST http://shop.invalid/coupon/redeem")
        # Credential-bearing URL origins are rejected before session registration;
        # exercise the production caller with its permitted query-token form.
        ex.url = "http://shop.invalid/coupon/redeem?token=query-secret"
        with patch.object(self, "_ex", return_value=ex):
            reports = self._run(_coupon([], fail=lambda i: i > 2))
        self._assert_not_negative(reports, "inconclusive")
        rendered = _text(reports)
        self.assertIn("shop.invalid/coupon/redeem", rendered)
        for secret in ("diagnostic-user", "diagnostic-secret", "query-secret"):
            self.assertNotIn(secret, rendered)

    def test_every_burst_send_refused_is_blocked(self):
        # Before the fix: error "Only 0/5 burst requests completed".
        sent = []
        reports = self._run(_coupon(sent), max_requests=0)
        self.assertEqual(sent, [])
        self._assert_not_negative(reports, "blocked")

    # -- controls
    def test_clean_successes_still_confirm(self):
        self._assert_confirmed(self._run(_coupon([], unlimited=True)))

    def test_clean_successes_despite_failed_sends_still_confirm(self):
        self._assert_confirmed(self._run(_coupon([], unlimited=True, fail=lambda i: i > 3)))

    def test_answered_rejections_stay_negative(self):
        self._assert_negative(self._run(_coupon([])))

    def test_every_burst_send_failing_is_still_an_error(self):
        sent = []
        reports = self._run(_refuse_all(sent))
        self.assertTrue(sent)
        self.assertEqual([r.status for r in reports], ["error"], _verdicts(reports))


_TARGET = "carlos@example.invalid"
_MAILBOX = "http://mail.invalid/email"


def _email_app(sent, *, vulnerable=False, fail=lambda method, url, state: False):
    """The change-email race: the controlled mailbox receives a confirmation
    link. Following it moves the account to the target address only when the
    endpoint is racy (vulnerable=True)."""
    state = {"controlled": "", "confirmed": False}

    async def request(client, method, url, **kwargs):
        u = str(url)
        sent.append((method, u))
        if fail(method, u, state):
            raise _connect_error(method, u)
        if method == "POST":
            email = dict(parse_qsl(_body(kwargs))).get("email", "")
            if email.endswith("@mail.invalid"):
                state["controlled"] = email
            return _response(method, u, text="pending")
        if u == _MAILBOX:
            return _response(method, u, text='<a href="/email/message-1">message</a>')
        if u == _MAILBOX + "/message-1":
            return _response(method, u, text=(
                f"To: {state['controlled']} "
                '<a href="http://shop.invalid/email/change-email?token=redacted">Confirm</a>'))
        if "token=redacted" in u:
            state["confirmed"] = True
            return _response(method, u, text="confirmed")
        if u == "http://shop.invalid/my-account":
            address = _TARGET if vulnerable and state["confirmed"] else state["controlled"]
            return _response(method, u, text=f"<p>Your email is: {address}</p>")
        return _response(method, u, 404, "not found")
    return request


class EmailRaceUnsentTests(_RvuBase):
    """U3: an email race whose pair, mailbox or readback got no response is not
    'no target-address readback'."""

    HOSTS = ("shop.invalid", "mail.invalid")

    def _ex(self):
        ex = _exchange("http://shop.invalid/my-account/change-email",
                       {"Cookie": "session=u", "Content-Type": "application/x-www-form-urlencoded"})
        ex.method, ex.request_body = "POST", "email=probe%40example.invalid&csrf=t"
        return ex

    def _run(self, fake, **run):
        v = RaceConditionValidator(timeout=1.0, target_email=_TARGET, mailbox_url=_MAILBOX,
                                   email_race_rounds=2)
        return self._run_in("race_condition", v, _finding("race_condition"), self._ex(), fake,
                            hosts=self.HOSTS, **run)

    def test_mailbox_read_failing_is_not_a_negative(self):
        sent = []
        reports = self._run(_email_app(sent, fail=lambda m, u, s: u == _MAILBOX))
        self.assertIn(("POST", "http://shop.invalid/my-account/change-email"), sent)
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("mail.invalid", _text(reports))

    def test_change_pair_failing_is_not_a_negative(self):
        reports = self._run(_email_app([], fail=lambda m, u, s: m == "POST"))
        self._assert_not_negative(reports, "inconclusive")

    def test_readback_failing_after_the_link_was_followed_is_not_a_negative(self):
        # A racy endpoint whose account readback never answered once the
        # confirmation link was followed: the confirming read is missing.
        sent = []
        reports = self._run(_email_app(sent, vulnerable=True,
                                       fail=lambda m, u, s: s["confirmed"] and u.endswith("/my-account")))
        self.assertTrue(any("token=redacted" in u for _, u in sent), "link never followed -- vacuous")
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("my-account", _text(reports))

    def test_budget_ending_mid_round_is_not_a_negative(self):
        # The form refresh and the pair spend the budget; the mailbox read is refused.
        sent = []
        reports = self._run(_email_app(sent), max_requests=3)
        self.assertEqual(len(sent), 3)
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("budget_exhausted", _text(reports))

    # -- controls
    def test_target_readback_still_confirms(self):
        self._assert_confirmed(self._run(_email_app([], vulnerable=True)))

    def test_controlled_readback_stays_negative(self):
        reports = self._run(_email_app([]))
        self._assert_negative(reports)
        self.assertIn("no target-address readback", _text(reports))


# -------------------------------------------------------------------- U4 oauth
_AUTHZ = ("http://shop.invalid/authorize?response_type=code&client_id=web&state=abcdefgh1234"
          "&code_challenge=abc123&code_challenge_method=S256&redirect_uri=http%3A%2F%2Fshop.invalid%2Fcb")


def _authz_server(sent, *, lax=False, fail=lambda url: False):
    """An authorization server that redirects only to the registered
    redirect_uri, or to any extension of it (lax=True, prefix matching)."""
    async def request(client, method, url, **kwargs):
        u = str(url)
        sent.append((method, u))
        if fail(u):
            raise _connect_error(method, u)
        redirect = parse_qs(urlsplit(u).query).get("redirect_uri", [""])[0]
        if redirect == "http://shop.invalid/cb" or (lax and redirect.startswith("http://shop.invalid/cb")):
            return _response(method, u, 302, "", headers={"Location": redirect + "?code=c&state=s"})
        return _response(method, u, 400, "invalid redirect_uri")
    return request


class OAuthUnsentTests(_RvuBase):
    """U4: a redirect_uri probe that was never answered is not 'exact match'."""

    def _run(self, fake, url=_AUTHZ, **run):
        v = OAuthValidator(timeout=1.0)
        if run:
            return self._run_in("oauth", v, _finding("oauth"), _exchange(url), fake, **run)
        return self._validate("oauth", v, _finding("oauth"), _exchange(url), fake)

    def test_probe_failing_is_not_a_negative(self):
        sent = []
        reports = self._run(_refuse_all(sent))
        self.assertTrue(sent)
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("redirect_uri", _text(reports))

    def test_probe_refused_by_the_run_budget_is_blocked(self):
        sent = []
        reports = self._run(_authz_server(sent), max_requests=0)
        self.assertEqual(sent, [])
        self._assert_not_negative(reports, "blocked")

    def test_probe_failing_when_it_is_the_only_check_is_not_skipped_as_not_oauth(self):
        url = "http://shop.invalid/authorize?client_id=web&redirect_uri=http%3A%2F%2Fshop.invalid%2Fcb"
        reports = self._run(_refuse_all([]), url)
        self._assert_not_negative(reports, "inconclusive")
        self.assertNotIn("doesn't look like an OAuth", _text(reports))

    # -- controls
    def test_prefix_matched_redirect_uri_still_confirms(self):
        self._assert_confirmed(self._run(_authz_server([], lax=True)))

    def test_passive_gap_still_confirms_when_the_probe_failed(self):
        url = _AUTHZ.replace("&state=abcdefgh1234", "")
        reports = self._run(_refuse_all([]), url)
        self._assert_confirmed(reports)
        self.assertIn("State Parameter", reports[0].summary)

    def test_answered_exact_match_stays_negative(self):
        self._assert_negative(self._run(_authz_server([])))


# ------------------------------------------------------- U5 subdomain_takeover
_PAGES_HOSTS = ("shop.invalid", "acme-assets.github.io", "acme-docs.github.io")


def _pages(sent, *, fail=lambda host: False, unclaimed=()):
    """GitHub Pages hosts: claimed sites answer their content; an unclaimed
    one answers the provider's 'no site here' page."""
    async def request(client, method, url, **kwargs):
        u = str(url)
        host = urlsplit(u).hostname
        sent.append((method, u))
        if fail(host):
            raise _connect_error(method, u)
        if host in unclaimed:
            return _response(method, u, 404, "There isn't a GitHub Pages site here.")
        return _response(method, u, text=f"<h1>{host}</h1><p>docs</p>")
    return request


class SubdomainTakeoverUnsentTests(_RvuBase):
    """U5: a candidate host whose fetch got no response is not 'no fingerprint'."""

    def setUp(self):
        super().setUp()
        # Fixture hosts under real provider suffixes: fail the test rather than
        # resolve one of them for real.
        def no_dns(host):
            raise AssertionError(f"unexpected DNS resolution of {host!r}")
        patcher = patch.object(run_context_module, "_default_resolver", no_dns)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _ex(self):
        ex = _exchange("http://shop.invalid/help")
        ex.response_body = ('<a href="https://acme-assets.github.io/">assets</a> '
                            '<a href="https://acme-docs.github.io/">docs</a>')
        return ex

    def _run(self, fake, *, hosts=_PAGES_HOSTS, **run):
        v = SubdomainTakeoverValidator(timeout=1.0)
        return self._run_in("subdomain_takeover", v, _finding("subdomain_takeover"), self._ex(),
                            fake, hosts=hosts, **run)

    def test_unfetched_candidate_is_not_a_negative(self):
        sent = []
        reports = self._run(_pages(sent, fail=lambda h: h == "acme-docs.github.io"))
        self.assertEqual(len(sent), 2)
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("acme-docs.github.io", _text(reports))

    def test_every_fetch_failing_is_not_a_negative(self):
        reports = self._run(_refuse_all([]))
        self._assert_not_negative(reports, "inconclusive")

    def test_out_of_scope_candidates_are_blocked(self):
        # The referenced hosts are outside the run's scope: nothing is fetched.
        sent = []
        reports = self._run(_pages(sent), hosts=("shop.invalid",))
        self.assertEqual(sent, [])
        self._assert_not_negative(reports, "blocked")
        self.assertIn("out_of_scope", _text(reports))

    # -- controls
    def test_unclaimed_fingerprint_still_confirms(self):
        self._assert_confirmed(self._run(_pages([], unclaimed=("acme-docs.github.io",))))

    def test_unclaimed_fingerprint_despite_a_failed_fetch_still_confirms(self):
        self._assert_confirmed(self._run(_pages([], unclaimed=("acme-docs.github.io",),
                                                fail=lambda h: h == "acme-assets.github.io")))

    def test_claimed_pages_stay_negative(self):
        self._assert_negative(self._run(_pages([])))


# ------------------------------------------------------------------- U6 crypto
class _TlsSock:
    def __init__(self, version):
        self._version = version

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def version(self):
        return self._version

    def cipher(self):
        return ("TLS_AES_128_GCM_SHA256", self._version, 128)

    def getpeercert(self):
        return {"notAfter": "Jan  1 00:00:00 2099 GMT"}


def _tls_layer(*, version="TLSv1.3", connect_error=None, handshake_error=None):
    """crypto_validator's socket and ssl names, faked inside that module only."""
    def create_connection(address, timeout=None):
        if connect_error is not None:
            raise connect_error
        return _TlsSock(None)

    class _Context:
        def wrap_socket(self, sock, server_hostname=None):
            if handshake_error is not None:
                raise handshake_error
            return _TlsSock(version)
    fake_socket = SimpleNamespace(create_connection=create_connection)
    fake_ssl = SimpleNamespace(create_default_context=_Context, SSLError=ssl.SSLError,
                               SSLCertVerificationError=ssl.SSLCertVerificationError)
    return fake_socket, fake_ssl


class CryptoUnsentTests(_RvuBase):
    """U6: a TLS handshake that never completed is not 'no issue'."""

    def _ex(self, *, hsts=True):
        ex = _exchange("https://shop.invalid/account")
        ex.response_headers = {"Content-Type": "text/html",
                               "Set-Cookie": "session=abc; Secure; HttpOnly; SameSite=Lax"}
        if hsts:
            ex.response_headers["Strict-Transport-Security"] = "max-age=31536000"
        return ex

    def _run(self, ex=None, **tls):
        fake_socket, fake_ssl = _tls_layer(**tls)
        v = CryptoValidator(timeout=1.0, allowed_hosts=list(_HOSTS))
        with patch.object(crypto_validator, "socket", fake_socket), \
                patch.object(crypto_validator, "ssl", fake_ssl):
            return self._validate("crypto", v, _finding("tls"), ex or self._ex())

    def test_tls_connect_failing_is_not_a_negative(self):
        reports = self._run(connect_error=ConnectionRefusedError("synthetic refused connection"))
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("TLS", _text(reports))
        self.assertIn("ConnectionRefusedError", _text(reports))

    def test_tls_handshake_failing_is_not_a_negative(self):
        reports = self._run(handshake_error=ssl.SSLError("unsupported protocol"))
        self._assert_not_negative(reports, "inconclusive")
        self.assertIn("SSLError", _text(reports))

    # -- controls
    def test_weak_protocol_still_confirms(self):
        self._assert_confirmed(self._run(version="TLSv1"))

    def test_missing_hsts_still_confirms_when_tls_failed(self):
        reports = self._run(self._ex(hsts=False),
                            connect_error=ConnectionRefusedError("synthetic refused connection"))
        self._assert_confirmed(reports)
        self.assertIn("HSTS", reports[0].summary)

    def test_modern_tls_with_headers_stays_negative(self):
        reports = self._run()
        self._assert_negative(reports)
        self.assertIn("No transport/crypto issue confirmed", reports[0].summary)


if __name__ == "__main__":
    unittest.main()
