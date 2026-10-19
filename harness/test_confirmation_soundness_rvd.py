"""Code review 02, batch RV-D (I10): false confirmations in the CORS, IDOR,
open-redirect and SSRF validators (R08, R09, R14, R16, R17).

Each test drives the production caller -- ``Orchestrator.analyze`` or
``Orchestrator._validate_findings`` -- the way the reviewer's
``boundary_checks.py`` did, with the reviewer's control as the negative control.
"""
import asyncio
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

from harness import cache, safety_gate, store
from harness.models import AgentReport, Finding
from harness.orchestrator import Orchestrator
from harness.test_default_history_caller import _config, _exchange, _RecordingModel


def _finding(cls: str) -> Finding:
    return Finding(vulnerability_class=cls, confidence=0.5, summary="candidate",
                   evidence="fixture", suggested_test="verify", basis="derived")


class _CallerBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="rvd_")
        self._saved = (store._DB_PATH, cache._cache)
        store._DB_PATH = Path(self._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(self._tmp, "cache.db"))
        safety_gate.reset_default_gate()

    def tearDown(self):
        store._DB_PATH, cache._cache = self._saved
        safety_gate.reset_default_gate()
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _orch(self, cfg=None, hosts=("shop.invalid",)):
        cfg = cfg or _config()
        cfg["server"]["allowed_hosts"] = list(hosts)
        orch = Orchestrator(cfg)
        model = _RecordingModel()
        orch.ollama = model
        for agent in orch.agent_manager.agents.values():
            agent.ollama = model
        return orch

    def _validate(self, validator, cls, exchange, fake_request=None, hosts=("shop.invalid",)):
        """Run one validator through Orchestrator._validate_findings. Without a
        fake_request the validator talks to a real (owned loopback) server."""
        orch = self._orch(hosts=hosts)
        orch.validator_registry.active_enabled = True
        orch.validator_registry.validators = {validator.name: validator}
        run = lambda: asyncio.run(orch._validate_findings(  # noqa: E731
            exchange, [AgentReport(agent=cls, model="fake", findings=[_finding(cls)])]))
        if fake_request is None:
            reports, _proofs = run()
        else:
            with patch.object(httpx.AsyncClient, "request", fake_request):
                reports, _proofs = run()
        return reports


def _verdicts(reports):
    return [(v.status, v.summary) for v in reports]


# --------------------------------------------------------------------- CORS
class CorsCallerTests(_CallerBase):
    """R09 (fixed trusted origin) and R08 (budget-blocked probe), via analyze()."""

    def _analyze(self, headers, max_requests=50):
        from harness.models import StageOutcome
        from harness.validators.cors_validator import CorsValidator
        cfg = _config()
        cfg["validators"]["active_enabled"] = True
        cfg["analyze"] = {"max_requests": max_requests}
        orch = self._orch(cfg)
        orch.validator_registry.validators = {"cors": CorsValidator(allowed_hosts=["shop.invalid"])}
        f = _finding("cors")

        async def pipeline(*args, **kwargs):
            return ([AgentReport(agent="cors", model="fake", findings=[f])], 0, 0,
                    StageOutcome(name="critique", status="skipped", reason="fixture"))
        sent = []

        async def fake_request(client, method, url, **kwargs):
            sent.append((method, str(url), dict(kwargs.get("headers") or {})))
            hdrs = headers(kwargs.get("headers") or {}) if callable(headers) else headers
            return httpx.Response(200, text="fixture", headers=hdrs,
                                  request=httpx.Request(method, url))
        with patch("harness.analysis_pipeline.AnalysisPipeline.run_full_analysis", pipeline), \
                patch.object(httpx.AsyncClient, "request", fake_request):
            result = asyncio.run(orch.analyze(_exchange("http://shop.invalid/a"),
                                              force_agents=["cors"], bypass_cache=True))
        return result, sent

    # R09
    def test_fixed_trusted_cors_origin_is_not_confirmed(self):
        result, sent = self._analyze({"Access-Control-Allow-Origin": "https://trusted.invalid",
                                      "Access-Control-Allow-Credentials": "true",
                                      "Vary": "Origin"})
        self.assertTrue(sent)
        self.assertTrue(result.validation_reports)
        self.assertFalse(any(v.confirmed for v in result.validation_reports),
                         _verdicts(result.validation_reports))

    def test_fixed_trusted_origin_header_weaknesses_do_not_confirm(self):
        # R09, same root cause: weaknesses that matter only to an allowed origin
        # (Allow-Headers *, a long Max-Age, exposed Set-Cookie) do not confirm
        # while the probe origin itself is refused.
        result, sent = self._analyze({"Access-Control-Allow-Origin": "https://trusted.invalid",
                                      "Access-Control-Allow-Credentials": "true",
                                      "Access-Control-Allow-Headers": "*",
                                      "Access-Control-Expose-Headers": "Set-Cookie",
                                      "Access-Control-Max-Age": "86400",
                                      "Vary": "Origin"})
        self.assertTrue(sent)
        self.assertFalse(any(v.confirmed for v in result.validation_reports),
                         _verdicts(result.validation_reports))

    def test_reflected_origin_with_credentials_confirms(self):
        # Genuine positive: the server grants whatever Origin it is sent, with
        # credentials. The probe origin is granted, so this still confirms.
        def reflect(request_headers):
            origin = {k.lower(): v for k, v in request_headers.items()}.get("origin", "")
            return {"Access-Control-Allow-Origin": origin,
                    "Access-Control-Allow-Credentials": "true", "Vary": "Origin"}
        result, sent = self._analyze(reflect)
        self.assertTrue(sent)
        confirmed = [v for v in result.validation_reports if v.confirmed]
        self.assertTrue(confirmed, _verdicts(result.validation_reports))
        self.assertIn("Origin Reflection", confirmed[0].summary)

    def test_no_cors_headers_negative_control(self):
        # R08 control: every probe ran and found nothing -> still a negative.
        result, sent = self._analyze({})
        self.assertTrue(sent)
        self.assertFalse(any(v.confirmed for v in result.validation_reports))
        self.assertEqual([v.status for v in result.validation_reports], ["safe"],
                         _verdicts(result.validation_reports))

    # R08
    def test_budget_blocked_cors_is_not_reported_safe(self):
        result, sent = self._analyze({}, max_requests=0)
        self.assertEqual(sent, [])
        self.assertTrue(result.validation_reports)
        self.assertFalse(any(v.status == "safe" for v in result.validation_reports),
                         _verdicts(result.validation_reports))
        self.assertEqual([v.status for v in result.validation_reports], ["blocked"],
                         _verdicts(result.validation_reports))
        self.assertFalse(any(v.confirmed for v in result.validation_reports))

    def test_partly_answered_cors_probe_is_inconclusive(self):
        # R08: a run whose budget ends part-way is incomplete, not a negative.
        result, sent = self._analyze({}, max_requests=3)
        self.assertTrue(sent)
        self.assertEqual([v.status for v in result.validation_reports], ["inconclusive"],
                         _verdicts(result.validation_reports))


# --------------------------------------------------------------------- IDOR
class IdorCallerTests(_CallerBase):
    """R14: public records at sequential ids are not an IDOR."""

    def test_public_product_navigation_is_not_confirmed_idor(self):
        from harness.validators.idor_read_validator import IdorReadValidator

        async def fake_request(client, method, url, **kwargs):
            last = str(url).rsplit("/", 1)[-1]
            body = ("Public product " + last + "; this catalog is readable by everyone, "
                    "without a session.") if last in ("1", "2") else "not found"
            return httpx.Response(200 if last in ("1", "2") else 404, text=body,
                                  request=httpx.Request(method, url))
        reports = self._validate(IdorReadValidator(allowed_hosts=["shop.invalid"]), "idor",
                                 _exchange("http://shop.invalid/products/1"), fake_request)
        self.assertTrue(reports)
        self.assertFalse(any(v.confirmed for v in reports), _verdicts(reports))
        self.assertEqual([v.status for v in reports], ["inconclusive"], _verdicts(reports))

    def _orders(self, *, protected):
        """Order pages: alice owns order 1, bob owns order 2. The page chrome
        differs by session ("Logged in as alice" vs a "Log in" link)."""
        sent = []

        async def fake_request(client, method, url, **kwargs):
            hdrs = {k.lower(): v for k, v in (kwargs.get("headers") or {}).items()}
            sent.append((str(url), "cookie" in hdrs))
            req = httpx.Request(method, url)
            if protected and "cookie" not in hdrs:
                return httpx.Response(302, headers={"Location": "/login"}, request=req)
            last = str(url).rsplit("/", 1)[-1]
            owner = {"1": "alice", "2": "bob", "3": "carol"}.get(last)
            if owner is None:
                return httpx.Response(404, text="not found", request=req)
            chrome = "Logged in as alice | " if "cookie" in hdrs else "Log in | "
            return httpx.Response(200, request=req, text=(
                f"{chrome}Order {last} for {owner}: 3 items, total ${last}9.00, "
                f"ship to {owner} street"))
        return fake_request, sent

    def _orders_verdict(self, *, protected):
        from harness.validators.idor_read_validator import IdorReadValidator
        fake_request, sent = self._orders(protected=protected)
        reports = self._validate(
            IdorReadValidator(allowed_hosts=["shop.invalid"]), "idor",
            _exchange("http://shop.invalid/orders/1", {"Cookie": "session=alice"}), fake_request)
        return reports, sent

    def test_cross_principal_read_of_protected_object_confirms(self):
        # Genuine positive: alice's session reads bob's order, which is refused
        # (login redirect) without a session.
        reports, sent = self._orders_verdict(protected=True)
        self.assertEqual([v.status for v in reports], ["confirmed"], _verdicts(reports))
        self.assertTrue(reports[0].confirmed)
        # The unauthorized-principal control really went out, without the cookie.
        self.assertIn(("http://shop.invalid/orders/2", False), sent)

    def test_public_object_with_session_chrome_is_not_confirmed(self):
        # The object is served to anyone; only the page chrome differs (an
        # anonymous "Log in" link). Not protected -> an unconfirmed candidate.
        reports, sent = self._orders_verdict(protected=False)
        self.assertFalse(any(v.confirmed for v in reports), _verdicts(reports))
        self.assertEqual([v.status for v in reports], ["inconclusive"], _verdicts(reports))
        self.assertIn(("http://shop.invalid/orders/2", False), sent)


# ------------------------------------------------------------ open redirect
class OpenRedirectCallerTests(_CallerBase):
    """R16: only a real 3xx to a parsed external host confirms."""

    def _verdict(self, status, location):
        from harness.validators.open_redirect_validator import OpenRedirectValidator
        sent = []

        async def fake_request(client, method, url, **kwargs):
            sent.append(str(url))
            return httpx.Response(status, headers={"Location": location},
                                  request=httpx.Request(method, url))
        reports = self._validate(OpenRedirectValidator(allowed_hosts=["shop.invalid"]),
                                 "open_redirect",
                                 _exchange("http://shop.invalid/leave?next=/home"), fake_request)
        self.assertTrue(sent)
        return reports

    def test_relative_location_does_not_confirm_open_redirect(self):
        reports = self._verdict(302, "/oob-openredirect.example/local-page")
        self.assertFalse(any(v.confirmed for v in reports), _verdicts(reports))
        self.assertEqual([v.status for v in reports], ["inconclusive"], _verdicts(reports))

    def test_non_redirect_response_does_not_confirm_open_redirect(self):
        reports = self._verdict(200, "https://oob-openredirect.example/metadata")
        self.assertFalse(any(v.confirmed for v in reports), _verdicts(reports))
        self.assertEqual([v.status for v in reports], ["inconclusive"], _verdicts(reports))

    def test_external_redirect_positive_control(self):
        reports = self._verdict(302, "https://oob-openredirect.example/next")
        self.assertTrue(any(v.confirmed for v in reports), _verdicts(reports))

    def test_scheme_relative_and_backslash_redirects_confirm(self):
        # Browsers read //host and /\host as off-origin: still genuine positives.
        for status, location in ((301, "//oob-openredirect.example/x"),
                                 (307, "/\\oob-openredirect.example/x")):
            with self.subTest(location=location):
                reports = self._verdict(status, location)
                self.assertTrue(any(v.confirmed for v in reports), _verdicts(reports))

    def test_destination_host_follows_browser_parsing(self):
        from harness.validators.open_redirect_validator import _destination_host
        cases = [
            ("https://oob-openredirect.example/a", "http://shop.invalid/x", "oob-openredirect.example"),
            ("//oob-openredirect.example/a", "http://shop.invalid/x", "oob-openredirect.example"),
            ("/\\oob-openredirect.example/a", "http://shop.invalid/x", "oob-openredirect.example"),
            ("https:/oob-openredirect.example/a", "http://shop.invalid/x", "oob-openredirect.example"),
            ("http:/oob-openredirect.example/a", "http://shop.invalid/x", "shop.invalid"),
            ("/oob-openredirect.example/a", "http://shop.invalid/x", "shop.invalid"),
            ("oob-openredirect.example/a", "http://shop.invalid/x", "shop.invalid"),
            ("https://shop.invalid@oob-openredirect.example/", "http://shop.invalid/x",
             "oob-openredirect.example"),
            ("javascript:alert(1)//oob-openredirect.example", "http://shop.invalid/x", ""),
        ]
        for location, base, host in cases:
            with self.subTest(location=location):
                self.assertEqual(_destination_host(location, base), host)


# --------------------------------------------------------------------- SSRF
class SsrfCallerTests(_CallerBase):
    """R17: a URL-syntax validator's response difference is not fetch proof."""

    def test_ssrf_url_validation_difference_is_not_fetch_proof(self):
        from urllib.parse import parse_qs, urlsplit
        from harness.validators.ssrf_validator import SsrfValidator

        class NoCallback:
            def token(self):
                return "synthetic-review-token"

            def url(self, token):
                return "http://callback.invalid/" + token

            async def wait_for_hit(self, *args, **kwargs):
                return False
        sent = []

        async def fake_request(client, method, url, **kwargs):
            sent.append(str(url))
            target = parse_qs(urlsplit(str(url)).query)["url"][0]
            forbidden = urlsplit(target).port not in (None, 80, 443)
            return httpx.Response(400 if forbidden else 200,
                                  text="Port is not allowed" if forbidden
                                  else "URL syntax is valid. No request has been made.",
                                  request=httpx.Request(method, url))
        reports = self._validate(
            SsrfValidator(allowed_hosts=["shop.invalid"], collaborator=NoCallback()), "ssrf",
            _exchange("http://shop.invalid/check-url?url=http://example.invalid"), fake_request)
        self.assertTrue(sent)
        self.assertTrue(reports)
        self.assertFalse(any(v.confirmed for v in reports), _verdicts(reports))
        self.assertEqual([v.status for v in reports], ["inconclusive"], _verdicts(reports))

    def _loopback_verdict(self, mode, timeout):
        from harness.collaborator import Collaborator
        from harness.validators.ssrf_validator import SsrfValidator
        app = _UrlCheckApp(mode)
        collab = Collaborator()
        try:
            reports = self._validate(
                SsrfValidator(allowed_hosts=["127.0.0.1"], collaborator=collab, timeout=timeout),
                "ssrf", _exchange(f"http://127.0.0.1:{app.port}/check?url=http://example.invalid/"),
                hosts=("127.0.0.1",))
            return reports, app.seen
        finally:
            collab.stop()
            app.close()

    def test_owned_loopback_fetcher_confirms_via_callback(self):
        # Genuine positive: an owned loopback app that really fetches the URL it
        # is given calls the real in-process collaborator back.
        reports, seen = self._loopback_verdict("fetch", timeout=5.0)
        self.assertEqual([v.status for v in reports], ["confirmed"], _verdicts(reports))
        self.assertTrue(reports[0].confirmed)
        self.assertTrue(any("/check?" in p for p in seen))

    def test_owned_loopback_url_validator_is_only_a_candidate(self):
        # The R17 shape on a real socket: the app validates the URL and never
        # fetches it, so no callback arrives; the 400-vs-200 difference stays a
        # candidate.
        reports, seen = self._loopback_verdict("syntax", timeout=1.0)
        self.assertTrue(seen)
        self.assertFalse(any(v.confirmed for v in reports), _verdicts(reports))
        self.assertEqual([v.status for v in reports], ["inconclusive"], _verdicts(reports))


class _UrlCheckApp:
    """Owned loopback app with ``GET /check?url=...``. Mode "fetch" really fetches
    the URL (no proxy, 2 s timeout); mode "syntax" only validates it, rejecting
    ports other than 80/443 as the reviewer's R17 fixture does."""

    def __init__(self, mode: str):
        import http.server
        import threading
        import urllib.request
        from urllib.parse import parse_qs, urlsplit
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        seen = self.seen = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(self.path)
                target = parse_qs(urlsplit(self.path).query).get("url", [""])[0]
                if mode == "fetch":
                    try:
                        with opener.open(target, timeout=2) as r:
                            status = 200
                            body = "Fetched: " + r.read(2000).decode("utf-8", "replace")
                    except Exception as e:
                        status, body = 502, f"Error: could not connect ({e.__class__.__name__})"
                elif urlsplit(target).port in (None, 80, 443):
                    status, body = 200, "URL syntax is valid. No request has been made."
                else:
                    status, body = 400, "Port is not allowed"
                data = body.encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self._thread.join(5)


if __name__ == "__main__":
    unittest.main()
