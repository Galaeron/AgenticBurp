"""Per-sink secret-canary tests (NC-4, R09 residual).

PR-9 wired secret redaction into the model-prompt path and made audit sanitization
recursive. NC-4 asserts the SAME guarantee holds at every other place engagement
data can egress or persist -- headers, URL, body (incl. nested), the audit event
sink, and the Markdown report export -- by driving a synthetic secret CANARY through
each real sink function and asserting it is gone, while a NEGATIVE-control injection
PAYLOAD in a non-secret field (q=/search=) survives verbatim (redaction is
secret-NAME-scoped, not blanket, so it must never eat a SQLi/XSS payload).

This run also covers the report chains section, whose evidence/suggested_test reached
the export unredacted before this change (the individual-finding path already masked
the same fields) -- see report_generator._render_finding vs the chains loop.

Offline, deterministic. No model, target, or network.
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

import httpx

from harness import security, issues, store
from harness.audit_logger import AuditLogger
from harness.report_generator import generate_markdown_report
from harness.run_context import RunContext, TypedRequest

# One canary per surface, and one injection payload used as the negative control.
CANARY = "CANARY_SECRET_9f3a"
PAYLOAD = "<script>alert(1)</script>"       # a non-secret-field injection payload


class HeaderSinkTests(unittest.TestCase):
    def test_authorization_and_cookie_redacted_custom_header_kept(self):
        out = security.redact_headers({
            "Authorization": f"Bearer {CANARY}",
            "Cookie": f"session={CANARY}",
            "X-Trace-Id": "keep-this-non-secret",
        })
        blob = json.dumps(out)
        self.assertNotIn(CANARY, blob)
        self.assertIn("keep-this-non-secret", blob)


class UrlSinkTests(unittest.TestCase):
    def test_secret_param_redacted_query_payload_survives(self):
        url = f"http://target.invalid/x?api_key={CANARY}&q={PAYLOAD}"
        out = security.redact_secrets_in_url(url)
        self.assertNotIn(CANARY, out)
        # the q= payload survives (URL-encoded but structurally intact).
        self.assertTrue("alert" in out and "script" in out,
                        f"injection payload was mangled/removed: {out!r}")


class BodySinkTests(unittest.TestCase):
    def test_json_secret_field_redacted_payload_field_survives(self):
        body = json.dumps({"password": CANARY, "q": PAYLOAD})
        out = security.redact_secrets_in_body(body)
        self.assertNotIn(CANARY, out)
        self.assertIn(PAYLOAD, out)

    def test_nested_secret_field_redacted(self):
        body = json.dumps({"outer": {"token": CANARY}, "data": {"search": PAYLOAD}})
        out = security.redact_secrets_in_body(body)
        self.assertNotIn(CANARY, out)
        self.assertIn(PAYLOAD, out)


class AuditSinkTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.logger = AuditLogger(name="nc4-canary",
                                  log_file=os.path.join(self.tmp, "audit.log"),
                                  enable_console=False, enable_file=False)

    def test_recursive_sanitize_removes_nested_secret_keeps_note(self):
        data = {"level1": {"password": CANARY, "note": PAYLOAD,
                           "level2": {"api_key": CANARY}}}
        out = self.logger._sanitize_data(data)
        blob = json.dumps(out)
        self.assertNotIn(CANARY, blob)
        self.assertIn(PAYLOAD, blob)


def _finding(vc, evidence, suggested_test="", url="http://target.invalid/x"):
    return {
        "vulnerability_class": vc, "summary": "s", "severity": "medium",
        "confidence": 0.7, "url": url, "method": "GET",
        "evidence": evidence, "suggested_test": suggested_test, "basis": "observed",
    }


class ReportExportSinkTests(unittest.TestCase):
    def test_individual_finding_evidence_and_url_redacted(self):
        md = generate_markdown_report("target.invalid", [
            _finding("info_disclosure",
                     evidence=f"response leaked token={CANARY}; reflected q={PAYLOAD}",
                     url=f"http://target.invalid/x?api_key={CANARY}&q=abc")])
        self.assertNotIn(CANARY, md)
        self.assertTrue("alert" in md and "script" in md)  # payload survives

    def test_chain_finding_evidence_and_suggested_test_redacted(self):
        # The NC-4 fix: the chains render path previously emitted evidence and
        # suggested_test unredacted.
        md = generate_markdown_report("target.invalid", [
            _finding("potential-attack-chain:sqli+idor",
                     evidence=f"chain quotes captured token={CANARY} and payload q={PAYLOAD}",
                     suggested_test=f"replay with api_key={CANARY} to verify")])
        self.assertIn("Potential Attack Chains", md)   # it really rendered the chain
        self.assertNotIn(CANARY, md)
        self.assertIn(PAYLOAD, md)                     # payload preserved


class EvidenceBlobProducerSinkTests(unittest.IsolatedAsyncioTestCase):
    """FR-2 (F03): storing real request/response bytes (harness.store.
    evidence_blobs, written by run_context.TargetTransport._artifact at the
    successful-send call site) is a BRAND NEW persistence sink -- today's
    ledger only ever stores a URL and an "HTTP {status}" string. NC-4's
    guarantee must hold here too: a canary secret placed in the request URL, a
    request/response header, and the request/response body must NOT appear in
    the stored blob bytes, while a non-secret field's injection PAYLOAD
    survives (redaction is secret-NAME-scoped, not blanket).

    Drives the REAL producer path end to end (TargetTransport.execute against
    a mocked HTTP transport -- no real network) rather than calling the blob
    writer directly, so this also proves the producer wiring (not just the
    redactors in isolation) never lets a secret through.
    """

    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self._orig_db = store._DB_PATH
        store._DB_PATH = Path(self._tmp) / "canary_blob_t.db"

    def tearDown(self):
        store._DB_PATH = self._orig_db
        shutil.rmtree(self._tmp, ignore_errors=True)

    async def test_canary_in_url_header_and_body_absent_from_stored_blobs(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                headers={"X-Api-Key": CANARY, "X-Trace-Id": "keep-this-header"},
                content=json.dumps({"token": CANARY, "q": PAYLOAD}).encode("utf-8"))

        run_context = RunContext.create(allowed_hosts=["a.test"], config={})
        run_context._default_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        case_ref = "canary-blob-finding-1"
        try:
            # GET, not POST: the default SafetyGateConfig gates mutating methods
            # behind validators.active_enabled (off by default) -- this test is
            # about blob redaction on the producer path, not the mutation gate,
            # so it uses a safe method that authorize() always allows.
            # H1: X-Api-Key is a credential, so the send names the session that
            # owns it (a sessionless one is refused before anything is stored).
            run_context.sessions.register("canary-session", "canary-user",
                                          headers={"X-Api-Key": CANARY},
                                          allowed_origins=["https://a.test"])
            run_context.sessions.get("canary-session")._client = httpx.AsyncClient(
                transport=httpx.MockTransport(handler))
            outcome = await run_context.target_transport().execute(
                TypedRequest(
                    method="GET",
                    url=f"https://a.test/x?api_key={CANARY}",
                    headers={"X-Api-Key": CANARY, "X-Trace-Id": "keep-this-header"},
                    body=json.dumps({"password": CANARY, "q": PAYLOAD}),
                ),
                capability="canary_probe", case_ref=case_ref, session_ref="canary-session")
        finally:
            await run_context.aclose()
        self.assertTrue(outcome.ok, f"the mocked send must have succeeded: {outcome}")

        events = store.ledger_events_for(case_ref)
        executions = [e for e in events if e["event_type"] == "execution"]
        self.assertTrue(executions, "the producer must have emitted an EXECUTION event")
        data = executions[0]["data"]
        req_hash, resp_hash = data.get("request_blob"), data.get("response_blob")
        self.assertTrue(req_hash and resp_hash,
                        f"both blobs must have been stored for a successful send: {data}")
        self.assertFalse(data.get("evidence_blob_degraded"))

        req_bytes = store.get_evidence_blob(req_hash)
        resp_bytes = store.get_evidence_blob(resp_hash)
        self.assertIsNotNone(req_bytes)
        self.assertIsNotNone(resp_bytes)
        self.assertTrue(store.evidence_blob_resolves(req_hash))
        self.assertTrue(store.evidence_blob_resolves(resp_hash))

        req_text = req_bytes.decode("utf-8")
        resp_text = resp_bytes.decode("utf-8")

        # The canary must not survive in EITHER stored blob -- url + header (both
        # blobs carry the request's own url/headers structure only on the request
        # side, but the header/body canary was also echoed back by the mock
        # target into the response) -- nor the body-carried secret field.
        self.assertNotIn(CANARY, req_text, f"canary leaked into the stored REQUEST blob: {req_text!r}")
        self.assertNotIn(CANARY, resp_text, f"canary leaked into the stored RESPONSE blob: {resp_text!r}")

        # Negative control: a non-secret field's injection payload is NOT a
        # secret and must survive redaction verbatim in both blobs.
        self.assertIn(PAYLOAD, req_text, "non-secret injection payload was wrongly stripped from the request blob")
        self.assertIn(PAYLOAD, resp_text, "non-secret injection payload was wrongly stripped from the response blob")

        # And a non-secret header name/value is preserved too (redaction is
        # name-scoped, not blanket).
        self.assertIn("keep-this-header", resp_text)


class MetricKeyBoundaryTests(unittest.TestCase):
    """CURRENT_STATE item 4: a COUNT or FLAG the harness itself keys by check family
    ("csrf", "auth") is a metric, not a secret, so structured sanitization keeps it.
    Paired controls: a token, header value, numeric-string token or container under the
    SAME key is still withheld, the exemption names only those two keys, and target
    data reaching a text/body sink is redacted as before."""

    METRICS = {"by_family": {"csrf": 3, "auth": 0, "sqli": 7}, "csrf": 2.5, "auth": True}

    def test_numeric_and_boolean_metrics_under_csrf_and_auth_survive(self):
        self.assertEqual(security.sanitize_data(self.METRICS), self.METRICS)

    def test_secret_values_under_the_same_keys_are_still_redacted(self):
        for value in (CANARY, f"Bearer {CANARY}", "839201", {"token": CANARY}, [CANARY]):
            for key in ("csrf", "auth", "CSRF", "Auth"):
                out = security.sanitize_data({"by_family": {key: value}})
                self.assertEqual(out["by_family"][key], security.SECRET_VALUE_PLACEHOLDER,
                                 f"{key}={value!r} was kept")

    def test_other_secret_names_keep_numeric_values_redacted(self):
        out = security.sanitize_data({"password": 123456, "sid": 987654, "csrf_token": 42})
        self.assertEqual(set(out.values()), {security.SECRET_VALUE_PLACEHOLDER})

    def test_target_data_in_text_and_body_sinks_is_still_redacted(self):
        body = json.dumps({"csrf": 839201, "auth": 1, "q": PAYLOAD})
        for out in (security.redact_secrets_in_body(body), security.sanitize_text(body),
                    security.sanitize_text(f"response was {body} after login")):
            self.assertNotIn("839201", out)
            self.assertIn(PAYLOAD, out)

    def test_auth_and_csrf_cookie_headers_still_redacted(self):
        # (redact_headers has no X-CSRF-Token entry; that pre-existing gap is out of scope here.)
        out = json.dumps(security.redact_headers({
            "Authorization": f"Basic {CANARY}", "Cookie": f"csrf={CANARY}", "X-Trace-Id": "keep"}))
        self.assertNotIn(CANARY, out)
        self.assertIn("keep", out)

    def test_job_result_sink_keeps_metrics_and_withholds_tokens(self):
        from harness.job_status import JobStatusStore
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        journal = JobStatusStore(Path(tmp) / "jobs.sqlite3", "canary-owner")
        result = {"run_id": "r1", "coverage": {"csrf": 3, "auth": 2},
                  "observed": {"csrf": CANARY, "auth": f"Bearer {CANARY}"}}
        job = dict(job_id="metric-job", host="captured.example", base_url="https://captured.example",
                   status="done", started_at=1.0, finished_at=2.0, result=result)
        journal.create(job)
        stored = json.loads(journal.read_result("metric-job"))
        self.assertEqual(stored["coverage"], {"csrf": 3, "auth": 2})
        self.assertEqual(stored["observed"], {"csrf": security.SECRET_VALUE_PLACEHOLDER,
                                             "auth": security.SECRET_VALUE_PLACEHOLDER})
        snapshot = json.dumps(JobStatusStore.public_snapshot(job))
        self.assertNotIn(CANARY, snapshot)
        with open(Path(tmp) / "jobs.sqlite3", "rb") as handle:
            self.assertNotIn(CANARY.encode(), handle.read())


if __name__ == "__main__":
    unittest.main()
