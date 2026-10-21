"""WL-05 (E39): a sensitive-file probe never confirms from a status code alone.

Discovery used to keep a conventional sensitive path (/.env, /.git/HEAD, ...) when
it answered 2xx OR 3xx, and investigate_engagement ingested every such hit as a
confirmed, high-severity `sensitive_file_exposure` with the evidence text
"HTTP 200 at {path}" whatever the real status was. These tests drive
`Orchestrator.investigate_engagement` -- real `build_engagement` -> `role_crawl`
-> `SurfaceDiscovery` -> ingest -- against an owned loopback fixture, entered
inside a run as the server does:

  (a) a benign synthetic dotenv file (placeholder values) at /.env confirms, and
      the evidence quotes the real status and the matched structure, never a value;
  (b) /.env.local answering 302 to a login page is not confirmed;
  (c) /.env.production answering an HTML shell is not confirmed, including when a
      catch-all shell answers every path with a per-response nonce, so soft-404
      calibration records nothing and the shell gets past it;
  (d) /.env.dev answering an empty 200 is not confirmed;
  (e) fault injection: restoring the status-only rule at the single decision
      point (sensitive_file_verdict) makes (b), (c) and (d) confirm, so the
      negative controls are not vacuous.

The REST wordlists are shrunk for speed; the sensitive-file wordlist is the real
one. Classifier unit checks cover every wordlist entry. Loopback only, synthetic
placeholder content, no model or recall claim.
"""
from __future__ import annotations

import asyncio
import json
import os
import secrets
import shutil
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

import yaml

from harness import api_surface_discovery as asd
from harness import cache, engagement_builder, evidence_ledger, global_throttle, safety_gate, store
from harness.ollama_client import OllamaResult
from harness.orchestrator import Orchestrator
from harness.role_crawl import RoleSession
from harness.run_context import RunContext
from harness.validators.base import ValidationResult

_HARNESS = Path(__file__).resolve().parent

# Obviously fake placeholder values; none may appear in any finding text.
_FAKE_VALUES = ("placeholder-app-wl05", "FAKE-TOKEN-NOT-A-SECRET-0000", "placeholder-password-wl05")
_DOTENV = ("# synthetic fixture file -- placeholder values only\n"
           f"APP_NAME={_FAKE_VALUES[0]}\n"
           f"API_TOKEN={_FAKE_VALUES[1]}\n"
           f"DB_PASSWORD={_FAKE_VALUES[2]}\n")
_LOGIN = "<!doctype html><html><head><title>Sign in</title></head><body><form>login</form></body></html>"


def _shell() -> str:
    # A per-response nonce made of letters: _norm_body_hash only folds digits, so
    # two bogus paths never share a signature and calibration records nothing.
    nonce = secrets.token_hex(8).translate(str.maketrans("0123456789", "ghijklmnop"))
    return (f'<!doctype html><html><head><meta name="csp-nonce" content="{nonce}">'
            '<title>App</title></head><body><div id="root"></div></body></html>')


class _Target:
    """Owned loopback target. Fixed paths: /.env (synthetic dotenv), /.env.local
    (302 -> /login), /.env.production (HTML shell), /.env.dev (empty 200), /login.
    Anything else is a 404, or with catch_all an HTML shell with a fresh nonce."""

    def __init__(self, *, catch_all: bool):
        self.requests: list[tuple[str, str]] = []
        self._lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, status, body="", ctype="text/html; charset=utf-8", location=None):
                data = body.encode()
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                if location:
                    self.send_header("Location", location)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(data)

            def do_GET(self):
                with outer._lock:
                    outer.requests.append((self.command, self.path))
                path = self.path.split("?", 1)[0]
                if path == "/.env":
                    self._send(200, _DOTENV, "text/plain")
                elif path == "/.env.local":
                    self._send(302, "", location="/login")
                elif path == "/login":
                    self._send(200, _LOGIN)
                elif path == "/.env.production":
                    self._send(200, _shell())
                elif path == "/.env.dev":
                    self._send(200, "", "text/plain")
                elif catch_all:
                    self._send(200, _shell())
                else:
                    self._send(404, "not found", "text/plain")

            do_OPTIONS = do_HEAD = do_GET

        class Server(ThreadingHTTPServer):
            daemon_threads = True

        self._server = Server(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self._server.server_address[1]}"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def close(self):
        self._server.shutdown()
        self._server.server_close()


class _SilentModel:
    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.1):
        if '"action":"mutate"' in (system_prompt or ""):
            return {"action": "stop", "verdict": "not_found", "thought": "done"}
        return {"findings": [], "components": []}

    async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1):
        return OllamaResult(data=await self.chat_json(model, system_prompt, user_prompt),
                            prompt_tokens=1, completion_tokens=1)


def _config() -> dict:
    with open(_HARNESS / "config.yaml") as f:
        cfg = yaml.safe_load(f) or {}
    cfg.setdefault("coordinator", {})["cloud_primary"] = False
    cfg.setdefault("critique", {})["enabled"] = False
    cfg.setdefault("validators", {})["active_enabled"] = False   # passive: discovery only
    for k in ("autonomous_discovery", "github_advisories", "kev_check", "package_registry_checks"):
        cfg.setdefault(k, {})["enabled"] = False
    cfg.setdefault("iterative_agent", {})["enabled"] = False
    eng = cfg.setdefault("engagement", {})
    eng["auto_escalate"] = False
    eng["feature_crawl"] = False
    cfg.setdefault("server", {})["allowed_hosts"] = ["127.0.0.1"]
    return cfg


def _install_model(orch: Orchestrator, model) -> None:
    orch.ollama = model
    for agent in getattr(orch.agent_manager, "agents", {}).values():
        agent.ollama = model
    if getattr(orch, "analysis_pipeline", None) is not None:
        orch.analysis_pipeline.ollama_client = model
    coordinator = getattr(orch, "coordinator", None)
    if coordinator is not None and hasattr(coordinator, "ollama"):
        coordinator.ollama = model


async def _skip_timing_leg(self, finding, exchange):
    return ValidationResult(self.name, "skipped", finding.vulnerability_class,
                            summary="stubbed in the WL-05 caller test")


def _status_only_verdict(path, status, body):
    """The pre-WL-05 rule: any kept 2xx/3xx is proof."""
    if 200 <= status < 400:
        return asd.SensitiveFileVerdict("status_only", "content_signature", f"HTTP {status}")
    return asd.SensitiveFileVerdict(None, "non_success", f"HTTP {status}")


class SensitiveFileConfirmationCallerTests(unittest.TestCase):
    """investigate_engagement -> build_engagement -> SurfaceDiscovery -> ingest."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="wl05_sensitive_")
        self._orig = (store._DB_PATH, cache._cache)
        store._DB_PATH = Path(self._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(self._tmp, "cache.db"))
        stats = global_throttle.throttle.stats()
        self._throttle = (stats["rate_per_second"] if stats["enabled"] else 0.0,
                          stats["burst"] if stats["enabled"] else None)
        global_throttle.configure(0)
        safety_gate.reset_default_gate()
        evidence_ledger.reset_default_ledger()

    def tearDown(self):
        global_throttle.configure(*self._throttle)
        safety_gate.reset_default_gate()
        store._DB_PATH, cache._cache = self._orig
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _investigate(self, *, catch_all: bool, extra_patches=()):
        """One investigate_engagement against an owned target; returns
        (sensitive-file findings by path, the result, the discovery records)."""
        target = _Target(catch_all=catch_all)
        self.addCleanup(target.close)
        cfg = _config()
        orch = Orchestrator(cfg)
        orch.allowed_hosts = ["127.0.0.1"]
        _install_model(orch, _SilentModel())
        rc = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=6000, config=cfg,
                               gate_config={"active_enabled": False})
        real_build = engagement_builder.build_engagement
        captured = {}

        async def build(*args, **kwargs):
            state, crawl = await real_build(*args, **kwargs)
            captured["state"], captured["crawl"] = state, crawl
            return state, crawl

        async def go():
            try:
                async with rc:
                    return await orch.investigate_engagement(
                        target.base, [RoleSession("anonymous", {})], max_nodes=0, step_budget=1,
                        max_chain_rounds=0, discovery_max_probes=1500,
                        discovery_max_endpoints=40, discovery_max_pages=2, run_context=rc)
            finally:
                await rc.aclose()

        patches = [patch("harness.engagement_builder.build_engagement", new=build),
                   patch("harness.browser_driver.default_driver", return_value=None),
                   # The command-injection precondition leg waits on real OOB/time
                   # probes and is not under test (as in test_run_escape_callers).
                   patch("harness.validators.command_injection_validator."
                         "CommandInjectionValidator.validate", _skip_timing_leg),
                   # Small REST wordlists keep the sweep fast; the sensitive-file
                   # wordlist stays the real DEFAULT_SENSITIVE_FILES.
                   patch.object(asd, "DEFAULT_NOUNS", ["status"]),
                   patch.object(asd, "DEFAULT_COLLECTIONS", []),
                   patch.object(asd, "DEFAULT_ACTIONS", []),
                   patch.object(asd, "DEFAULT_PREFIXES", ("/api/",)),
                   *extra_patches]
        for p in patches:
            p.start()
        try:
            result = asyncio.run(go())
        finally:
            for p in reversed(patches):
                p.stop()
        self.assertGreater(len(target.requests), 0, "discovery never reached the fixture")
        by_path = {}
        for ep in captured["state"].endpoints.values():
            for f in ep.findings:
                if f.get("vulnerability_class") == "sensitive_file_exposure":
                    by_path[ep.path] = f
        return by_path, result, list(getattr(captured["crawl"], "sensitive_file_evidence", []))

    def _assert_no_values(self, finding):
        text = json.dumps(finding)
        for value in _FAKE_VALUES:
            self.assertNotIn(value, text, "a file value leaked into the finding")

    def test_artifact_confirms_and_controls_do_not(self):
        by_path, result, records = self._investigate(catch_all=False)
        # (a) the synthetic dotenv confirms; evidence quotes the real status and structure.
        env = by_path.get("/.env")
        self.assertIsNotNone(env, f"/.env produced no finding: {sorted(by_path)}")
        self.assertTrue(env["confirmed"])
        self.assertEqual(env["severity"], "high")
        self.assertIn("HTTP 200 at /.env", env["evidence"])
        self.assertIn("dotenv", env["evidence"])
        self.assertIn("3 KEY=VALUE assignments", env["evidence"])
        self.assertIn("content-type text/plain", env["evidence"])
        self.assertIn("redacted", env["evidence"])
        self._assert_no_values(env)
        # (b) a 302 to the login page is existence only and says so with its status.
        local = by_path["/.env.local"]
        self.assertFalse(local["confirmed"])
        self.assertIn("existence only: HTTP 302", local["evidence"])
        self.assertNotIn("HTTP 200", local["evidence"])
        self.assertEqual(local["severity"], "low")
        # (c) an HTML shell at a dotenv path and (d) an empty 200 are not confirmed.
        self.assertFalse(by_path["/.env.production"]["confirmed"])
        self.assertIn("HTML page", by_path["/.env.production"]["evidence"])
        self.assertFalse(by_path["/.env.dev"]["confirmed"])
        self.assertIn("empty body", by_path["/.env.dev"]["evidence"])
        confirmed = sorted(p for p, f in by_path.items() if f["confirmed"])
        self.assertEqual(confirmed, ["/.env"])
        for finding in by_path.values():
            self._assert_no_values(finding)
        # The per-hit record carries status, type, structure and fingerprint, never the body.
        rec = next(r for r in records if r["path"] == "/.env")
        self.assertEqual((rec["status"], rec["structure"], rec["confirmed"]), (200, "dotenv", True))
        self.assertEqual(len(rec["fingerprint"]), 16)
        self.assertNotIn(_FAKE_VALUES[1], json.dumps(records))
        # Nothing in the returned worklist echoes a value either.
        for item in result["worklist"]:
            for f in item.get("findings", []):
                if f.get("vulnerability_class") == "sensitive_file_exposure":
                    self._assert_no_values(f)

    def test_catch_all_shell_past_calibration_confirms_nothing_but_the_artifact(self):
        by_path, result, records = self._investigate(catch_all=True)
        # The shell got past soft-404 calibration: wordlist paths the fixture never
        # serves (e.g. /.git/HEAD) were kept as hits, and none confirmed.
        self.assertIn("/.git/HEAD", by_path, "the catch-all shell did not get past calibration")
        self.assertFalse(by_path["/.git/HEAD"]["confirmed"])
        self.assertIn("HTML page", by_path["/.git/HEAD"]["evidence"])
        confirmed = sorted(p for p, f in by_path.items() if f["confirmed"])
        self.assertEqual(confirmed, ["/.env"])
        self.assertGreater(len(by_path), 20)

    def test_restoring_the_status_only_rule_is_detected(self):
        """Fault injection (e): with the old rule the controls confirm again."""
        by_path, _, _ = self._investigate(catch_all=True, extra_patches=[
            patch.object(asd, "sensitive_file_verdict", _status_only_verdict)])
        for path in ("/.env.local", "/.env.production", "/.env.dev", "/.git/HEAD"):
            self.assertTrue(by_path[path]["confirmed"],
                            f"status-only rule no longer confirms {path} -- the control is vacuous")


# --- the classifier over the real wordlist -------------------------------------------
# One benign synthetic positive per artifact class (placeholder content only).
_POSITIVES = {
    ".env": "APP_ENV=placeholder\nAPP_DEBUG=false\n",
    "settings.py": "SECRET_KEY = 'placeholder'\nINSTALLED_APPS = []\nDEBUG = False\n",
    "application.properties": "spring.datasource.url=jdbc:placeholder\nserver.port=8080\n",
    "appsettings.json": '{"ConnectionStrings": {"Default": "placeholder"}, "AllowedHosts": "*"}',
    "web.config": '<?xml version="1.0"?>\n<configuration><appSettings><add key="k" value="v"/>'
                  "</appSettings></configuration>",
    ".htaccess": "RewriteEngine On\nRewriteRule ^ index.php [L]\n",
    ".htpasswd": "placeholder:$apr1$placehol$0000000000000000000000\n",
    ".git/config": "[core]\n\trepositoryformatversion = 0\n\tbare = false\n",
    ".git/HEAD": "ref: refs/heads/main\n",
    ".svn/entries": "12\n\ndir\n0\n",
    "backup.sql": "-- MySQL dump 10.13\nCREATE TABLE placeholder (id int);\n",
    "db.sqlite": "SQLite format 3\x00placeholder",
    "backup.zip": "PK\x03\x04placeholder",
    "backup.tar.gz": "\x1f�\x08\x00placeholder",
    "backup/": "<html><head><title>Index of /backup</title></head><body></body></html>",
    "id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\nplaceholder\n-----END OPENSSH PRIVATE KEY-----\n",
    ".aws/credentials": "[default]\naws_access_key_id = PLACEHOLDER\n",
    "credentials.json": '{"installed": {"client_id": "placeholder", "client_secret": "placeholder"}}',
    ".npmrc": "registry=https://registry.example.invalid/\n",
    ".pypirc": "[distutils]\nindex-servers = pypi\n",
    "package.json": '{"name": "placeholder", "dependencies": {"left-pad": "1.0.0"}}',
    "composer.json": '{"require": {"php": ">=8.1"}}',
    "composer.lock": '{"_readme": [], "content-hash": "0", "packages": []}',
    "requirements.txt": "requests==2.31.0\nflask>=2.0\n",
    "Dockerfile": "FROM python:3.12-slim\nRUN true\n",
    "docker-compose.yml": "services:\n  web:\n    image: placeholder:latest\n",
    ".DS_Store": "\x00\x00\x00\x01Bud1\x00placeholder",
    "phpinfo.php": "<html><head><title>PHP 8.2.0 - phpinfo()</title></head>"
                   "<body><h1>PHP Version 8.2.0</h1></body></html>",
    "server-status": "<html><body><h1>Apache Server Status for placeholder</h1>"
                     "<dl><dt>Server Version: Apache</dt></dl></body></html>",
    "error.log": "[Mon Oct 21 10:00:00 2026] [error] placeholder\n",
}
# Wordlist entries with no structure specific enough to confirm (always candidates).
_NO_SIGNATURE = {"config.json", "config.yaml", "config.yml", "secrets.json", ".gitignore",
                 ".well-known/security.txt"}


class SensitiveFileVerdictTests(unittest.TestCase):
    def test_every_wordlist_entry_has_a_class_or_is_a_known_unconfirmable(self):
        unclassified = {f for f in asd.DEFAULT_SENSITIVE_FILES
                        if asd.sensitive_artifact_class("/" + f) is None}
        self.assertEqual(unclassified, _NO_SIGNATURE)

    def test_each_class_confirms_its_synthetic_artifact(self):
        for name, body in _POSITIVES.items():
            with self.subTest(name=name):
                verdict = asd.sensitive_file_verdict("/" + name, 200, body)
                self.assertEqual(verdict.structure, asd.sensitive_artifact_class("/" + name),
                                 verdict.reason)
                self.assertNotIn("placeholder", verdict.reason)

    def test_no_wordlist_entry_confirms_on_status_alone(self):
        for f in asd.DEFAULT_SENSITIVE_FILES:
            path = "/" + f
            body = _POSITIVES.get(f, "")
            with self.subTest(path=path):
                for status in (301, 302, 307):
                    self.assertIsNone(asd.sensitive_file_verdict(path, status, body).structure)
                self.assertIsNone(asd.sensitive_file_verdict(path, 403, body).structure)
                self.assertIsNone(asd.sensitive_file_verdict(path, 200, "").structure)
                self.assertIsNone(asd.sensitive_file_verdict(path, 200, "  \n").structure)
                self.assertIsNone(asd.sensitive_file_verdict(path, 200, _shell()).structure)
                self.assertIsNone(asd.sensitive_file_verdict(path, 200, _LOGIN).structure)
                self.assertIsNone(asd.sensitive_file_verdict(path, 200, '{"ok": true}').structure)
                self.assertIsNone(asd.sensitive_file_verdict(path, 200, "OK").structure)

    def test_a_lone_assignment_is_not_a_dotenv_file(self):
        self.assertIsNone(asd.sensitive_file_verdict("/.env", 200, "status=ok").structure)

    def test_candidate_finding_quotes_the_real_status(self):
        rec = {"path": "/.env", "status": 302, "outcome": "redirect",
               "reason": "HTTP 302 redirect, not the file itself", "confirmed": False,
               "structure": "", "length": 0}
        finding = asd.sensitive_file_finding(rec)
        self.assertFalse(finding["confirmed"])
        self.assertIn("existence only: HTTP 302 at /.env", finding["evidence"])
        self.assertNotIn("HTTP 200", finding["evidence"])
        self.assertNotIn("confirmation_method", finding)

    def test_hit_without_a_record_is_never_confirmed(self):
        finding = asd.sensitive_file_finding({"path": "/.env"})
        self.assertFalse(finding["confirmed"])
        self.assertIn("HTTP status not recorded", finding["evidence"])


class _RedirectingRun:
    """A run whose transport answers /.env with a 302 to /login, following it (as
    TargetTransport does by default) unless max_redirects=0. Records each call."""

    base = "https://app.test"

    def __init__(self):
        self.calls: list[tuple[str, str, int]] = []
        outer = self

        class _Transport:
            async def execute(self, request, *, capability, session_ref=None, max_redirects=5, **kw):
                from urllib.parse import urlsplit
                from harness.run_context import ExecutionOutcome
                outer.calls.append((request.method, urlsplit(request.url).path, max_redirects))
                if urlsplit(request.url).path != "/.env":
                    return ExecutionOutcome("ok", 404, "not found", {}, request.url)
                if max_redirects > 0:
                    return ExecutionOutcome("ok", 200, _LOGIN, {"content-type": "text/html"},
                                            outer.base + "/login")
                return ExecutionOutcome("ok", 302, "", {"location": "/login"}, request.url)

        self._transport = _Transport()

    def executor(self):
        return self._transport


class SensitiveFileRedirectTests(unittest.TestCase):
    """Inside a run the transport follows redirects; a redirect must still be
    reported as one, never as the login page's HTTP 200."""

    def _discover(self, **kw):
        run = _RedirectingRun()
        disc = asd.SurfaceDiscovery(run.base, allowed_hosts=["app.test"], prefixes=["/"],
                                    collections=[], actions=[], sensitive_files=[".env"],
                                    use_ffuf=False, max_probes=400, run_context=run, **kw)
        return asyncio.run(disc.discover()), run

    def test_sensitive_probe_does_not_follow_the_redirect(self):
        result, run = self._discover(nouns=[])
        self.assertIn(("GET", "/.env", 0), run.calls)
        rec = next(r for r in result.sensitive_file_evidence if r["path"] == "/.env")
        self.assertEqual((rec["status"], rec["outcome"], rec["confirmed"]), (302, "redirect", False))
        evidence = asd.sensitive_file_finding(rec)["evidence"]
        self.assertIn("existence only: HTTP 302 at /.env", evidence)
        self.assertNotIn("HTTP 200 at", evidence)

    def test_a_redirect_followed_in_an_earlier_phase_is_not_reported_as_200(self):
        # The noun sweep reaches /.env first, with redirects followed.
        result, run = self._discover(nouns=[".env"])
        self.assertIn(("GET", "/.env", 5), run.calls)
        rec = next(r for r in result.sensitive_file_evidence if r["path"] == "/.env")
        self.assertFalse(rec["confirmed"])
        self.assertEqual((rec["status"], rec["redirected_to"], rec["final_status"]),
                         (None, "/login", 200))
        evidence = asd.sensitive_file_finding(rec)["evidence"]
        self.assertIn("existence only: an HTTP redirect at /.env", evidence)
        self.assertNotIn("HTTP 200 at", evidence)


if __name__ == "__main__":
    unittest.main()
