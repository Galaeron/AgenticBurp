"""WL-11 / audit E19: `privacy.external_lookups` gates third-party lookups.

"Passive" analysis looks up components seen in captured target traffic at
api.github.com, registry.npmjs.org, pypi.org and www.cisa.gov (and has a
malware-feed loader for malware-list.aikido.dev). These tests drive the
production `Orchestrator.analyze()` with only two boundaries replaced:

  * the model (a stub that names two components the exchange really advertises);
  * the outbound HTTP client (`httpx.AsyncClient`), swapped for a fake that
    RECORDS each request and answers from canned data. No real socket is ever
    opened; `socket.getaddrinfo` is additionally guarded so a path that bypassed
    the fake would be recorded as a DNS lookup of one of the five hosts.

What each test proves:
  * default config      -> lookups are attempted (recorded) and the per-service
                           telemetry counters equal the recorded request counts;
  * flag false          -> zero requests, zero counter movement, and no
                           "checked / nothing found" report (absence = not checked);
  * non-boolean value   -> rejected by config validation AND by Orchestrator
                           construction (a quoted "false" can never enable lookups);
  * fault injection     -> re-enabling one path while the flag is off makes the
                           no-egress assertions FAIL, so they are not vacuous.
"""
import asyncio
import json
import os
import shutil
import socket
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock
from urllib.parse import urlparse

import httpx
import yaml

_HARNESS = Path(__file__).resolve().parent

from harness import cache, config_schema, package_registry_checks, store, telemetry
from harness.github_advisories import (
    GitHubAdvisoryClient, STATUS_SKIPPED_EXTERNAL_DISABLED as GHA_SKIPPED)
from harness.kev_check import KevClient, STATUS_SKIPPED_EXTERNAL_DISABLED as KEV_SKIPPED
from harness.models import ComponentCandidate, HttpExchange
from harness.ollama_client import OllamaResult
from harness.orchestrator import Orchestrator
from harness.package_registry_checks import (
    PackageRegistryClient, STATUS_SKIPPED_EXTERNAL_DISABLED as REG_SKIPPED)

# host -> the service name the telemetry counter must use for it.
_HOST_SERVICE = {
    "api.github.com": "github_advisories",
    "registry.npmjs.org": "npm_registry",
    "pypi.org": "pypi_registry",
    "www.cisa.gov": "cisa_kev",
    "malware-list.aikido.dev": "aikido_malware_feed",
}
_SERVICES = sorted(_HOST_SERVICE.values())
_EVENT_PREFIX = "external_lookup:"

_SUPPLY_ANCHOR = "Supply chain and dependency risk"  # supply_chain_agent.specialty_prompt only

# Both name and version are literally present in the exchange below, so they pass
# `_verify_component_observation` and reach the lookups.
_COMPONENTS = [
    {"ecosystem": "PyPI", "name": "Werkzeug", "version": "2.0.1",
     "source": "Server response header"},
    {"ecosystem": "npm", "name": "express", "version": "4.17.1",
     "source": "X-Powered-By response header"},
]
_CVE = {"werkzeug": "CVE-2099-0001", "express": "CVE-2099-0002"}

# /health routes to misconfig + supply_chain by the deterministic fast path.
_EXCHANGE = HttpExchange(
    url="http://localhost/app/health",
    method="GET",
    request_headers={"User-Agent": "wl11-test"},
    request_body="",
    response_status=200,
    response_headers={"Content-Type": "application/json",
                      "Server": "Werkzeug/2.0.1 Python/3.9.7",
                      "X-Powered-By": "Express/4.17.1"},
    response_body='{"status": "ok"}',
)

_CLAIM_AGENTS = {"known_vuln_lookup", "registry_age_check"}
_CLAIM_CLASS_PREFIXES = ("known-vulnerable-dependency", "recently-published-dependency")


def _recent() -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")


class _FakeResponse:
    def __init__(self, status_code: int, payload):
        self.status_code = status_code
        self._payload = payload
        self.text = json.dumps(payload)

    def json(self):
        return self._payload


class _Recorder:
    """What crossed the (fake) network boundary during one analysis."""

    def __init__(self):
        self.requests: list[tuple[str, str]] = []   # (host, url)
        self.dns: list[str] = []

    def hosts(self) -> list[str]:
        return [h for h, _ in self.requests]

    def respond(self, url: str, params) -> _FakeResponse:
        host, path = urlparse(url).hostname, urlparse(url).path
        if host == "api.github.com":
            name = (params or {}).get("affects", "")
            return _FakeResponse(200, [{
                "ghsa_id": f"GHSA-test-{name.lower()}", "cve_id": _CVE.get(name.lower()),
                "summary": "synthetic advisory", "severity": "high",
                "html_url": "https://example.invalid/advisory",
                "vulnerabilities": [{"package": {"name": name},
                                     "vulnerable_version_range": "< 99.0.0"}],
            }])
        if host == "pypi.org":
            return _FakeResponse(200, {"info": {"version": "2.0.1"},
                                       "releases": {"2.0.1": [{"upload_time_iso_8601": _recent()}]}})
        if host == "registry.npmjs.org":
            return _FakeResponse(200, {"dist-tags": {"latest": "4.17.1"},
                                       "time": {"4.17.1": _recent()}})
        if host == "www.cisa.gov":
            return _FakeResponse(200, {"vulnerabilities": [
                {"cveID": cve, "dateAdded": "2099-01-01", "knownRansomwareCampaignUse": "Unknown"}
                for cve in _CVE.values()]})
        if host == "malware-list.aikido.dev":
            return _FakeResponse(200, [])
        return _FakeResponse(404, {})


def _fake_async_client(recorder: _Recorder):
    class _FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get(self, url, params=None, headers=None, **kwargs):
            recorder.requests.append((urlparse(str(url)).hostname, str(url)))
            return recorder.respond(str(url), params)

    return _FakeAsyncClient


def _guarded_getaddrinfo(recorder: _Recorder):
    real = socket.getaddrinfo

    def guarded(host, *args, **kwargs):
        if str(host).lower() in _HOST_SERVICE:
            recorder.dns.append(str(host))
            raise socket.gaierror("blocked by test: WL-11 no-egress boundary")
        return real(host, *args, **kwargs)

    return guarded


class _boundary:
    """Context manager: record instead of perform every outbound lookup."""

    def __init__(self):
        self.recorder = _Recorder()
        self._patches = []

    def __enter__(self) -> _Recorder:
        self._patches = [
            mock.patch.object(httpx, "AsyncClient", _fake_async_client(self.recorder)),
            mock.patch.object(socket, "getaddrinfo", _guarded_getaddrinfo(self.recorder)),
        ]
        for p in self._patches:
            p.start()
        return self.recorder

    def __exit__(self, *exc):
        for p in reversed(self._patches):
            p.stop()
        return False


def _counts() -> dict[str, int]:
    ev = telemetry.events()
    return {svc: ev.get(_EVENT_PREFIX + svc, 0) for svc in _SERVICES}


def _delta(before: dict, after: dict) -> dict[str, int]:
    return {svc: after[svc] - before[svc] for svc in _SERVICES}


class _StubOllama:
    """The model boundary: names the two components for the supply_chain
    specialist, nothing for anyone else."""

    def __init__(self):
        self.component_answers = 0

    def _answer(self, system_prompt: str) -> dict:
        if _SUPPLY_ANCHOR in system_prompt:
            self.component_answers += 1
            return {"findings": [], "components": [dict(c) for c in _COMPONENTS]}
        return {"findings": [], "components": []}

    async def chat_json(self, model, system_prompt, user_prompt, temperature=0.1):
        return self._answer(system_prompt)

    async def chat_json_metered(self, model, system_prompt, user_prompt, temperature=0.1):
        return OllamaResult(data=self._answer(system_prompt), prompt_tokens=1, completion_tokens=1)


def _config(external_lookups=True, *, snapshot_path=None, omit_privacy=False) -> dict:
    """The shipped config with everything except the three lookups silenced:
    github_advisories / package_registry_checks / kev_check stay as shipped
    (enabled)."""
    with open(_HARNESS / "config.yaml") as f:
        cfg = yaml.safe_load(f) or {}
    cfg.setdefault("concurrency", {})["max_parallel_agents"] = 1
    cfg.setdefault("coordinator", {})["cloud_primary"] = False
    cfg.setdefault("critique", {})["enabled"] = False
    validators = cfg.setdefault("validators", {})
    validators["active_enabled"] = False
    validators["allow_mutating_replay"] = False
    cfg.setdefault("autonomous_discovery", {})["enabled"] = False
    cfg.setdefault("iterative_agent", {})["enabled"] = False
    cfg.setdefault("engagement", {})["auto_escalate"] = False
    cfg.setdefault("server", {})["allowed_hosts"] = ["localhost", "127.0.0.1"]
    if omit_privacy:
        cfg.pop("privacy", None)
    else:
        cfg["privacy"] = {"external_lookups": external_lookups}
    if snapshot_path:
        cfg["github_advisories"]["snapshot_path"] = str(snapshot_path)
    return cfg


def _build(cfg: dict) -> tuple[Orchestrator, _StubOllama]:
    orch = Orchestrator(cfg)
    stub = _StubOllama()
    orch.ollama = stub
    for agent in orch.agent_manager.agents.values():
        agent.ollama = stub
    if getattr(orch, "analysis_pipeline", None) is not None:
        orch.analysis_pipeline.ollama_client = stub
    coord = getattr(orch, "coordinator", None)
    if coord is not None and hasattr(coord, "ollama"):
        coord.ollama = stub
    return orch, stub


class _Outcome:
    def __init__(self, resp, recorder, delta, stub):
        self.resp = resp
        self.recorder = recorder
        self.delta = delta
        self.stub = stub

    @property
    def reports(self):
        return list(self.resp.agent_reports)

    @property
    def findings(self):
        return [f for r in self.reports for f in r.findings]


class _PrivacyTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="wl11_privacy_")
        cls._orig_store_db = store._DB_PATH
        cls._orig_cache = cache._cache
        store._DB_PATH = Path(cls._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(cls._tmp, "cache.db"))

    @classmethod
    def tearDownClass(cls):
        store._DB_PATH = cls._orig_store_db
        cache._cache = cls._orig_cache
        shutil.rmtree(cls._tmp, ignore_errors=True)

    def analyze(self, orch: Orchestrator, stub: _StubOllama) -> _Outcome:
        before = _counts()
        with _boundary() as recorder:
            resp = asyncio.run(orch.analyze(_EXCHANGE, bypass_cache=True))
        return _Outcome(resp, recorder, _delta(before, _counts()), stub)

    # -- the assertions fault injection must be able to trip -------------------

    def assert_no_egress(self, out: _Outcome):
        self.assertEqual(out.recorder.requests, [],
                         f"outbound lookups were made with external_lookups off: {out.recorder.hosts()}")
        self.assertEqual(out.recorder.dns, [], "a third-party host was resolved")
        self.assertEqual(out.delta, {svc: 0 for svc in _SERVICES},
                         "external-lookup telemetry moved with external_lookups off")

    def assert_no_claim(self, out: _Outcome):
        claim_reports = [r.agent for r in out.reports if r.agent in _CLAIM_AGENTS]
        self.assertEqual(claim_reports, [],
                         "a lookup report (even an empty 'checked, nothing found' one) exists "
                         "although no lookup ran")
        claimed = [f.vulnerability_class for f in out.findings
                   if f.vulnerability_class.startswith(_CLAIM_CLASS_PREFIXES)]
        self.assertEqual(claimed, [])
        self.assertFalse([f for f in out.findings if "[CISA KEV]" in (f.summary or "")])

    def assert_components_reached_the_lookups_stage(self, out: _Outcome):
        """Non-vacuity: the exchange really did yield verified components, so
        absence of lookups is due to the flag and nothing else."""
        self.assertIn("supply_chain", out.resp.dispatched_agents)
        self.assertGreater(out.stub.component_answers, 0)


class DefaultConfigStillLooksUpTest(_PrivacyTestBase):
    """(a) Default behaviour is unchanged: lookups run and are counted."""

    def test_shipped_config_default_is_true(self):
        # D4 is an owner decision; this pins that this change did not make it.
        with open(_HARNESS / "config.yaml") as f:
            shipped = yaml.safe_load(f)
        self.assertIs(shipped["privacy"]["external_lookups"], True)
        for section in ("github_advisories", "package_registry_checks", "kev_check"):
            self.assertIs(shipped[section]["enabled"], True, section)

    def _assert_lookups_ran_and_were_counted(self, out: _Outcome):
        self.assert_components_reached_the_lookups_stage(out)
        hosts = set(out.recorder.hosts())
        self.assertTrue({"api.github.com", "registry.npmjs.org", "pypi.org", "www.cisa.gov"} <= hosts,
                        f"expected GitHub, npm, PyPI and CISA lookups, saw {sorted(hosts)}")
        self.assertTrue(hosts <= set(_HOST_SERVICE), f"unexpected host contacted: {sorted(hosts)}")
        for host, service in _HOST_SERVICE.items():
            recorded = out.recorder.hosts().count(host)
            self.assertEqual(out.delta[service], recorded,
                             f"telemetry counter for {service} disagrees with the boundary "
                             f"({recorded} recorded request(s) to {host})")
        # The lookups' results are real analysis output (so the flag-off test
        # below has something concrete to be absent).
        self.assertIn("known_vuln_lookup", [r.agent for r in out.reports])
        self.assertIn("registry_age_check", [r.agent for r in out.reports])
        self.assertTrue([f for f in out.findings if "[CISA KEV]" in (f.summary or "")])

    def test_default_config_attempts_and_counts_lookups(self):
        orch, stub = _build(_config(True))
        self.assertTrue(orch.external_lookups_enabled)
        self._assert_lookups_ran_and_were_counted(self.analyze(orch, stub))

    def test_missing_privacy_section_behaves_as_default(self):
        # An older config.local.yaml-merged config with no `privacy:` key at all.
        orch, stub = _build(_config(omit_privacy=True))
        self.assertTrue(orch.external_lookups_enabled)
        self._assert_lookups_ran_and_were_counted(self.analyze(orch, stub))


class FlagOffMakesNoLookupsTest(_PrivacyTestBase):
    """(b) `privacy.external_lookups: false`: nothing leaves, nothing is claimed."""

    def test_disabled_makes_no_calls_counts_nothing_and_claims_nothing(self):
        orch, stub = _build(_config(False))
        self.assertFalse(orch.external_lookups_enabled)
        # The stages are OFF (the shape _resolve_known_vulnerabilities and
        # _check_registry_ages already treat as "return None").
        self.assertFalse(orch.gha_enabled)
        self.assertFalse(orch.registry_checks_enabled)
        self.assertFalse(orch.kev_enabled)
        out = self.analyze(orch, stub)
        self.assert_components_reached_the_lookups_stage(out)
        self.assert_no_egress(out)
        self.assert_no_claim(out)

    def test_clients_refuse_even_if_a_stage_flag_is_forced_on(self):
        """Defence in depth: if some future code path ignores the orchestrator's
        stage flags, the CLIENTS still refuse to egress. (An empty
        known_vuln_lookup report can still be produced in that situation, since
        the consumer in orchestrator_detect.py cannot tell a skipped status from
        a clean one; so only egress and findings are asserted here.)"""
        orch, stub = _build(_config(False))
        orch.gha_enabled = True
        orch.registry_checks_enabled = True
        orch.kev_enabled = True
        out = self.analyze(orch, stub)
        self.assert_components_reached_the_lookups_stage(out)
        self.assert_no_egress(out)
        self.assertEqual(
            [f for f in out.findings if f.vulnerability_class.startswith(_CLAIM_CLASS_PREFIXES)], [])

    def test_local_snapshot_still_works_with_flag_off_and_still_no_egress(self):
        snap = Path(self._tmp) / "snapshot.json"
        snap.write_text(json.dumps({"advisories": [
            {"ecosystem": "pip", "package": "Werkzeug", "ghsa_id": "GHSA-snap-0001",
             "cve_id": _CVE["werkzeug"], "summary": "snapshot advisory", "severity": "high",
             "vulnerable_range": "<2.2.3", "url": "https://example.invalid/snap"}]}))
        orch, stub = _build(_config(False, snapshot_path=snap))
        self.assertTrue(orch.gha_enabled, "a local snapshot involves no network and may stay on")
        self.assertFalse(orch.registry_checks_enabled)
        self.assertFalse(orch.kev_enabled, "no local KEV file: the CISA feed would need the network")
        out = self.analyze(orch, stub)
        self.assert_no_egress(out)
        vuln = [f for f in out.findings if f.vulnerability_class.startswith("known-vulnerable-dependency")]
        self.assertTrue(vuln, "the local snapshot should still produce its advisory finding")
        self.assertFalse([f for f in vuln if "[CISA KEV]" in f.summary])
        self.assertNotIn("registry_age_check", [r.agent for r in out.reports])


class FaultInjectionTest(_PrivacyTestBase):
    """(d) A path that ignores the flag must make the no-egress checks FAIL."""

    def _assert_flag_off_checks_trip(self, orch, stub):
        out = self.analyze(orch, stub)
        self.assert_components_reached_the_lookups_stage(out)
        with self.assertRaises(AssertionError):
            self.assert_no_egress(out)
        return out

    def test_github_path_ignoring_the_flag_is_caught(self):
        orch, stub = _build(_config(False))
        orch.gha_client = GitHubAdvisoryClient(external_lookups=True)   # ignores the flag
        orch.gha_enabled = True
        out = self._assert_flag_off_checks_trip(orch, stub)
        self.assertIn("api.github.com", out.recorder.hosts())
        self.assertGreater(out.delta["github_advisories"], 0)
        with self.assertRaises(AssertionError):
            self.assert_no_claim(out)

    def test_registry_path_ignoring_the_flag_is_caught(self):
        orch, stub = _build(_config(False))
        orch.registry_client = PackageRegistryClient(external_lookups=True)  # ignores the flag
        orch.registry_checks_enabled = True
        out = self._assert_flag_off_checks_trip(orch, stub)
        self.assertTrue({"pypi.org", "registry.npmjs.org"} <= set(out.recorder.hosts()))
        with self.assertRaises(AssertionError):
            self.assert_no_claim(out)

    def test_kev_path_ignoring_the_flag_is_caught(self):
        snap = Path(self._tmp) / "snapshot_kev.json"
        snap.write_text(json.dumps({"advisories": [
            {"ecosystem": "pip", "package": "Werkzeug", "ghsa_id": "GHSA-snap-0002",
             "cve_id": _CVE["werkzeug"], "summary": "snapshot advisory", "severity": "high",
             "vulnerable_range": "<2.2.3", "url": "https://example.invalid/snap"}]}))
        # Control: with the snapshot (so the KEV stage is reachable) and the flag
        # honoured, nothing is fetched from CISA.
        orch, stub = _build(_config(False, snapshot_path=snap))
        self.assert_no_egress(self.analyze(orch, stub))
        # Injection: only KEV ignores the flag.
        orch, stub = _build(_config(False, snapshot_path=snap))
        orch.kev_client = KevClient(external_lookups=True)
        orch.kev_enabled = True
        out = self._assert_flag_off_checks_trip(orch, stub)
        self.assertEqual(out.recorder.hosts(), ["www.cisa.gov"])
        self.assertEqual(out.delta["cisa_kev"], 1)


class ConfigValidationTest(unittest.TestCase):
    """(c) Only a real boolean is accepted; "false" can never silently enable."""

    _BAD = ("false", "true", "False", "no", "off", "0", "", 0, 1, 2, None, [], {}, 1.0)

    def test_non_boolean_values_are_rejected_by_validate_config(self):
        for bad in self._BAD:
            with self.subTest(value=bad):
                result = config_schema.validate_config({"privacy": {"external_lookups": bad}})
                self.assertFalse(result.ok)
                self.assertTrue(any("external_lookups" in e for e in result.errors), result.errors)
                with self.assertRaises(ValueError):
                    config_schema.validate_config({"privacy": {"external_lookups": bad}}, strict=True)

    def test_booleans_and_absent_section_are_valid(self):
        for ok in (True, False):
            with self.subTest(value=ok):
                self.assertTrue(
                    config_schema.validate_config({"privacy": {"external_lookups": ok}}).ok)
        self.assertTrue(config_schema.validate_config({}).ok)
        self.assertTrue(config_schema.validate_config({"privacy": None}).ok)
        self.assertTrue(config_schema.validate_config({"privacy": {}}).ok)

    def test_parse_privacy_flags(self):
        self.assertEqual(config_schema.parse_privacy_flags(None), {"external_lookups": True})
        self.assertEqual(config_schema.parse_privacy_flags({}), {"external_lookups": True})
        self.assertEqual(config_schema.parse_privacy_flags({"external_lookups": True}),
                         {"external_lookups": True})
        self.assertEqual(config_schema.parse_privacy_flags({"external_lookups": False}),
                         {"external_lookups": False})
        for bad in self._BAD:
            with self.subTest(value=bad):
                with self.assertRaises(ValueError):
                    config_schema.parse_privacy_flags({"external_lookups": bad})
        with self.assertRaises(ValueError):
            config_schema.parse_privacy_flags(["external_lookups"])

    def test_orchestrator_refuses_to_start_on_a_non_boolean(self):
        """The production constructor, not only the linter: the string "false"
        must not be read as truthy and leave lookups on."""
        for bad in ("false", "no", 0, None):
            with self.subTest(value=bad):
                cfg = _config(True)
                cfg["privacy"] = {"external_lookups": bad}
                with self.assertRaises(ValueError) as cm:
                    Orchestrator(cfg)
                self.assertIn("external_lookups", str(cm.exception))


class ClientLevelTest(unittest.TestCase):
    """Each client, alone: gate at the network site, count at the boundary."""

    def setUp(self):
        self._feed_cache = mock.patch.object(package_registry_checks, "_malware_feed_cache", {})
        self._feed_time = mock.patch.object(package_registry_checks, "_malware_feed_last_load", None)
        self._feed_cache.start()
        self._feed_time.start()
        self.addCleanup(self._feed_cache.stop)
        self.addCleanup(self._feed_time.stop)

    @staticmethod
    def _comp(ecosystem="npm", name="express", version="4.17.1"):
        return ComponentCandidate(ecosystem=ecosystem, name=name, version=version, source="test")

    def _run(self, coro_factory):
        before = _counts()
        with _boundary() as rec:
            result = asyncio.run(coro_factory())
        return result, rec, _delta(before, _counts())

    def test_github_client(self):
        off = GitHubAdvisoryClient(external_lookups=False)
        for call in (lambda: off.lookup(self._comp()), lambda: off._lookup_network(self._comp())):
            res, rec, delta = self._run(call)
            self.assertEqual(res.status, GHA_SKIPPED)
            self.assertEqual((rec.requests, rec.dns, delta), ([], [], {s: 0 for s in _SERVICES}))
        on = GitHubAdvisoryClient(external_lookups=True)
        res, rec, delta = self._run(lambda: on.lookup(self._comp()))
        self.assertEqual(res.status, "matched")
        self.assertEqual(rec.hosts(), ["api.github.com"])
        self.assertEqual(delta["github_advisories"], 1)

    def test_github_client_fails_closed_on_a_non_boolean(self):
        for bad in ("false", "true", 1, None):
            with self.subTest(value=bad):
                client = GitHubAdvisoryClient(external_lookups=bad)
                res, rec, _ = self._run(lambda: client.lookup(self._comp()))
                self.assertEqual(rec.requests, [])
                self.assertEqual(res.status, GHA_SKIPPED)

    def test_github_client_off_still_serves_a_local_snapshot(self):
        from harness.advisory_snapshot import AdvisorySnapshot
        snap = AdvisorySnapshot([{"ecosystem": "npm", "package": "express", "ghsa_id": "GHSA-s",
                                  "cve_id": None, "summary": "s", "severity": "low",
                                  "vulnerable_range": "<5", "url": "u"}])
        client = GitHubAdvisoryClient(snapshot=snap, external_lookups=False)
        res, rec, delta = self._run(lambda: client.lookup(self._comp()))
        self.assertEqual(res.status, "matched")
        self.assertEqual((rec.requests, delta), ([], {s: 0 for s in _SERVICES}))

    def test_registry_client(self):
        off = PackageRegistryClient(external_lookups=False)
        for comp in (self._comp("npm", "express"), self._comp("PyPI", "Werkzeug", "2.0.1")):
            res, rec, delta = self._run(lambda: off.check(comp))
            self.assertEqual(res.status, REG_SKIPPED)
            self.assertEqual((rec.requests, rec.dns, delta), ([], [], {s: 0 for s in _SERVICES}))
        for direct in (off._check_npm, off._check_pypi):
            res, rec, delta = self._run(lambda: direct(self._comp()))
            self.assertEqual(res.status, REG_SKIPPED)
            self.assertEqual((rec.requests, delta), ([], {s: 0 for s in _SERVICES}))
        on = PackageRegistryClient(external_lookups=True)
        res, rec, delta = self._run(lambda: on.check(self._comp("npm", "express")))
        self.assertEqual((res.status, rec.hosts(), delta["npm_registry"]),
                         ("checked", ["registry.npmjs.org"], 1))
        res, rec, delta = self._run(lambda: on.check(self._comp("PyPI", "Werkzeug", "2.0.1")))
        self.assertEqual((res.status, rec.hosts(), delta["pypi_registry"]),
                         ("checked", ["pypi.org"], 1))

    def test_aikido_malware_feed_is_gated_and_never_a_false_clean(self):
        off = PackageRegistryClient(external_lookups=False)
        res, rec, delta = self._run(lambda: off.check_malware(self._comp()))
        self.assertEqual(res.status, REG_SKIPPED)
        self.assertFalse(res.is_malicious)
        self.assertEqual((rec.requests, delta), ([], {s: 0 for s in _SERVICES}))
        _, rec, delta = self._run(off._load_malware_feeds)
        self.assertEqual((rec.requests, delta), ([], {s: 0 for s in _SERVICES}))
        # A feed cache loaded earlier by an ENABLED client must not let a
        # disabled one report "checked / No malware detected".
        package_registry_checks._malware_feed_cache["cross_ecosystem"] = []
        res, _, _ = self._run(lambda: off.check_malware(self._comp()))
        self.assertEqual(res.status, REG_SKIPPED)
        package_registry_checks._malware_feed_cache.clear()
        on = PackageRegistryClient(external_lookups=True)
        res, rec, delta = self._run(lambda: on.check_malware(self._comp()))
        self.assertEqual(res.status, "checked")
        self.assertEqual(rec.hosts(), ["malware-list.aikido.dev"] * 2)
        self.assertEqual(delta["aikido_malware_feed"], 2)

    def test_kev_client(self):
        off = KevClient(external_lookups=False)
        for call in (lambda: off.check("CVE-2099-0001"), off._ensure_loaded):
            res, rec, delta = self._run(call)
            self.assertEqual((rec.requests, rec.dns, delta), ([], [], {s: 0 for s in _SERVICES}))
        self.assertEqual(asyncio.run(off.check("CVE-2099-0001")).status, KEV_SKIPPED)
        on = KevClient(external_lookups=True)
        res, rec, delta = self._run(lambda: on.check("CVE-2099-0001"))
        self.assertEqual((res.status, rec.hosts(), delta["cisa_kev"]), ("listed", ["www.cisa.gov"], 1))

    def test_kev_local_file_still_works_with_flag_off(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "kev.json"
            path.write_text(json.dumps({"vulnerabilities": [
                {"cveID": "CVE-2099-0001", "dateAdded": "2099-01-01"}]}))
            client = KevClient(local_file=str(path), external_lookups=False)
            res, rec, delta = self._run(lambda: client.check("CVE-2099-0001"))
            self.assertEqual(res.status, "listed")
            self.assertEqual((rec.requests, delta), ([], {s: 0 for s in _SERVICES}))

    def test_counters_record_only_service_names(self):
        """No component names, package names, CVE ids or URLs in telemetry."""
        gha = GitHubAdvisoryClient(external_lookups=True)
        reg = PackageRegistryClient(external_lookups=True)
        kev = KevClient(external_lookups=True)

        async def everything():
            await gha.lookup(self._comp("PyPI", "Werkzeug", "2.0.1"))
            await reg.check(self._comp("npm", "express"))
            await reg.check_malware(self._comp("npm", "express"))
            await kev.check("CVE-2099-0001")

        self._run(everything)
        keys = {k for k in telemetry.events() if k.startswith(_EVENT_PREFIX)}
        self.assertTrue(keys, "expected external_lookup counters")
        for key in keys:
            self.assertRegex(key, r"^external_lookup:[a-z_]+$")
            self.assertIn(key[len(_EVENT_PREFIX):], _SERVICES)
            for leaked in ("werkzeug", "express", "cve-", "http", "."):
                self.assertNotIn(leaked, key.lower())


if __name__ == "__main__":
    unittest.main()
