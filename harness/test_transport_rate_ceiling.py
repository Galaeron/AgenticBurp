"""ARC-3: the outbound rate binds the TARGET, and a default run has a finite ceiling.

Real sockets: an owned loopback HTTP server records the arrival time of every
request it receives. Two concurrent jobs (separate RunContexts, as two investigate
jobs are) send to the same origin through TargetTransport with the throttle on;
the arrivals must respect the configured rate. Negative control: give each job its
own bucket (the pre-ARC-3 shape: nothing shared at the transport) and the same
traffic exceeds the rate.

The ceiling and the manifest are checked through the real investigate route
(server.py job -> RunContext -> TargetTransport -> RunManifest) with the shipped
config.yaml `runs` block: the run reaches runs.max_requests, its next send is
budget_exhausted, and the manifest records stop_reason, the request_ceiling block
and the throttle change made through /settings while the job ran. Negative
control: without runs.max_requests the same run is unbounded and records no stop.
"""
from __future__ import annotations

import asyncio
import contextvars
import json
import socket
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import yaml

from harness import global_throttle, safety_gate
from harness.global_throttle import GlobalRequestThrottle
from harness.run_context import RunContext

_RATE = 10.0          # requests per second
_PER_JOB = 6          # sends per job; two jobs
_REAL_GETADDRINFO = socket.getaddrinfo


class _Recorder:
    """Owned loopback server; records each request's monotonic arrival time."""

    def __init__(self):
        self.arrivals: list[float] = []
        self._lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                with outer._lock:
                    outer.arrivals.append(time.monotonic())
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

        class Server(ThreadingHTTPServer):
            daemon_threads = True

        self._server = Server(("127.0.0.1", 0), Handler)
        self.port = self._server.server_address[1]
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def close(self):
        self._server.shutdown()
        self._server.server_close()


def _excess(arrivals: list[float], rate: float, burst: float) -> float:
    """Largest count, over every arrival window, above what the rate allows
    (burst + rate * window). A small tolerance absorbs scheduling jitter."""
    times = sorted(arrivals)
    worst = 0.0
    for i in range(len(times)):
        for j in range(i, len(times)):
            allowed = burst + rate * (times[j] - times[i])
            worst = max(worst, (j - i + 1) - allowed)
    return worst


def _configure_throttle(test: unittest.TestCase, rate: float, burst: float | None = None):
    global_throttle.configure(rate, burst, source="test")
    test.addCleanup(global_throttle.configure, 0, source="test")


class SharedOriginBucketTests(unittest.TestCase):
    def setUp(self):
        safety_gate.reset_default_gate()
        self.addCleanup(safety_gate.reset_default_gate)
        self.server = _Recorder()
        self.addCleanup(self.server.close)
        self.url = f"http://127.0.0.1:{self.server.port}/item"

    def _two_jobs(self, *, per_job_bucket: bool = False) -> list[str]:
        job_bucket: contextvars.ContextVar = contextvars.ContextVar("arc3_job_bucket")

        async def job():
            if per_job_bucket:
                bucket = GlobalRequestThrottle()
                bucket.configure(_RATE, 1, source="test")
                job_bucket.set(bucket)
            run = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=50,
                                    gate_config={"active_enabled": True}, timeout=5.0)
            async with run:
                transport = run.target_transport()
                return [(await transport.send("GET", self.url, capability="arc3_pace",
                                              max_redirects=0)).outcome
                        for _ in range(_PER_JOB)]

        async def per_run_acquire(origin, *, capability=""):
            return await job_bucket.get().acquire_origin(origin, capability=capability)

        async def both():
            results = await asyncio.gather(job(), job())
            return [o for r in results for o in r]

        if per_job_bucket:
            with patch.object(global_throttle, "acquire_origin", per_run_acquire):
                return asyncio.run(both())
        return asyncio.run(both())

    def test_two_concurrent_jobs_share_the_origin_rate(self):
        _configure_throttle(self, _RATE, 1)
        outcomes = self._two_jobs()
        self.assertEqual(outcomes, ["ok"] * (2 * _PER_JOB))
        self.assertEqual(len(self.server.arrivals), 2 * _PER_JOB)
        self.assertLessEqual(_excess(self.server.arrivals, _RATE, 1), 1.0,
                             "arrivals exceeded the configured per-origin rate")
        span = max(self.server.arrivals) - min(self.server.arrivals)
        self.assertGreaterEqual(span, (2 * _PER_JOB - 1) / _RATE * 0.85)
        self.assertGreater(global_throttle.throttle.stats()["per_origin"]["paced"], 0)

    def test_negative_control_per_run_buckets_exceed_the_rate(self):
        _configure_throttle(self, _RATE, 1)
        outcomes = self._two_jobs(per_job_bucket=True)
        self.assertEqual(outcomes, ["ok"] * (2 * _PER_JOB))
        # Each job alone keeps the rate, so together they double it at the target.
        self.assertGreater(_excess(self.server.arrivals, _RATE, 1), 2.0)

    def test_throttle_off_is_unlimited(self):
        _configure_throttle(self, 0)
        started = time.monotonic()
        self.assertEqual(self._two_jobs(), ["ok"] * (2 * _PER_JOB))
        self.assertEqual(global_throttle.throttle.stats()["per_origin"]["origins"], 0)
        self.assertLess(time.monotonic() - started, 3 * (2 * _PER_JOB - 1) / _RATE)

    def test_burst_validator_is_charged_but_not_delayed(self):
        _configure_throttle(self, _RATE, 1)

        async def go():
            run = RunContext.create(allowed_hosts=["127.0.0.1"], max_requests=50,
                                    gate_config={"active_enabled": True}, timeout=5.0)
            async with run:
                transport = run.target_transport()
                paced_before = global_throttle.throttle.stats()["per_origin"]["paced"]
                burst = await asyncio.gather(*[
                    transport.send("GET", self.url, capability="race_condition_validator",
                                   max_redirects=0) for _ in range(3)])
                burst_paced = global_throttle.throttle.stats()["per_origin"]["paced"] - paced_before
                after = time.monotonic()
                follow = await transport.send("GET", self.url, capability="arc3_pace",
                                              max_redirects=0)
                return [o.outcome for o in burst], burst_paced, time.monotonic() - after, follow.outcome

        burst, burst_paced, follow_wait, follow = asyncio.run(go())
        self.assertEqual(burst + [follow], ["ok"] * 4)
        self.assertEqual(burst_paced, 0)                   # no burst send was delayed
        self.assertGreaterEqual(follow_wait, 2.5 / _RATE)  # the next send waits off its cost


class DefaultRunCeilingRouteTests(unittest.TestCase):
    """The investigate route with the shipped `runs` config."""

    def setUp(self):
        from harness.test_pairing_contract import PairingCallerTests
        safety_gate.reset_default_gate()
        self.addCleanup(safety_gate.reset_default_gate)
        self.fixture = PairingCallerTests("test_health_is_liveness_and_pairing_requires_credential")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.server = self.fixture.server
        orch = self.server.orchestrator
        orch.allowed_hosts = ["captured.example"]
        orch.config = self.server.config
        orch.validator_registry = SimpleNamespace(active_enabled=True)
        orch.agent_manager.agents = {}
        with open(Path(__file__).with_name("config.yaml"), encoding="utf-8") as f:
            self.shipped_runs = dict((yaml.safe_load(f) or {}).get("runs") or {})
        self.client = self.fixture.client
        self.client.headers.update(self.fixture.auth)
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)
        git = patch.object(self.server._run_manifest, "_git_state", return_value=(None, None))
        git.start()
        self.addCleanup(git.stop)
        self.target = _Recorder()
        self.addCleanup(self.target.close)

        def resolve(host, port, *args, **kwargs):
            name = host.decode() if isinstance(host, bytes) else host
            if name == "captured.example":
                return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "",
                         ("127.0.0.1", int(port or 0)))]
            return _REAL_GETADDRINFO(host, port, *args, **kwargs)
        resolver = patch("socket.getaddrinfo", side_effect=resolve)
        resolver.start()
        self.addCleanup(resolver.stop)
        self.settings_changed = threading.Event()
        self.url = f"http://captured.example:{self.target.port}/item"

        async def investigate(*args, run_context, **kwargs):
            for _ in range(500):          # the test changes the throttle mid-run
                if self.settings_changed.is_set():
                    break
                await asyncio.sleep(0.01)
            budget = run_context.budget
            # Fast-forward to one send below the ceiling (an unbounded run: the
            # same count) instead of sending 100000 real requests.
            spent = (budget.remaining if budget.remaining is not None else 100000) - 1
            self.assertTrue(budget.reserve(spent, label="fast_forward"))
            transport = run_context.target_transport()
            return {"outcomes": [(await transport.send("GET", self.url, capability="arc3_ceiling",
                                                       max_redirects=0)).outcome
                                 for _ in range(2)]}
        orch.investigate_engagement = investigate

    def _run(self, runs: dict, *, change_throttle: bool) -> tuple[dict, dict]:
        self.server.config["runs"] = {**runs, "output_dir": self.fixture.tmp.name}
        response = self.client.post("/engagement/captured.example/investigate",
                                    json={"base_url": "http://captured.example/item"})
        self.assertEqual(response.status_code, 200, response.text)
        job_id = response.json()["job_id"]
        if change_throttle:
            changed = self.client.post("/settings", json={"throttle_rps": 40.0})
            self.assertEqual(changed.status_code, 200, changed.text)
            self.addCleanup(global_throttle.configure, 0, source="test")
        self.settings_changed.set()
        for _ in range(500):
            reply = self.client.get(f"/engagement/captured.example/investigate/{job_id}")
            self.assertEqual(reply.status_code, 200, reply.text)
            job = reply.json()
            if job["status"] not in ("queued", "running"):
                break
            time.sleep(0.01)
        self.assertEqual(job["status"], "done", json.dumps(job)[:2000])
        manifest = json.loads(Path(job["manifest_path"]).read_text(encoding="utf-8"))
        return job["result"], manifest

    def test_shipped_config_stops_at_the_ceiling_and_the_manifest_records_it(self):
        ceiling = self.shipped_runs.get("max_requests")
        self.assertIsInstance(ceiling, int)
        self.assertGreater(ceiling, 0)
        result, manifest = self._run(self.shipped_runs, change_throttle=True)
        self.assertEqual(result["outcomes"], ["ok", "budget_exhausted"])
        self.assertEqual(len(self.target.arrivals), 1)
        self.assertEqual(manifest["stop_reason"], "budget_exhausted")
        self.assertEqual(manifest["request_ceiling"],
                         {"max_requests": ceiling, "used": ceiling, "remaining": 0,
                          "denied": 1, "exhausted": True})
        throttle = manifest["throttle"]
        self.assertFalse(throttle["at_start"]["enabled"])
        self.assertEqual(throttle["at_finish"]["rate_per_second"], 40.0)
        self.assertEqual(throttle["at_finish"]["set_by"]["source"], "settings")
        self.assertEqual([(c["source"], c["rate_per_second"], c["previous_rate_per_second"])
                          for c in throttle["changes"]], [("settings", 40.0, 0.0)])

    def test_negative_control_without_a_ceiling_the_run_is_unbounded(self):
        runs = {k: v for k, v in self.shipped_runs.items() if k != "max_requests"}
        result, manifest = self._run(runs, change_throttle=False)
        self.assertEqual(result["outcomes"], ["ok", "ok"])
        self.assertEqual(len(self.target.arrivals), 2)
        self.assertNotIn("stop_reason", manifest)
        self.assertIsNone(manifest["request_ceiling"]["max_requests"])
        self.assertFalse(manifest["request_ceiling"]["exhausted"])
        self.assertEqual(manifest["throttle"]["changes"], [])


if __name__ == "__main__":
    unittest.main()
