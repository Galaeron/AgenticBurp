"""
Run-derived confirmation trust tiers (P0-2).

`harness/confirmation_gate.py`'s LIVE_VERIFIED_MARKERS is a hand-maintained
frozenset asserting which confirmation legs are known to actually confirm
real instances live -- an assertion, not a measurement. If a leg silently
regresses (a validator refactor breaks its oracle, a dependency changes
behavior), the gate keeps stamping its class "live" forever, producing false
confidence.

This module is the measurement: it fires each active confirmation leg THIS
RUN against a disposable, owned loopback fixture
(testing/leg-verification/vuln_fixture.py) and its paired negative control,
and returns the frozenset of vulnerability-class markers whose leg BOTH
confirmed the vulnerable case and stayed silent (did not confirm) on the
safe one. That is the run-derived live set.

Feed the result into confirmation_gate.leg_tier() / apply_confirmation_
suppression() through their existing `live_verified_markers` override seam
(designed for exactly this in the Phase-2 live-verification work): a class
that did NOT pass its self-test this run is never treated as "live" this
run, regardless of what the static LIVE_VERIFIED_MARKERS seed says -- it
falls to "provisional" (capped at medium). The static seed remains the
OFFLINE default: it is used only when this self-test did not run at all
(the override passed to leg_tier()/apply_confirmation_suppression() is
None). Once the override is present -- even as an empty frozenset -- it
wins outright.

FAIL-SAFE, by construction: a case is added to the returned set only on an
explicit double-pass (confirmed on the vulnerable endpoint AND not-confirmed
on the control). Any case that raises, whose supporting tool is unavailable
(e.g. curl for the OOB command-injection leg, Playwright for the browser-XSS
leg), or that the fixture itself fails to serve, is simply left OUT --
never included on partial, exceptional, or default-truthy evidence. If the
whole self-test cannot run at all (fixture fails to import/bind/come up),
this returns an EMPTY frozenset, never None and never the static default --
"could not verify anything" must demote everything, not silently keep the
offline table's claims.
"""
from __future__ import annotations

import asyncio
import importlib.util
import logging
import shutil
import threading
import time
import urllib.request
from pathlib import Path
from typing import Callable, NamedTuple

log = logging.getLogger("harness.leg_self_test")

_FIXTURE = (Path(__file__).resolve().parent.parent
            / "testing" / "leg-verification" / "vuln_fixture.py")


def _load_make_app():
    spec = importlib.util.spec_from_file_location("vuln_fixture_self_test", _FIXTURE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.make_app


def _finding(vuln_class: str):
    from harness.models import Finding
    return Finding(vulnerability_class=vuln_class, confidence=0.5, severity="high",
                   summary=f"{vuln_class} self-test hypothesis", evidence="",
                   suggested_test="", basis="derived")


class LegCase(NamedTuple):
    """One self-test case. `marker` is the CONFIRMABLE_CLASS_MARKERS-style
    string added to the run-derived live set when this case passes.
    `build_tp`/`build_neg` take the fixture's base_url and return an
    HttpExchange for the vulnerable / paired-safe endpoint. `setup`, if
    given, is called with base_url before EACH of the TP and NEG probes (to
    reset any fixture-side mutable state). `available`, if given, gates the
    whole case on an external tool being present (fail-safe: unavailable ==
    left out, never assumed live)."""
    marker: str
    finding_class: str
    validator_factory: Callable[[], object]
    build_tp: Callable[[str], object]
    build_neg: Callable[[str], object]
    setup: Callable[[str], None] | None = None
    available: Callable[[], bool] = lambda: True


def _reset(path: str):
    def _do(base_url: str) -> None:
        try:
            urllib.request.urlopen(
                urllib.request.Request(f"{base_url}{path}", method="POST"), timeout=2).read()
        except OSError:
            pass
    return _do


def _default_cases() -> list[LegCase]:
    """The self-test's built-in leg roster -- one case per class the owned
    loopback fixture has a matched vulnerable/safe pair for. Deliberately a
    SUBSET of CONFIRMABLE_CLASS_MARKERS: a class with no fixture coverage
    here simply never enters the run-derived live set and is treated as
    provisional, same as any other unverified class (fail-safe default, not
    an oversight to special-case)."""
    from harness.models import HttpExchange
    from harness.validators.ssti_validator import SstiValidator
    from harness.validators.open_redirect_validator import OpenRedirectValidator
    from harness.validators.ssrf_validator import SsrfValidator
    from harness.validators.sequence_validator import SequenceValidator
    from harness.validators.command_injection_validator import CommandInjectionValidator
    from harness.validators.deserialization_oob_validator import DeserializationOobValidator
    from harness.validators.auth_sequence_validator import AuthSequenceValidator
    from harness.validators.stored_xss_validator import StoredXssValidator
    from harness.validators.jwt_forge_validator import JwtForgeValidator

    def _get(base_url, path):
        return HttpExchange(url=f"{base_url}{path}", method="GET",
                            request_headers={}, request_body="")

    def _profile_patch(base_url, path):
        return HttpExchange(url=f"{base_url}{path}", method="PATCH",
                            request_headers={"Content-Type": "application/json"},
                            request_body='{"name": "alice"}')

    def _auth_post(base_url, path, body):
        return HttpExchange(url=f"{base_url}{path}", method="POST",
                            request_headers={"Content-Type": "application/json"},
                            request_body=body)

    def _comment_post(base_url, path):
        return HttpExchange(url=f"{base_url}{path}", method="POST",
                            request_headers={"Content-Type": "application/json"},
                            request_body='{"text": "hello world"}')

    def _pickle_cookie(base_url, path):
        import base64, pickle
        seed = base64.b64encode(pickle.dumps({"user": "alice"})).decode()
        return HttpExchange(url=f"{base_url}{path}", method="GET",
                            request_headers={"Cookie": f"session={seed}"}, request_body="")

    def _jwt_get(base_url, path):
        import base64, json
        h = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).rstrip(b"=").decode()
        p = base64.urlsafe_b64encode(json.dumps({"role": "user", "sub": "alice"}).encode()).rstrip(b"=").decode()
        seed = f"{h}.{p}.Z2FyYmFnZQ"
        return HttpExchange(url=f"{base_url}{path}", method="GET",
                            request_headers={"Authorization": f"Bearer {seed}"}, request_body="")

    return [
        LegCase("ssti", "ssti",
                lambda: SstiValidator(allowed_hosts=["127.0.0.1"]),
                lambda b: _get(b, "/ssti/render?q=seed"), lambda b: _get(b, "/ssti/echo?q=seed")),

        LegCase("open_redirect", "open_redirect",
                lambda: OpenRedirectValidator(allowed_hosts=["127.0.0.1"]),
                lambda b: _get(b, "/redirect/open?url=/seed"), lambda b: _get(b, "/redirect/safe?url=/seed")),

        LegCase("ssrf", "ssrf",
                lambda: SsrfValidator(allowed_hosts=["127.0.0.1"], timeout=1.0),
                lambda b: _get(b, "/ssrf/fetch?url=http://example.invalid/x"),
                lambda b: _get(b, "/ssrf/safe?url=http://example.invalid/x")),

        LegCase("mass_assignment", "mass_assignment",
                lambda: SequenceValidator(allowed_hosts=["127.0.0.1"]),
                lambda b: _profile_patch(b, "/account/profile"), lambda b: _profile_patch(b, "/account/profile-safe"),
                setup=_reset("/account/reset")),

        LegCase("privilege escalation", "privilege_escalation",
                lambda: SequenceValidator(allowed_hosts=["127.0.0.1"]),
                lambda b: _profile_patch(b, "/account/profile"), lambda b: _profile_patch(b, "/account/profile-safe"),
                setup=_reset("/account/reset")),

        LegCase("command_injection", "command_injection",
                lambda: CommandInjectionValidator(allowed_hosts=["127.0.0.1"], timeout=1.0),
                lambda b: _get(b, "/cmdi/ping?host=seed"), lambda b: _get(b, "/cmdi/safe?host=seed"),
                available=lambda: shutil.which("curl") is not None),

        LegCase("deserialization", "deserialization",
                lambda: DeserializationOobValidator(allowed_hosts=["127.0.0.1"], timeout=2.0),
                lambda b: _pickle_cookie(b, "/deser/load"), lambda b: _pickle_cookie(b, "/deser/safe")),

        LegCase("session_fixation", "session_fixation",
                lambda: AuthSequenceValidator(allowed_hosts=["127.0.0.1"]),
                lambda b: _auth_post(b, "/auth/login-fixation", '{"username": "alice", "password": "x"}'),
                lambda b: _auth_post(b, "/auth/login-rotate", '{"username": "alice", "password": "x"}')),

        LegCase("weak_password", "weak_password",
                lambda: AuthSequenceValidator(allowed_hosts=["127.0.0.1"]),
                lambda b: _auth_post(b, "/auth/register-weak", '{"username": "alice", "password": "alicepw123"}'),
                lambda b: _auth_post(b, "/auth/register-strong", '{"username": "alice", "password": "alicepw123"}')),

        LegCase("username_enumeration", "username_enumeration",
                lambda: AuthSequenceValidator(allowed_hosts=["127.0.0.1"]),
                lambda b: _auth_post(b, "/auth/login-enum", '{"username": "alice", "password": "alicepw"}'),
                lambda b: _auth_post(b, "/auth/login-uniform", '{"username": "alice", "password": "alicepw"}')),

        LegCase("xss", "xss",
                lambda: StoredXssValidator(allowed_hosts=["127.0.0.1"]),
                lambda b: _comment_post(b, "/stored/comments"), lambda b: _comment_post(b, "/stored/comments-safe"),
                setup=_reset("/stored/reset")),

        LegCase("jwt", "jwt",
                lambda: JwtForgeValidator(allowed_hosts=["127.0.0.1"]),
                lambda b: _jwt_get(b, "/jwt/kid"), lambda b: _jwt_get(b, "/jwt/kid-safe")),
    ]


def _case_passes(case: LegCase, base_url: str) -> bool:
    """A case passes only on the full double-check: confirmed-true on the
    vulnerable endpoint AND confirmed-false (not_confirmed / any other
    non-"confirmed" status) on the paired safe control. Any exception
    propagates to the caller, which treats it as a fail (leave the marker
    out) -- never as a pass."""
    validator = case.validator_factory()

    if case.setup:
        case.setup(base_url)
    tp = asyncio.run(validator.validate(_finding(case.finding_class), case.build_tp(base_url)))
    if not (tp.status == "confirmed" and tp.confirmed):
        return False

    if case.setup:
        case.setup(base_url)
    neg = asyncio.run(validator.validate(_finding(case.finding_class), case.build_neg(base_url)))
    if neg.status == "confirmed" or neg.confirmed:
        return False

    return True


def run_self_test(*, cases: list[LegCase] | None = None, health_timeout: float = 5.0) -> frozenset:
    """Fire every self-test case against a fresh, in-process fixture
    instance and return the frozenset of markers that BOTH confirmed-true
    on their vulnerable endpoint and refuted-false on their paired negative
    control THIS run. Never raises -- any failure (fixture won't start, a
    leg crashes, a tool is missing) degrades to leaving that marker (or all
    of them) out of the returned set, which is exactly the fail-safe this
    exists to guarantee: "could not verify" must never read as "verified
    live"."""
    cases = _default_cases() if cases is None else cases
    if not cases:
        return frozenset()

    try:
        app = _load_make_app()()
    except Exception:
        log.warning("leg self-test: fixture failed to load -- all confirmable "
                    "classes fall back to provisional this run", exc_info=True)
        return frozenset()

    from werkzeug.serving import make_server
    server = make_server("127.0.0.1", 0, app, threaded=True)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{port}"

    from harness import global_throttle, safety_gate
    from harness.safety_gate import SafetyGate, SafetyGateConfig

    prev_rate, prev_burst = global_throttle.throttle._rate, global_throttle.throttle._burst
    live: set[str] = set()
    try:
        deadline = time.time() + health_timeout
        up = False
        while time.time() < deadline:
            try:
                urllib.request.urlopen(f"{base_url}/health", timeout=0.5).read()
                up = True
                break
            except OSError:
                time.sleep(0.05)
        if not up:
            log.warning("leg self-test: fixture did not come up -- all confirmable "
                        "classes fall back to provisional this run")
            return frozenset()

        global_throttle.configure(0)
        # A scoped, task-local gate (harness.safety_gate.gate_scope) -- never
        # touches the process-wide default gate a concurrent/enclosing real
        # run relies on, and never grants anything beyond the loopback
        # fixture (allowed_hosts=["127.0.0.1"]).
        scoped_gate = SafetyGate(SafetyGateConfig.from_dict({
            "active_enabled": True, "allow_mutating_replay": True,
            "allowed_hosts": ["127.0.0.1"],
        }))
        with safety_gate.gate_scope(scoped_gate):
            for case in cases:
                try:
                    if not case.available():
                        continue  # fail-safe: unavailable tool -- never counted as live
                    if _case_passes(case, base_url):
                        live.add(case.marker)
                except Exception:
                    log.debug("leg self-test: case %r errored -- leaving it "
                              "provisional this run", case.marker, exc_info=True)
                    continue
    except Exception:
        log.warning("leg self-test crashed -- all confirmable classes fall back "
                    "to provisional this run", exc_info=True)
        return frozenset()
    finally:
        try:
            server.shutdown()
            thread.join(timeout=5.0)
        except Exception:
            pass
        try:
            global_throttle.configure(prev_rate if prev_rate > 0 else None, prev_burst)
        except Exception:
            pass

    return frozenset(live)
