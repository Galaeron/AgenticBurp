"""
Forced-egress safety proxy -- a mitmproxy addon that enforces
`safety_gate.py`'s policy on every request that reaches the network,
regardless of which process or language sent it.

Why this exists: see /PROXY_WATCHER_TODO.md at the repo root for the full
design rationale (process boundaries sqlmap's subprocess creates,
runtime boundaries the JVM creates, code that forgets to call the
in-process gate, and the lack of an independent audit trail). This file
is the implementation of that design.

======================================================================
READ THIS BEFORE RUNNING: fail-closed is the entire point of this file
======================================================================
A safety proxy that fails OPEN on an error is worse than no proxy at
all, because it creates the appearance of a safety net without the
substance -- an operator who believes traffic is gated will take risks
they wouldn't take bare-handed. Every design decision below defaults to
BLOCKING when something is uncertain, unparseable, or has thrown an
exception. If you modify this file, preserve that property above all
else: it is more acceptable for this proxy to block a request it should
have allowed (an availability cost, recoverable by the operator loosening
config) than to allow a request it should have blocked (a safety cost,
potentially irreversible on the target).

Concretely, fail-closed means:
1. Any exception raised anywhere in request-handling logic kills the
   flow. It does NOT fall through to allowing the request -- mitmproxy's
   own default behavior on an addon exception is to log it and continue
   processing the flow (i.e. allow it), which is the opposite of what a
   safety control needs. This file overrides that default explicitly.
2. `running()` refuses to start if mitmproxy is configured with any
   option that lets traffic bypass inspection entirely --
   `ignore_hosts`, `allow_hosts` (an allowlist implies a matching
   denylist-by-omission that passes through unexamined), `tcp_hosts`,
   or `udp_hosts`. These are real mitmproxy options that create exactly
   the "traffic never reached the gate" blind spot this proxy exists to
   close -- an operator setting one of them (even accidentally, e.g.
   copy-pasting a mitmproxy config snippet from documentation aimed at
   a different use case) would silently reintroduce the gap. Refusing
   to start is louder and safer than starting in a partially-blind mode.
3. A body that can't be decoded as text (binary upload, unusual
   encoding) is decoded with `errors="replace"` rather than raising --
   the hard-deny pattern check still runs against best-effort text
   rather than skipping the check because decoding was inconvenient.
4. TLS handshake failures (a client that doesn't trust this proxy's CA,
   or certificate-pins to the real target) are NOT a safety gap: if the
   handshake fails, no HTTP request was ever sent, which is the safe
   outcome by construction. `tls_failed_client` below only logs this for
   operator diagnosis -- it does not (and must not) attempt any kind of
   fallback, passthrough, or retry that would let the un-inspected
   connection through anyway.

======================================================================
The TLS/certificate story, stated precisely
======================================================================
This proxy MITMs HTTPS traffic to inspect it -- there is no way to gate
mutating requests inside encrypted traffic without decrypting it. That
requires:
- A CA certificate (mitmproxy generates one automatically on first run,
  at ~/.mitmproxy/mitmproxy-ca-cert.pem) that every client routed through
  this proxy must trust. See PROXY_SETUP.md for the concrete trust-store
  steps for httpx, sqlmap, and the JVM Burp runs in -- none of that setup
  is optional, and none of it is done automatically by this file.
- A deliberate choice, `ssl_insecure=True` (set in `running()` below),
  to NOT verify the upstream (real target's) certificate. This is
  intentional, not an oversight: this tool's targets are frequently
  local test instances or engagement targets with self-signed,
  expired, or otherwise imperfect certificates, and refusing to proxy
  to them would make the tool unusable for a common, legitimate case.
  This does not weaken what this proxy is FOR -- authorizing what the
  harness's own tooling is allowed to send -- because that authorization
  decision doesn't depend on whether the upstream cert is trustworthy.
  It does mean this proxy provides no protection against a genuine
  on-path attacker between the proxy and the real target; that was never
  its job (Burp/the analyst's own network position is responsible for
  that), and conflating the two would be a false sense of security in
  the other direction.
- An explicit non-goal: this file does not implement, and must not grow,
  any "if the CA isn't trusted, fall back to plain TCP passthrough"
  behavior. That would be the exact bypass this whole design exists to
  prevent, reintroduced as a convenience feature. If a client can't or
  won't trust the CA, the correct behavior is a failed connection that
  the operator has to go fix the trust configuration for -- not a
  quieter, unauthorized path around the gate.

======================================================================
What this file adds beyond safety_gate.py's existing per-process gate
======================================================================
`CombinedBurstTracker` enforces a ceiling on mutating requests to the
same host across ALL sources this proxy sees -- Python's httpx client,
sqlmap's subprocess, and Burp's JVM -- in a sliding time window. This is
the one thing an in-process gate structurally cannot do: safety_gate.py's
own HARD_MAX_BURST_SIZE (20) is a per-call, per-process ceiling, so two
components racing a burst at the same target near-simultaneously could
combine past it with neither one seeing the other. This proxy is the
only vantage point that sees both, which is exactly the "cross-component
accounting" PROXY_WATCHER_TODO.md names as impossible without it.

======================================================================
What this file deliberately does NOT try to verify by itself
======================================================================
Live TLS interception against a real target, real Burp JVM trust
configuration, and real sqlmap proxy behavior cannot be verified in a
sandboxed environment with no real target or real Burp instance to
point this at. The unit tests alongside this file (`test_safety_proxy_addon.py`)
verify the *policy logic* (fail-closed on exceptions, the combined-burst
ceiling, the startup bypass-option check) against mocked mitmproxy flow
objects -- they do NOT and cannot prove the CA trust chain, the real
mitmproxy TLS interception machinery, or cross-process behavior actually
work end-to-end. That is a real, disclosed verification gap, matching
this project's own honesty vocabulary: everything in this file is
"source-reviewed" and "unit-tested against mocks," not "live-tested,"
until someone runs it against a real target. See PROXY_SETUP.md's final
section for exactly what that live run needs to confirm.
"""
from __future__ import annotations

import logging
import time
import traceback
from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from harness import safety_gate

if TYPE_CHECKING:
    from mitmproxy import http
    from mitmproxy.tls import TlsData

log = logging.getLogger("harness.safety_proxy")

# This proxy's own additional ceiling, enforced across all sources it
# sees combined -- separate from, and in addition to, safety_gate.py's
# own HARD_MAX_BURST_SIZE (20) per single authorize_burst() call in one
# process. Deliberately set to the SAME value as that single-process
# ceiling, not their sum: the point is to force genuine cross-component
# awareness (Python and Java together must stay under one component's
# worth of burst, not each get their own full allowance), not to grant
# a bigger combined budget than either side has alone. This is a
# judgment call, not a derived number -- HARD_MAX_BURST_SIZE, not this
# proxy's own constant, remains the canonical hard ceiling if the two
# are ever changed independently; keep this <= that one.
HARD_MAX_COMBINED_MUTATING_PER_WINDOW = safety_gate.HARD_MAX_BURST_SIZE
COMBINED_WINDOW_SECONDS = 10.0

# mitmproxy options that let traffic bypass inspection entirely. If any
# of these are non-empty when the proxy starts, it refuses to run rather
# than start in a mode with an undisclosed blind spot. See the module
# docstring, point 2.
_BYPASS_OPTIONS = ("ignore_hosts", "allow_hosts", "tcp_hosts", "udp_hosts")


class ProxyConfigurationError(Exception):
    """Raised when mitmproxy is configured in a way that would let
    traffic bypass this addon's inspection. Fatal and deliberately not
    caught anywhere -- see module docstring."""


class CombinedBurstTracker:
    """
    Sliding-window counter of mutating requests per host, shared across
    every source this proxy observes (Python, sqlmap, Java/Burp) --
    the one piece of accounting that requires a vantage point outside
    any single process. Not a replacement for safety_gate.py's own
    per-call authorization; this only adds an additional, stricter
    ceiling on top of it.
    """

    def __init__(self, window_seconds: float = COMBINED_WINDOW_SECONDS,
                 hard_ceiling: int = HARD_MAX_COMBINED_MUTATING_PER_WINDOW):
        self._window_seconds = window_seconds
        self._hard_ceiling = hard_ceiling
        self._timestamps: dict[str, list[float]] = defaultdict(list)

    def _prune(self, host: str, now: float) -> None:
        cutoff = now - self._window_seconds
        self._timestamps[host] = [t for t in self._timestamps[host] if t >= cutoff]

    def check_and_record(self, host: str) -> tuple[bool, int]:
        """
        Atomically (single-threaded per mitmproxy's asyncio event loop --
        see note in test file about why this doesn't need an explicit
        lock) checks whether recording one more mutating request to
        `host` would exceed the combined ceiling, and records it if not.
        Returns (allowed, current_count_in_window_after_this_call).
        A request that would exceed the ceiling is NOT recorded -- it
        doesn't consume a slot it was denied.
        """
        now = time.time()
        self._prune(host, now)
        current = len(self._timestamps[host])
        if current >= self._hard_ceiling:
            return False, current
        self._timestamps[host].append(now)
        return True, current + 1


def _safe_decode_body(raw: bytes | None) -> str:
    """
    Best-effort text decode for the hard-deny pattern check. Never
    raises -- a body that fails to decode as UTF-8 is decoded with
    errors="replace" rather than skipping the check, so binary content
    (e.g. a file upload) still gets scanned for the destructive text
    patterns safety_gate.py checks for, rather than silently exempting
    anything that doesn't decode cleanly.
    """
    if not raw:
        return ""
    try:
        return raw.decode("utf-8")
    except (UnicodeDecodeError, AttributeError):
        return raw.decode("utf-8", errors="replace")


class SafetyProxyAddon:
    """
    mitmproxy addon entry point. Load with:
        mitmdump -s harness/safety_proxy_addon.py --set ssl_insecure=true

    (ssl_insecure is also force-set in running() below as a defense in
    depth against the operator forgetting the CLI flag -- see module
    docstring's TLS section for why this is a deliberate choice.)
    """

    def __init__(self, config_path: Path | None = None):
        self._config_path = config_path or (Path(__file__).parent / "config.yaml")
        self._gate = self._load_gate()
        self._combined_tracker = CombinedBurstTracker()

    def _load_gate(self) -> safety_gate.SafetyGate:
        """
        Loads the SAME config.yaml the main harness process uses, so
        this proxy's policy and the in-process gate's policy can't drift
        out of sync from having two hand-maintained copies. This is
        policy-source sharing, not runtime state sharing -- this proxy
        runs in its own process with its own SafetyGate instance and its
        own audit log, separate from the harness process's gate. State
        (e.g. how many mutating requests have already happened this
        session) is NOT shared via this mechanism; only the *rules* are.
        The CombinedBurstTracker above is what actually gives this proxy
        cross-process visibility, and it does that by being the single
        vantage point all traffic passes through, not by sharing memory
        with the in-process gate.
        """
        try:
            with open(self._config_path) as f:
                full_config = yaml.safe_load(f) or {}
        except FileNotFoundError:
            log.critical(
                "safety_proxy: could not find config.yaml at %s -- refusing to "
                "guess at a policy. Fix the path or pass config_path explicitly.",
                self._config_path,
            )
            raise
        validators_cfg = full_config.get("validators", {})
        return safety_gate.SafetyGate(safety_gate.SafetyGateConfig.from_dict(validators_cfg))

    # ------------------------------------------------------------------
    # mitmproxy lifecycle hooks
    # ------------------------------------------------------------------

    def running(self) -> None:
        """
        Called once mitmproxy is up. Refuses to continue if any
        bypass-capable option is configured, and forces ssl_insecure on
        (see module docstring). Deliberately raises rather than just
        logging a warning -- see ProxyConfigurationError's docstring.
        """
        from mitmproxy import ctx

        offending = []
        for opt_name in _BYPASS_OPTIONS:
            value = getattr(ctx.options, opt_name)
            if value:
                offending.append((opt_name, value))
        if offending:
            details = "; ".join(f"{name}={value!r}" for name, value in offending)
            log.critical(
                "safety_proxy: refusing to start -- mitmproxy is configured with "
                "a bypass-capable option that would let matching traffic skip "
                "inspection entirely: %s. Remove this option from mitmproxy's "
                "config/CLI flags before running the safety proxy.",
                details,
            )
            raise ProxyConfigurationError(details)

        # See module docstring's TLS section: intentional, not a default
        # left as-is. Set here as well as recommended on the CLI so a
        # forgotten flag doesn't silently disable proxying to self-signed
        # test targets in a way that looks like a proxy malfunction.
        ctx.options.ssl_insecure = True
        log.info("safety_proxy: started. No bypass options configured. ssl_insecure=True (intentional).")

    def tls_failed_client(self, data: "TlsData") -> None:
        """
        Diagnostic-only. A failed client TLS handshake (e.g. a client
        that doesn't trust this proxy's CA, or pins to the real target's
        certificate) means no HTTP request was ever sent through this
        connection -- that is the SAFE outcome by construction, not a
        gap to work around. This hook exists purely so an operator
        debugging "why isn't traffic from X flowing through the proxy"
        gets a clear log line instead of a silent hang. It must never be
        extended to attempt a passthrough or retry -- see module
        docstring.
        """
        try:
            client = data.context.client
            log.warning(
                "safety_proxy: TLS handshake with a client failed (sni=%r, "
                "address=%r, error=%r). This blocks the connection entirely, "
                "which is the safe default -- if this is unexpected, the "
                "client likely doesn't trust this proxy's CA certificate; "
                "see PROXY_SETUP.md.",
                getattr(client, "sni", None), getattr(client, "address", None),
                getattr(client, "error", None),
            )
        except Exception:
            # Even the diagnostic path fails closed in spirit: an error
            # while logging must never propagate and must never be
            # treated as license to do anything except leave the
            # connection blocked (which it already is, by mitmproxy's
            # own handling of a failed handshake).
            log.warning("safety_proxy: TLS handshake with a client failed (could not extract details).")

    def request(self, flow: "http.HTTPFlow") -> None:
        """
        The actual gate. Wrapped in a single try/except covering
        everything -- any unexpected exception here kills the flow
        rather than allowing it through, which is the opposite of
        mitmproxy's own default (log-and-continue) for an addon
        exception. See module docstring, point 1.
        """
        try:
            self._handle_request(flow)
        except Exception:
            log.critical(
                "safety_proxy: unhandled exception while evaluating a request -- "
                "killing the flow rather than allowing it through by default. "
                "This is fail-closed behavior, not a bug report to ignore: "
                "%s %s\n%s",
                getattr(flow.request, "method", "?"),
                getattr(flow.request, "pretty_url", "?"),
                traceback.format_exc(),
            )
            flow.kill()

    def _handle_request(self, flow: "http.HTTPFlow") -> None:
        method = flow.request.method
        url = flow.request.pretty_url
        host = flow.request.pretty_host
        body = _safe_decode_body(flow.request.raw_content)

        decision = self._gate.authorize(
            validator_name="safety_proxy(network)", method=method, url=url, body=body,
        )

        if not decision.allowed:
            self._block(flow, decision.reason)
            return

        if decision.tier == safety_gate.ActionRiskTier.MUTATING:
            allowed, current_count = self._combined_tracker.check_and_record(host)
            if not allowed:
                self._block(
                    flow,
                    f"Combined mutating-request ceiling for host {host!r} reached "
                    f"({HARD_MAX_COMBINED_MUTATING_PER_WINDOW} within "
                    f"{COMBINED_WINDOW_SECONDS:.0f}s, counted across every source this "
                    f"proxy sees -- Python, sqlmap, and Java/Burp combined, not any "
                    f"single one of them). This is the cross-component ceiling "
                    f"safety_gate.py's own per-process limit cannot enforce alone.",
                )
                return

    def _block(self, flow: "http.HTTPFlow", reason: str) -> None:
        from mitmproxy import http

        log.warning("safety_proxy: BLOCKED %s %s -- %s",
                    flow.request.method, flow.request.pretty_url, reason)
        flow.response = http.Response.make(
            403,
            f"Blocked by AgenticBurp safety_proxy: {reason}".encode("utf-8"),
            {"Content-Type": "text/plain; charset=utf-8", "X-Safety-Proxy-Blocked": "true"},
        )


addons = [SafetyProxyAddon()]
