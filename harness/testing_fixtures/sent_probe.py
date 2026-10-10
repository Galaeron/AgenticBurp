"""Shared helpers for the confirmation-leg tests (review 2026-10).

Two jobs, both aimed at the "green tests, dead pipeline" failure mode:

1. `seed_gate_scope` resets and seeds the process-wide safety gate with the
   engagement's hosts, so the fail-closed empty-scope lock (commit 3c622c3) does
   not refuse the loopback/stub send BEFORE the confirmation leg runs. Without it
   every active-mode leg test skips at the gate and "passes" having sent nothing.

2. `CountingResponder` wraps the `httpx.AsyncClient.request` stand-in a leg test
   patches in, counting every call that actually REACHES the responder. Because
   `GatedAsyncClient.request()` calls the gate's `authorize()` and only then the
   parent `request()` (the patched function), a call to the wrapped responder
   means the send CLEARED THE GATE. A leg test asserts `responder.count >= 1`
   (or the known burst minimum) so it can never pass by sending nothing; the
   negative controls assert it too, and the out-of-scope guard asserts it stays
   0. `.calls` carries (method, url) for a legible failure message.

`CountingResponder` is a non-data descriptor so that, patched onto the class as
`AsyncClient.request`, attribute access still binds the client as the first arg
exactly like the plain async function the tests replace -- see
`test_sent_probe.py` for the binding contract.
"""
from __future__ import annotations

from harness import safety_gate


class CountingResponder:
    def __init__(self, responder):
        self._responder = responder
        self.count = 0
        self.calls: list[tuple[str, str]] = []

    def __get__(self, client, owner=None):
        # Descriptor bind: `client.request` -> this, with `client` captured as the
        # first positional arg the real AsyncClient.request would receive.
        async def _bound(method, url, *args, **kwargs):
            self.count += 1
            self.calls.append((method, str(url)))
            return await self._responder(client, method, url, *args, **kwargs)
        return _bound

    def reset(self) -> None:
        self.count = 0
        self.calls = []

    def why(self) -> str:
        """Failure-message context: what reached the responder, so a count==0
        failure says whether the gate refused (nothing cleared) rather than just
        asserting a bare number."""
        if not self.calls:
            return "no request reached the responder (gate refused, or leg sent nothing)"
        return "sends that cleared the gate: " + ", ".join(f"{m} {u}" for m, u in self.calls)


def seed_gate_scope(allowed_hosts, *, allow_mutating_replay=True):
    """Reset and seed the process-wide gate so active-mode sends to `allowed_hosts`
    clear the scope lock. Pair with `safety_gate.reset_default_gate()` on teardown."""
    safety_gate.reset_default_gate()
    safety_gate.get_default_gate({
        "active_enabled": True,
        "allow_mutating_replay": allow_mutating_replay,
        "allowed_hosts": list(allowed_hosts),
    })
