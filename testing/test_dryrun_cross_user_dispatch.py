"""Phase 1.4 dry-run gate, as a committed regression test.

Replays the captured crAPI requests that touch other users' objects (vehicles,
videos, orders, community posts -- testing/fixtures/crapi_object_scoped_exchanges.json)
and asserts the Phase 1.4 gate: with two identities registered for the host and
active mode armed, an access-control finding on those requests DISPATCHES the
cross-user validator, and NO skipped-validator warning is logged. The negative
control -- the same corpus with no identities -- proves registration is exactly
what flips it (and that the no-accounts warning fires when it is missing), so this
doubles as a regression test for account registration + cross-user dispatch.

Offline by construction: dispatch is decided by registry.for_finding (active +
identities + an access-control class), not by sending anything, so no live crAPI
is needed and the check is deterministic.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from urllib.parse import urlsplit

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_HERE.parent))

from harness import identity_headers  # noqa: E402
from harness.models import Finding, HttpExchange  # noqa: E402
from harness.validators.cross_identity_validator import has_object_identifier, is_admin_namespaced  # noqa: E402
from harness.validators.registry import ValidatorRegistry  # noqa: E402

_FIXTURE = _HERE / "fixtures" / "crapi_object_scoped_exchanges.json"


def _load_exchanges():
    with open(_FIXTURE, encoding="utf-8") as f:
        return json.load(f)["exchanges"]


def _finding():
    # An access-control finding is what the cross-user validator arms on; the
    # object-scoped URL is what it would then probe.
    return Finding(vulnerability_class="idor", confidence=0.8, severity="high",
                   summary="possible IDOR on object id", evidence="id in path",
                   suggested_test="swap the id across identities", basis="derived")


def _exchange(rec) -> HttpExchange:
    return HttpExchange(url=rec["url"], method=rec["method"],
                        request_headers={}, request_body="")


def _armed_registry():
    # active + mutating replay on, so set_active_enabled raises no replay warning.
    reg = ValidatorRegistry({"validators": {"enabled": True, "active_enabled": False,
                                            "allow_mutating_replay": True}})
    reg.set_active_enabled(True)
    return reg


class DryRunCrossUserDispatchTest(unittest.TestCase):
    def setUp(self):
        self.exchanges = _load_exchanges()
        self.hosts = {urlsplit(e["url"]).hostname for e in self.exchanges}
        for h in self.hosts:
            identity_headers.clear(h)

    def tearDown(self):
        for h in self.hosts:
            identity_headers.clear(h)

    def _register_two(self):
        for h in self.hosts:
            identity_headers.set_identity(h, "victimA", {"Authorization": "Bearer A"})
            identity_headers.set_identity(h, "victimB", {"Authorization": "Bearer B"})

    def test_corpus_is_object_scoped(self):
        self.assertGreaterEqual(len(self.exchanges), 1, "no object-scoped corpus")
        for rec in self.exchanges:
            self.assertTrue(has_object_identifier(rec["url"]) or is_admin_namespaced(rec["url"]),
                            f"corpus entry is not object-scoped/function-level: {rec['url']}")

    def test_cross_user_dispatches_when_identities_registered(self):
        self._register_two()
        reg = _armed_registry()
        dispatched = 0
        with self.assertNoLogs("harness.validators.registry", level="WARNING"):
            for rec in self.exchanges:
                names = [v.name for v in reg.for_finding(_finding(), _exchange(rec))]
                if "cross_identity" in names:
                    dispatched += 1
        self.assertGreaterEqual(
            dispatched, 1,
            "the cross-user validator was never dispatched on the object-scoped crAPI "
            "corpus despite two registered identities -- the Phase 1.4 gate is not met")
        # Dispatch is class-gated, so every object-scoped access-control finding arms it.
        self.assertEqual(dispatched, len(self.exchanges))

    def test_without_identities_it_does_not_dispatch_and_warns(self):
        # Negative control: identities are the thing that enables the check. With
        # none registered, cross_identity cannot arm AND the no-accounts warning
        # fires -- exactly the silent-skip Phase 1.1 closes.
        reg = _armed_registry()
        rec = self.exchanges[0]
        with self.assertLogs("harness.validators.registry", level="WARNING") as cm:
            names = [v.name for v in reg.for_finding(_finding(), _exchange(rec))]
        self.assertNotIn("cross_identity", names)
        self.assertIn("no identities", "\n".join(cm.output).lower())


if __name__ == "__main__":
    unittest.main()
