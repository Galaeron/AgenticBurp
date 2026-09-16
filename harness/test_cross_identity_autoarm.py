"""W-12: cross-identity confirmation is auto-armed for applicable object-scoped
requests WITHIN an active, scoped engagement that has registered identities --
and only then. Applicability is automatic; authorization to send stays explicit
(active_enabled AND identities for the host)."""
import unittest

from harness import identity_headers
from harness.validators.registry import ValidatorRegistry
from harness.models import Finding, HttpExchange


def _reg(active=True):
    return ValidatorRegistry({
        "validators": {"active_enabled": active, "cross_identity": {"enabled": False}},
        "server": {"allowed_hosts": ["shop.test"]},
    })


def _idor():
    return Finding(vulnerability_class="idor", confidence=0.6, summary="maybe idor",
                   evidence="e", suggested_test="t", basis="derived")


def _obj_get(url="https://shop.test/api/orders/1"):
    return HttpExchange(url=url, method="GET")


class CrossIdentityAutoArmTests(unittest.TestCase):
    def setUp(self):
        identity_headers.clear()

    def tearDown(self):
        identity_headers.clear()

    def _names(self, reg, finding, exchange):
        return {getattr(v, "name", "") for v in reg.for_finding(finding, exchange)}

    def test_auto_armed_when_active_with_identities(self):
        reg = _reg(active=True)
        identity_headers.set_identity("shop.test", "alice", {"Cookie": "s=a"}, "user")
        identity_headers.set_identity("shop.test", "bob", {"Cookie": "s=b"}, "user")
        self.assertIn("cross_identity", self._names(reg, _idor(), _obj_get()))
        # Armed for THIS dispatch only -- the explicit toggle/registration is untouched.
        self.assertFalse(reg.cross_identity_enabled())

    def test_not_armed_without_identities(self):
        reg = _reg(active=True)
        self.assertNotIn("cross_identity", self._names(reg, _idor(), _obj_get()))

    def test_not_armed_when_passive(self):
        reg = _reg(active=False)
        identity_headers.set_identity("shop.test", "alice", {"Cookie": "s=a"}, "user")
        self.assertNotIn("cross_identity", self._names(reg, _idor(), _obj_get()))

    def test_not_armed_for_non_access_control_finding(self):
        reg = _reg(active=True)
        identity_headers.set_identity("shop.test", "alice", {"Cookie": "s=a"}, "user")
        xss = Finding(vulnerability_class="xss", confidence=0.6, summary="s",
                      evidence="e", suggested_test="t", basis="derived")
        self.assertNotIn("cross_identity", self._names(reg, xss, _obj_get()))

    def test_explicit_registration_is_not_duplicated(self):
        reg = _reg(active=True)
        reg.set_cross_identity_enabled(True)
        identity_headers.set_identity("shop.test", "alice", {"Cookie": "s=a"}, "user")
        xids = [v for v in reg.for_finding(_idor(), _obj_get())
                if getattr(v, "name", "") == "cross_identity"]
        self.assertEqual(len(xids), 1)


if __name__ == "__main__":
    unittest.main()
