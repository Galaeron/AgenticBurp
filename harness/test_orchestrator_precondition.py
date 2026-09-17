"""Tests for the proactive, precondition-driven leg routing (HANDOVER_6 §4).

These cover the SHAPE routing -- which confirmation legs an endpoint's shape
warrants, independent of any agent label -- at the module level, so the routing
that `investigate_engagement` depends on is exercised without a live model. This
is deliberately the piece the historical "green tests, dead pipeline" failures
lived in: routing code that no test ever ran."""
import unittest

from harness.models import HttpExchange
from harness.role_crawl import RoleSession
from harness.orchestrator import (
    shape_precondition_legs,
    shape_precondition_findings,
    confirmation_cache_key,
    coverage_confirmation_finding,
    second_order_identities,
    bounded_gather,
    _carries_jwt,
    _jwt_identity,
    _accepts_xml,
    _has_url_param,
    _has_injectable_param,
    _has_file_shape,
    _has_redirect_param,
)

# A structurally-valid JWT (header.payload.sig) the regex must recognise.
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjo0fQ.c2lnbmF0dXJl"


def _ex(url="http://t/api/tickets/1", method="GET", headers=None, body=""):
    return HttpExchange(url=url, method=method, request_headers=headers or {},
                        request_body=body, response_status=None,
                        response_headers={}, response_body="")


class ConfirmationCacheKeyTests(unittest.TestCase):
    """R03: the within-run confirmation memoisation key must include IDENTITY and
    finding subtype, so the same URL/body probed as different principals (or for
    different subclasses) does not collide and replay one identity's result into
    another's cell."""

    def test_identical_inputs_same_key(self):
        a = _ex(headers={"Authorization": "Bearer alice"})
        b = _ex(headers={"Authorization": "Bearer alice"})
        self.assertEqual(confirmation_cache_key("cross_identity", a, "idor"),
                         confirmation_cache_key("cross_identity", b, "idor"))

    def test_different_authorization_differs(self):
        alice = _ex(headers={"Authorization": "Bearer alice"})
        admin = _ex(headers={"Authorization": "Bearer admin"})
        self.assertNotEqual(confirmation_cache_key("cross_identity", alice, "idor"),
                            confirmation_cache_key("cross_identity", admin, "idor"))

    def test_different_cookie_differs(self):
        u = _ex(headers={"Cookie": "session=alice"})
        v = _ex(headers={"Cookie": "session=bob"})
        self.assertNotEqual(confirmation_cache_key("cross_identity", u, "idor"),
                            confirmation_cache_key("cross_identity", v, "idor"))

    def test_anonymous_vs_authenticated_differs(self):
        anon = _ex(headers={})
        authed = _ex(headers={"Authorization": "Bearer x"})
        self.assertNotEqual(confirmation_cache_key("sqlmap", anon, "sqli"),
                            confirmation_cache_key("sqlmap", authed, "sqli"))

    def test_different_finding_class_differs(self):
        ex = _ex(headers={"Authorization": "Bearer alice"}, method="POST",
                 body='{"x":1}')
        self.assertNotEqual(confirmation_cache_key("auth_sequence", ex, "session_fixation"),
                            confirmation_cache_key("auth_sequence", ex, "weak_password"))


class CoverageConfirmationFindingTests(unittest.TestCase):
    """R06: a CONFIRMED coverage-driven leg must map to an ingestible finding dict
    so it enters the same state/report pipeline; a non-confirmation maps to None
    (nothing invented)."""

    class _Res:
        def __init__(self, confirmed, fc="sqli", conf=0.95, summary="boom", evidence="ev", validator="sqlmap"):
            self.confirmed = confirmed
            self.finding_class = fc
            self.confidence = conf
            self.summary = summary
            self.evidence = evidence
            self.validator = validator

    class _Check:
        vulnerability_class = "sqli"
        confirmation = "sqlmap"

    def test_confirmed_result_maps_to_finding(self):
        f = coverage_confirmation_finding(self._Res(True), self._Check(), "http://t/x", "user")
        self.assertIsNotNone(f)
        self.assertTrue(f["confirmed"])
        self.assertEqual(f["vulnerability_class"], "sqli")
        self.assertEqual(f["url"], "http://t/x")
        self.assertEqual(f["identity"], "user")
        self.assertEqual(f["confirmation_method"], "sqlmap")
        self.assertEqual(f["evidence"], "ev")

    def test_confirmed_by_leg_matches_the_graph_paths_structured_field(self):
        # 2026-09-17 coverage-recovery plan, Step 4: the coverage-driven path
        # must stamp the SAME structured field name (confirmed_by_leg) the
        # graph-driven path (_validate_findings) stamps, with the same value
        # -- one provenance reader, not "check confirmation_method for
        # coverage-driven, confirmed_by_leg for graph-driven."
        f = coverage_confirmation_finding(self._Res(True, validator="sqlmap"),
                                          self._Check(), "http://t/x", "user")
        self.assertEqual(f["confirmed_by_leg"], "sqlmap")
        self.assertEqual(f["confirmed_by_leg"], f["confirmation_method"])

    def test_confirmed_by_leg_falls_back_to_the_checks_own_confirmation_name(self):
        # When the ValidationResult carries no validator name of its own, the
        # check's own declared confirmation leg is used -- never left blank.
        res = self._Res(True, validator=None)
        f = coverage_confirmation_finding(res, self._Check(), "http://t/x", "user")
        self.assertEqual(f["confirmed_by_leg"], "sqlmap")   # _Check.confirmation

    def test_not_confirmed_result_maps_to_none(self):
        self.assertIsNone(coverage_confirmation_finding(self._Res(False), self._Check(), "http://t/x", "user"))

    def test_none_result_maps_to_none(self):
        self.assertIsNone(coverage_confirmation_finding(None, self._Check(), "http://t/x", "user"))


class SecondOrderIdentitiesTests(unittest.TestCase):
    """R13: second-order plant/read must use authenticated, distinct identities."""

    def test_planter_is_authenticated_not_anonymous(self):
        roles = [RoleSession("anonymous", {}),
                 RoleSession("user", {"Authorization": "Bearer alice"})]
        planter, other = second_order_identities(roles)
        self.assertEqual(planter.get("Authorization"), "Bearer alice")  # not anonymous
        self.assertIsNone(other)                                        # only one authed id

    def test_distinct_other_for_cross_identity_read(self):
        roles = [RoleSession("user", {"Authorization": "Bearer alice"}),
                 RoleSession("user", {"Authorization": "Bearer bob"})]
        planter, other = second_order_identities(roles)
        self.assertEqual(planter.get("Authorization"), "Bearer alice")
        self.assertEqual(other.get("Authorization"), "Bearer bob")     # a DISTINCT principal

    def test_no_authenticated_roles_yields_empty_planter(self):
        planter, other = second_order_identities([RoleSession("anonymous", {})])
        self.assertEqual(planter, {})
        self.assertIsNone(other)


class BoundedGatherTests(unittest.TestCase):
    """R29: validation fan-out must be concurrency-capped, not unbounded."""

    def test_caps_in_flight_and_preserves_order(self):
        import asyncio
        state = {"cur": 0, "peak": 0}

        async def job(i):
            state["cur"] += 1
            state["peak"] = max(state["peak"], state["cur"])
            await asyncio.sleep(0.01)
            state["cur"] -= 1
            return i

        async def run():
            return await bounded_gather([job(i) for i in range(20)], limit=4)

        results = asyncio.run(run())
        self.assertEqual(results, list(range(20)))   # order preserved
        self.assertLessEqual(state["peak"], 4)       # never more than 4 at once

    def test_exceptions_returned_not_raised(self):
        import asyncio

        async def boom():
            raise ValueError("x")

        async def ok():
            return 1

        out = asyncio.run(bounded_gather([boom(), ok()], limit=2))
        self.assertIsInstance(out[0], ValueError)
        self.assertEqual(out[1], 1)


class CarriesJwtTests(unittest.TestCase):
    def test_bearer_jwt_detected(self):
        self.assertTrue(_carries_jwt({"Authorization": f"Bearer {JWT}"}))

    def test_jwt_in_cookie_detected(self):
        self.assertTrue(_carries_jwt({"Cookie": f"session={JWT}"}))

    def test_non_jwt_bearer_not_detected(self):
        self.assertFalse(_carries_jwt({"Authorization": "Bearer opaque-token-abc123"}))

    def test_empty_headers(self):
        self.assertFalse(_carries_jwt({}))
        self.assertFalse(_carries_jwt(None))


class JwtIdentityTests(unittest.TestCase):
    def test_picks_lowest_trust_reachable_role_with_jwt(self):
        roles = [RoleSession("anonymous", {}),
                 RoleSession("user", {"Authorization": f"Bearer {JWT}"}),
                 RoleSession("admin", {"Authorization": f"Bearer {JWT}"})]
        node = {"reachable_roles": ["user", "admin"], "method": "GET", "path": "/api/tickets/{id}"}
        chosen = _jwt_identity(node, roles)
        self.assertEqual(chosen.role, "user")   # lower trust than admin

    def test_none_when_no_reachable_role_carries_jwt(self):
        roles = [RoleSession("anonymous", {}),
                 RoleSession("user", {"Cookie": "sid=opaque"})]
        node = {"reachable_roles": ["anonymous", "user"], "method": "GET", "path": "/x"}
        self.assertIsNone(_jwt_identity(node, roles))

    def test_falls_back_to_any_jwt_role_when_node_lists_no_reachable(self):
        roles = [RoleSession("admin", {"Authorization": f"Bearer {JWT}"})]
        node = {"reachable_roles": [], "method": "GET", "path": "/x"}
        self.assertEqual(_jwt_identity(node, roles).role, "admin")


class AcceptsXmlTests(unittest.TestCase):
    def test_xml_content_type(self):
        self.assertTrue(_accepts_xml(_ex(headers={"Content-Type": "application/xml"}, body="<a/>")))

    def test_xml_body_shape_without_header(self):
        self.assertTrue(_accepts_xml(_ex(body="<?xml version='1.0'?><root/>")))

    def test_doctype_body(self):
        self.assertTrue(_accepts_xml(_ex(body="<!DOCTYPE foo><foo/>")))

    def test_json_is_not_xml(self):
        self.assertFalse(_accepts_xml(_ex(headers={"Content-Type": "application/json"}, body='{"a":1}')))


class HasUrlParamTests(unittest.TestCase):
    def test_url_in_query(self):
        self.assertTrue(_has_url_param(_ex(url="http://t/fetch?target=http://evil.example")))

    def test_url_in_body(self):
        self.assertTrue(_has_url_param(_ex(method="POST", body='{"callback":"https://evil.example/x"}')))

    def test_encoded_url_in_query(self):
        self.assertTrue(_has_url_param(_ex(url="http://t/fetch?u=%2f%2fevil.example")))

    def test_no_url(self):
        self.assertFalse(_has_url_param(_ex(url="http://t/api/tickets/1")))


class ShapePreconditionLegsTests(unittest.TestCase):
    ROLES = [RoleSession("anonymous", {}),
             RoleSession("user", {"Authorization": f"Bearer {JWT}"})]

    def test_object_scoped_get_routes_cross_identity(self):
        node = {"method": "GET", "path": "/api/tickets/{id}", "object_scoped": True,
                "reachable_roles": ["user"]}
        legs = shape_precondition_legs(node, _ex(), self.ROLES, "http://t")
        classes = [c for c, _ in legs]
        self.assertIn("idor", classes)

    def test_jwt_leg_seeded_from_jwt_identity(self):
        node = {"method": "GET", "path": "/api/tickets/mine", "object_scoped": False,
                "reachable_roles": ["user"]}
        legs = shape_precondition_legs(node, _ex(url="http://t/api/tickets/mine"), self.ROLES, "http://t")
        jwt_legs = [ex for c, ex in legs if c == "jwt"]
        self.assertEqual(len(jwt_legs), 1)
        # the jwt leg's seed must carry the JWT identity's Authorization header
        self.assertIn(JWT, jwt_legs[0].request_headers.get("Authorization", ""))

    def test_non_get_object_scoped_gets_no_idor_leg(self):
        node = {"method": "POST", "path": "/api/tickets/{id}", "object_scoped": True,
                "reachable_roles": ["user"]}
        legs = shape_precondition_legs(node, _ex(method="POST"), self.ROLES, "http://t")
        self.assertNotIn("idor", [c for c, _ in legs])

    def test_xml_body_routes_xxe(self):
        node = {"method": "POST", "path": "/api/import", "reachable_roles": ["user"]}
        ex = _ex(url="http://t/api/import", method="POST",
                 headers={"Content-Type": "application/xml"}, body="<a/>")
        legs = shape_precondition_legs(node, ex, self.ROLES, "http://t")
        self.assertIn("xxe", [c for c, _ in legs])

    def test_url_param_routes_ssrf(self):
        node = {"method": "GET", "path": "/api/fetch", "reachable_roles": ["anonymous"]}
        ex = _ex(url="http://t/api/fetch?target=http://evil.example")
        legs = shape_precondition_legs(node, ex, self.ROLES, "http://t")
        self.assertIn("ssrf", [c for c, _ in legs])

    def test_benign_node_routes_nothing(self):
        node = {"method": "GET", "path": "/api/health", "object_scoped": False,
                "reachable_roles": ["anonymous"]}
        # anonymous carries no JWT, not object-scoped, no xml/url -> no legs
        legs = shape_precondition_legs(node, _ex(url="http://t/api/health"),
                                       [RoleSession("anonymous", {})], "http://t")
        self.assertEqual(legs, [])

    def test_object_scoped_jwt_endpoint_routes_both(self):
        node = {"method": "GET", "path": "/api/tickets/{id}", "object_scoped": True,
                "reachable_roles": ["user"]}
        legs = shape_precondition_legs(node, _ex(), self.ROLES, "http://t")
        classes = [c for c, _ in legs]
        self.assertIn("idor", classes)
        self.assertIn("jwt", classes)

    def test_injectable_param_routes_cmdi_and_ssti(self):
        node = {"method": "GET", "path": "/api/tickets/search", "reachable_roles": ["user"]}
        ex = _ex(url="http://t/api/tickets/search?q=test")
        classes = [c for c, _ in shape_precondition_legs(node, ex, self.ROLES, "http://t")]
        self.assertIn("command_injection", classes)
        self.assertIn("ssti", classes)

    def test_fileish_path_segment_routes_path_traversal(self):
        node = {"method": "GET", "path": "/uploads/{id}", "reachable_roles": ["anonymous"]}
        ex = _ex(url="http://t/uploads/1")
        classes = [c for c, _ in shape_precondition_legs(node, ex, self.ROLES, "http://t")]
        self.assertIn("path_traversal", classes)

    def test_redirect_param_routes_open_redirect(self):
        node = {"method": "GET", "path": "/login", "reachable_roles": ["anonymous"]}
        ex = _ex(url="http://t/login?next=/dashboard")
        classes = [c for c, _ in shape_precondition_legs(node, ex, self.ROLES, "http://t")]
        self.assertIn("open_redirect", classes)

    def test_bare_object_path_does_not_route_injection_legs(self):
        # /api/tickets/1 has no params and is not file-ish -> no cmdi/ssti/path/redir.
        classes = [c for c, _ in shape_precondition_legs(
            {"method": "GET", "path": "/api/tickets/{id}", "reachable_roles": ["user"]},
            _ex(), self.ROLES, "http://t")]
        for c in ("command_injection", "ssti", "path_traversal", "open_redirect"):
            self.assertNotIn(c, classes)

    def test_settable_json_body_routes_mass_assignment(self):
        # Step 3 (2026-09-17 coverage-recovery plan): a POST with a settable
        # JSON body (e.g. /api/account/profile, /api/register) previously got
        # NO shape-driven mass-assignment leg at all -- only an agent that
        # happened to label it 'mass_assignment' itself would trigger the
        # sequence validator, reproducing the exact detection->confirmation
        # coupling this module exists to remove for every other class.
        node = {"method": "POST", "path": "/api/account/profile", "reachable_roles": ["user"]}
        ex = _ex(url="http://t/api/account/profile", method="POST",
                 body='{"role":"user","email":"me@t"}')
        classes = [c for c, _ in shape_precondition_legs(node, ex, self.ROLES, "http://t")]
        self.assertIn("mass_assignment", classes)

    def test_settable_form_body_on_register_routes_mass_assignment(self):
        node = {"method": "POST", "path": "/api/register", "reachable_roles": ["anonymous"]}
        ex = _ex(url="http://t/api/register", method="POST", body="username=me&role=user")
        classes = [c for c, _ in shape_precondition_legs(node, ex, self.ROLES, "http://t")]
        self.assertIn("mass_assignment", classes)

    def test_get_only_no_body_does_not_route_mass_assignment(self):
        # Negative control: a GET-only node with no body must not be mislabeled
        # as tested for mass-assignment -- there is nothing settable to probe.
        node = {"method": "GET", "path": "/api/account/profile", "reachable_roles": ["user"]}
        ex = _ex(url="http://t/api/account/profile", method="GET")
        classes = [c for c, _ in shape_precondition_legs(node, ex, self.ROLES, "http://t")]
        self.assertNotIn("mass_assignment", classes)

    def test_post_with_no_object_body_does_not_route_mass_assignment(self):
        # Negative control: a mutating method with an empty/non-object body
        # (no settable fields) is not a mass-assignment target either.
        node = {"method": "POST", "path": "/api/logout", "reachable_roles": ["user"]}
        ex = _ex(url="http://t/api/logout", method="POST", body="")
        classes = [c for c, _ in shape_precondition_legs(node, ex, self.ROLES, "http://t")]
        self.assertNotIn("mass_assignment", classes)


class ShapePredicateTests(unittest.TestCase):
    def test_has_injectable_param(self):
        self.assertTrue(_has_injectable_param(_ex(url="http://t/s?q=1")))
        self.assertTrue(_has_injectable_param(_ex(method="POST", headers={"Content-Type": "application/json"},
                                                  body='{"a":1}')))
        self.assertFalse(_has_injectable_param(_ex(url="http://t/api/tickets/1")))

    def test_has_file_shape(self):
        self.assertTrue(_has_file_shape(_ex(url="http://t/d?file=a.txt")))     # file param
        self.assertTrue(_has_file_shape(_ex(url="http://t/uploads/1")))        # file-ish segment
        self.assertFalse(_has_file_shape(_ex(url="http://t/api/tickets/1")))   # neither

    def test_has_redirect_param(self):
        self.assertTrue(_has_redirect_param(_ex(url="http://t/login?next=/x")))
        self.assertFalse(_has_redirect_param(_ex(url="http://t/s?q=1")))


class ShapePreconditionFindingsTests(unittest.TestCase):
    def test_injectable_param_yields_cmdi_and_ssti_findings(self):
        classes = {f.vulnerability_class for f in
                   shape_precondition_findings(_ex(url="http://t/s?q=test"))}
        self.assertIn("command_injection", classes)
        self.assertIn("ssti", classes)

    def test_fileish_segment_yields_path_traversal_finding(self):
        classes = {f.vulnerability_class for f in
                   shape_precondition_findings(_ex(url="http://t/uploads/1"))}
        self.assertIn("path_traversal", classes)

    def test_redirect_param_yields_open_redirect_finding(self):
        classes = {f.vulnerability_class for f in
                   shape_precondition_findings(_ex(url="http://t/go?next=/x"))}
        self.assertIn("open_redirect", classes)

    def test_benign_object_get_yields_nothing(self):
        self.assertEqual(shape_precondition_findings(_ex(url="http://t/api/tickets/1")), [])

    def test_csrf_shape_on_post_without_token(self):
        classes = {f.vulnerability_class for f in
                   shape_precondition_findings(_ex(url="http://t/api/tickets",
                                                    method="POST", body='{"title":"x"}'))}
        self.assertIn("csrf", classes)

    def test_no_csrf_shape_on_get(self):
        classes = {f.vulnerability_class for f in
                   shape_precondition_findings(_ex(url="http://t/api/tickets"))}
        self.assertNotIn("csrf", classes)

    def test_no_csrf_shape_when_token_present(self):
        classes = {f.vulnerability_class for f in
                   shape_precondition_findings(_ex(url="http://t/api/tickets",
                                                    method="POST",
                                                    body='csrf_token=abc&title=x'))}
        self.assertNotIn("csrf", classes)

    def test_mass_assignment_shape_on_post_with_json_body(self):
        classes = {f.vulnerability_class for f in
                   shape_precondition_findings(_ex(url="http://t/api/users/1",
                                                    method="PUT",
                                                    body='{"name":"x"}'))}
        self.assertIn("mass_assignment", classes)

    def test_no_mass_assignment_shape_on_get(self):
        classes = {f.vulnerability_class for f in
                   shape_precondition_findings(_ex(url="http://t/api/users/1"))}
        self.assertNotIn("mass_assignment", classes)

    def test_no_mass_assignment_shape_with_empty_body(self):
        classes = {f.vulnerability_class for f in
                   shape_precondition_findings(_ex(url="http://t/api/users/1",
                                                    method="POST", body=""))}
        self.assertNotIn("mass_assignment", classes)


if __name__ == "__main__":
    unittest.main()
