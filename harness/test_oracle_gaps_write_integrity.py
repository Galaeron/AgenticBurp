"""write_integrity gaps: parameter pollution on a cross-identity create, forged
authorship on an update, and the owner's opt-in for self-service registrations
with no DELETE route, each against an owned loopback JSON store with its
negative control on the same store.

The store extends the generic one in test_write_integrity: it parses the raw body
pair by pair, so a duplicate key is visible. Its "check_first" mode is the classic
split parser: the ownership check reads the FIRST member of a duplicate key while
the stored object keeps the LAST (and an array is checked by its first element).
"reject_pollution" refuses duplicate keys and arrays outright; "check_every"
checks every member. Updates honour "bind_author" (the author is forced to the
session's own) and "refuse_author" (a foreign author is refused).
"""
import json
import unittest

from harness.models import HttpExchange
from harness.test_write_integrity import _EMAIL, _Fixture, _Store, _seed
from harness.validators.write_integrity_validator import _polluted


class _PairStore(_Store):
    def body(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}"
        self.dup, self.first = False, {}

        def hook(pairs):
            keys = [k for k, _ in pairs]
            self.dup = self.dup or len(keys) != len(set(keys))
            first = {}
            for k, v in pairs:
                first.setdefault(k, v)
            self.first = first   # the outermost object is hooked last
            return dict(pairs)   # the last member wins in what is stored

        return json.loads(raw, object_pairs_hook=hook)

    def rules(self, coll, data, objs, oid=None):
        modes, who = self.server.modes, self.caller()
        if "reject_pollution" in modes and (self.dup or any(isinstance(v, list) for v in data.values())):
            return 400, {"error": "malformed body"}
        if coll == "items" and "listId" in data:
            first = self.first.get("listId", data["listId"])
            checked = {"check_first": [first], "check_every": [first, data["listId"]]}
            for mode, values in checked.items():
                if mode not in modes:
                    continue
                for value in values:
                    value = value[0] if isinstance(value, list) and value else value
                    if not isinstance(value, int) or self.server.owners.get(("lists", value)) != who:
                        return 403, {"error": "not your list"}
        if coll == "notes" and oid is not None and "refuse_author" in modes \
                and data.get("author") not in (None, _EMAIL.get(who)):
            return 403, {"error": "you are not the author"}
        return None

    def update(self):
        if self.command in ("PUT", "PATCH") and "bind_author" in self.server.modes:
            coll, oid = self.route()
            data = self.body()
            self.server.received.append((self.command, self.path, self.caller()))
            if coll is None or oid not in self.server.data.get(coll, {}):
                return self.reply(404, {"error": "not found"})
            if "author" in data:
                data["author"] = _EMAIL.get(self.caller(), "")
            objs = self.server.data[coll]
            objs[oid] = {**data, "id": oid} if self.command == "PUT" else {**objs[oid], **data}
            return self.reply(200, {"status": "success", "data": self.public(coll, objs[oid])})
        return super().update()

    do_PUT = do_PATCH = update


_ITEM = {"listId": 1, "name": "pen", "quantity": 2}
_NOTE = {"id": 20, "author": "alice@example.test", "text": "hello"}
_ACCOUNT = {"email": "new@example.test", "password": "pw-123456", "name": "Newcomer"}


class _PairFixture(_Fixture, unittest.IsolatedAsyncioTestCase):   # base named for the static checks
    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.server.RequestHandlerClass = _PairStore
        self.server.data["notes"][20] = dict(_NOTE)
        self.server.owners[("notes", 20)] = "Bearer a"

    def seed(self):
        data = _seed()
        data["notes"][20] = dict(_NOTE)
        return data

    def assert_store_restored(self):
        self.assertEqual(self.server.data, self.seed(), "the store was not returned to its seed state")


class ParameterPollutionTests(_PairFixture):
    async def test_duplicate_key_split_parser_is_confirmed_by_read_back_and_deleted(self):
        self.server.modes.add("check_first")
        result, run = await self.dispatch("cross_identity_write", "/api/items", _ITEM)
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertIn("parameter pollution", result.summary)
        self.assertIn("writer's value first", result.summary)
        self.assertIn("listId=2", result.summary)
        self.assertIn("refused (HTTP 403)", result.summary)
        self.assertIn("restore_succeeded=true", result.evidence)
        # control (own list), plain attack (bob's list, refused), then the variant.
        self.assertEqual([b.get("listId") for b in self.server.bodies], [1, 2, 2])
        self.assert_store_restored()
        self.assert_creates_restored(run)

    async def test_a_server_that_rejects_pollution_is_a_held_control(self):
        self.server.modes.update({"check_first", "reject_pollution"})
        result, run = await self.dispatch("cross_identity_write", "/api/items", _ITEM)
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertEqual(result.control_outcome, "control_held")
        self.assertIn("did not land", result.summary)
        self.assertIn("dup-own-first: HTTP 400", result.summary)
        self.assert_store_restored()
        self.assert_creates_restored(run)

    async def test_a_server_that_checks_every_member_is_a_held_control(self):
        self.server.modes.add("check_every")
        result, run = await self.dispatch("cross_identity_write", "/api/items", _ITEM)
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertEqual(result.control_outcome, "control_held")
        self.assertNotIn("parameter pollution", result.summary)
        self.assert_store_restored()

    async def test_variants_the_ceiling_cannot_pay_for_are_named_not_sent(self):
        self.server.modes.add("check_every")
        result, _ = await self.dispatch("cross_identity_write", "/api/items", _ITEM, ceiling=4)
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertIn("not sent:", result.summary)
        self.assertIn("mutating headroom", result.summary)
        self.assertLessEqual(len(self.writes()), 4)
        self.assert_store_restored()

    def test_polluted_body_carries_the_key_twice_in_order(self):
        raw = _polluted({"listId": 1, "name": "pen"}, "listId", 1, 2)
        pairs = json.loads(raw, object_pairs_hook=lambda p: p)
        self.assertEqual([v for k, v in pairs if k == "listId"], [1, 2])
        self.assertEqual(json.loads(raw)["listId"], 2)
        self.assertEqual(json.loads(_polluted({}, "k", "a", "b"), object_pairs_hook=lambda p: p),
                         [("k", "a"), ("k", "b")])


class UpdateAuthorshipTests(_PairFixture):
    async def test_forged_author_on_put_is_confirmed_and_written_back(self):
        result, run = await self.dispatch("forged_authorship", "/api/notes/20", _NOTE, method="PUT")
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertIn("Forged authorship on update", result.summary)
        self.assertIn("written back and verified", result.summary)
        self.assertIn("restore_succeeded=true", result.evidence)
        self.assertEqual([m for m, _ in self.writes()], ["PUT", "PUT", "PUT"])
        self.assert_store_restored()
        self.assertEqual(run.change_log.failed_restores(), [])

    async def test_forged_author_on_patch_is_confirmed_and_written_back(self):
        result, _ = await self.dispatch("forged_authorship", "/api/notes/20",
                                        {"author": "alice@example.test"}, method="PATCH")
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assert_store_restored()

    async def test_author_bound_to_the_session_is_a_held_control(self):
        self.server.modes.add("bind_author")
        result, _ = await self.dispatch("forged_authorship", "/api/notes/20", _NOTE, method="PUT")
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertEqual(result.control_outcome, "control_held")
        self.assertIn("alice@example.test", result.summary)
        self.assert_store_restored()

    async def test_refused_foreign_author_is_a_held_control(self):
        self.server.modes.add("refuse_author")
        result, _ = await self.dispatch("forged_authorship", "/api/notes/20", _NOTE, method="PUT")
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertEqual(result.control_outcome, "control_held")
        self.assertIn("HTTP 403", result.summary)
        self.assert_store_restored()

    async def test_put_without_an_object_id_is_skipped_with_no_write(self):
        result, _ = await self.dispatch("forged_authorship", "/api/notes", _NOTE, method="PUT")
        self.assertEqual(result.status, "skipped", result.summary)
        self.assertIn("does not end in an object id", result.summary)
        self.assertNotIn("needs a POST create", result.summary)
        self.assertEqual(self.server.received, [])


class SelfServiceOptInTests(_PairFixture):
    _NO_ACCOUNT_DELETE = ("DELETE /api/items/{id}", "DELETE /api/notes/{id}")

    async def anonymous(self, opt_in):
        reg, run = self.build(restore_routes=self._NO_ACCOUNT_DELETE)
        if opt_in is not None:
            run.config["validators"]["write_integrity"]["allow_unrestorable_self_service_creates"] = opt_in
        finding, ex = self.capture("mass_assignment_create", "/api/accounts", _ACCOUNT)
        ex.request_headers.pop("Authorization")
        legs = [v for v in reg.bind_run_context(reg.for_finding(finding, ex), run)
                if v.name == "write_integrity"]
        self.assertTrue(legs)
        async with run:
            return await legs[0].validate(finding, ex)

    async def test_off_by_default_skips_and_names_the_opt_in(self):
        for opt_in in (None, "true", 1):
            result = await self.anonymous(opt_in)
            self.assertEqual(result.status, "skipped", result.summary)
            self.assertIn("allow_unrestorable_self_service_creates (off by default)", result.summary)
        self.assertEqual(self.writes(), [])

    async def test_opt_in_runs_and_names_every_account_left_in_place(self):
        result = await self.anonymous(True)
        self.assertEqual(result.status, "confirmed", result.summary)
        left = self.server.data["accounts"]
        self.assertEqual(len(left), 2, "control and attack accounts stay, and nothing else")
        self.assertIn("NOT deleted", result.summary)
        for oid in left:
            self.assertIn(f"/api/accounts/{oid}", result.summary)
        self.assertIn("restore=left_in_place", result.evidence)
        self.assertNotIn("DELETE", [m for m, _ in self.writes()])

    async def test_opt_in_never_covers_an_authenticated_create(self):
        reg, run = self.build(restore_routes=self._NO_ACCOUNT_DELETE)
        run.config["validators"]["write_integrity"]["allow_unrestorable_self_service_creates"] = True
        finding, ex = self.capture("mass_assignment_create", "/api/accounts", _ACCOUNT)
        legs = [v for v in reg.bind_run_context(reg.for_finding(finding, ex), run)
                if v.name == "write_integrity"]
        async with run:
            result = await legs[0].validate(finding, ex)
        self.assertEqual(result.status, "skipped", result.summary)
        self.assertIn("no restore path known", result.summary)
        self.assertEqual(self.writes(), [])


_TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0aHJvd2F3YXkifQ.c2lnbmF0dXJlLW9ubHk"


class _SignupStore(_PairStore):
    """Sign-ups plus a login. "unique_email" refuses a taken email (409, nothing
    stored); "empty_stored_400" STORES a sign-up with an empty field and then
    answers 400; "empty_refused" answers 400 and stores nothing (the negative
    control); "login_any_password" lets any password log in to a known email."""

    def rules(self, coll, data, objs, oid=None):
        modes = self.server.modes
        if coll == "accounts" and oid is None:
            if "unique_email" in modes and any(o.get("email") == data.get("email") for o in objs.values()):
                return 409, {"error": "email taken"}
            if any(isinstance(v, str) and not v for v in data.values()):
                if "empty_stored_400" in modes:
                    new_id = self.server.next_id
                    self.server.next_id += 1
                    objs[new_id] = {**self.shape(coll, data), "id": new_id}
                    return 400, {"error": "validation failed"}
                if "empty_refused" in modes:
                    return 400, {"error": "validation failed"}
        return super().rules(coll, data, objs, oid)

    def do_POST(self):
        if self.path.split("?")[0].rstrip("/") not in ("/auth/login", "/auth/signin"):
            return super().do_POST()
        data = self.body()
        self.server.received.append(("POST", self.path, self.caller()))
        self.server.logins.append((self.path, data))
        any_pw = "login_any_password" in self.server.modes
        for acc in self.server.data["accounts"].values():
            if acc.get("email") == data.get("email") and (any_pw or acc.get("password") == data.get("password")):
                return self.reply(200, {"authentication": {"token": _TOKEN, "umail": acc.get("email")}})
        return self.reply(401, {"error": "invalid email or password"})


class SignupLoginReadBackTests(_PairFixture):
    """create_validation on the opt-in path: a refused sign-up is read back by
    logging in with the credentials it submitted, through an observed login."""
    _ROUTES = ("DELETE /api/items/{id}", "POST /auth/login")

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.server.RequestHandlerClass = _SignupStore
        self.server.logins = []

    async def signup(self, *, routes=_ROUTES, ceiling=8, captured=None):
        reg, run = self.build(restore_routes=routes, ceiling=ceiling)
        run.config["validators"]["write_integrity"]["allow_unrestorable_self_service_creates"] = True
        if captured is not None:
            run.experiment_context = {"captured": captured}
        finding, ex = self.capture("create_validation", "/api/accounts", _ACCOUNT)
        ex.request_headers.pop("Authorization")
        legs = [v for v in reg.bind_run_context(reg.for_finding(finding, ex), run)
                if v.name == "write_integrity"]
        async with run:
            result = await legs[0].validate(finding, ex)
        text = result.summary + result.evidence
        self.assertNotIn(_TOKEN, text)
        self.assertNotIn("eyJ", text, "a token reached the verdict")
        self.assertNotIn(_ACCOUNT["password"], text, "a password reached the verdict")
        self.assertNotIn("wi-wrong-", text)
        return result

    async def test_empty_signup_stored_despite_400_is_confirmed_by_login_and_named(self):
        self.server.modes.update({"unique_email", "empty_stored_400"})
        result = await self.signup()
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertIn("stored despite HTTP 400", result.summary)
        self.assertIn("failed before the create (HTTP 401)", result.summary)
        self.assertIn("a wrong password was refused (HTTP 401)", result.summary)
        self.assertIn("the account email='' (logs in at POST /auth/login)", result.summary)
        self.assertIn("login_empty=before:401,after:200,wrong:401->stored", result.evidence)
        self.assertIn("left_in_place=", result.evidence)
        self.assertIn("email=''", result.evidence.split("left_in_place=", 1)[1])
        # The empty login is before, after and the wrong-password control, in that order.
        empties = [d for _, d in self.server.logins if d.get("email") == ""]
        self.assertEqual(len(empties), 3)
        self.assertEqual([d["password"] for d in empties[:2]], ["", ""])
        self.assertNotEqual(empties[2]["password"], "")
        # The duplicates share one credential pair, so neither is logged in as.
        self.assertEqual(len(self.server.logins), 3)

    async def test_a_refused_signup_that_was_not_stored_is_a_held_control(self):
        self.server.modes.update({"unique_email", "empty_refused"})
        result = await self.signup()
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertEqual(result.control_outcome, "control_held")
        self.assertIn("failed before (HTTP 401) and after it (HTTP 401)", result.summary)
        self.assertIn("->not_stored", result.evidence)
        self.assertFalse(any(a.get("email") == "" for a in self.server.data["accounts"].values()))

    async def test_an_account_that_already_logs_in_is_not_claimed(self):
        self.server.modes.update({"unique_email", "empty_stored_400"})
        self.server.data["accounts"][50] = {"id": 50, "email": "", "password": "", "name": "", "role": "customer"}
        result = await self.signup()
        self.assertEqual(result.status, "inconclusive", result.summary)
        self.assertFalse(result.confirmed)
        self.assertIn("already succeeded before the create", result.summary)
        self.assertNotIn("stored despite", result.summary)
        self.assertIn("->existing", result.evidence)
        self.assertEqual(len([1 for _, d in self.server.logins if d.get("email") == ""]), 1)

    async def test_a_login_that_takes_any_password_proves_nothing(self):
        self.server.modes.update({"unique_email", "empty_stored_400", "login_any_password"})
        result = await self.signup()
        self.assertEqual(result.status, "inconclusive", result.summary)
        self.assertIn("wrong-password control did not fail (HTTP 200)", result.summary)
        self.assertIn("->unsure", result.evidence)

    async def test_no_observed_login_route_leaves_the_verdict_unchanged(self):
        self.server.modes.update({"unique_email", "empty_stored_400"})
        result = await self.signup(routes=("DELETE /api/items/{id}",))
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertIn("the empty create was refused (HTTP 400)", result.summary)
        self.assertIn("observed no login route", result.summary)
        self.assertEqual(self.server.logins, [])
        self.assertNotIn("login_", result.evidence)

    async def test_a_captured_login_is_used_with_its_own_field_names(self):
        self.server.modes.update({"unique_email", "empty_stored_400"})
        seen = HttpExchange(url=self.origin + "/auth/signin", method="POST",
                            request_body=json.dumps({"email": "someone@example.test", "password": "pw",
                                                     "remember": True}),
                            response_status=200)
        result = await self.signup(routes=("DELETE /api/items/{id}",), captured=[seen])
        self.assertEqual(result.status, "confirmed", result.summary)
        self.assertIn("login=a captured login (POST /auth/signin)", result.evidence)
        self.assertTrue(self.server.logins)
        for path, body in self.server.logins:
            self.assertEqual(path, "/auth/signin")
            self.assertIs(body.get("remember"), True)
            self.assertNotEqual(body.get("email"), "someone@example.test")

    async def test_a_ceiling_that_cannot_pay_for_the_logins_sends_none(self):
        self.server.modes.update({"unique_email", "empty_stored_400"})
        result = await self.signup(ceiling=6)
        self.assertEqual(result.status, "not_confirmed", result.summary)
        self.assertIn("login read-back needs 7 mutating sends", result.summary)
        self.assertEqual(self.server.logins, [])


if __name__ == "__main__":
    unittest.main()
