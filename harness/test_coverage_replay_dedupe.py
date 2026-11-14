"""Coverage drive: one replay per distinct capture, no injection legs on a polling
transport, a per-(endpoint, check) time share, and object ids found by their name.

r9's drive replayed every capture of an endpoint with the whole check battery. A
long-polling route captured 23 times (differing only by `t` and `sid`) took about
half of a 4 h drive, and the drive's check dispatch had no polling-transport rule.

- replay_dedupe / engagement.replayable_variants merge captures of ONE identity that
  differ only by throwaway values AND drew the same response. Controls: different
  object ids (path, query, JSON body), different input names, different responses,
  different identities, too few samples, a value the server handed out, and
  id-shaped values all stay apart.
- registry.capability_for_check refuses injection and CSRF legs on a polling
  transport, like for_finding already did; other routes are unchanged.
- The drive stops replaying one endpoint's captures for one check once that check
  used its share of a time-bound drive, and says so; share 0 is the control.
- idor_read._locate_id finds an id under an identifier-named query key that is not
  in the fixed key list, without moving an id an earlier rule found.

Generic loopback fixtures only. The drive tests enter investigate_engagement as the
server does; the legs they count are recorded, not sent.
"""
from __future__ import annotations

import asyncio
import json
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from harness import coverage_tracker, engagement, engagement_builder
from harness.engagement import capture_identity_key, normalize_path, replayable_variants
from harness.engagement_policy import EngagementPolicy
from harness.models import HttpExchange
from harness.replay_dedupe import MIN_SAMPLES, distinct_replays
from harness.test_engagement_transport_callers import _ROLES, _EngagementCallerBase, _config
from harness.validators.base import ValidationResult
from harness.validators.idor_read_validator import _locate_id

BASE = "http://127.0.0.1:9"
ALICE_ID = _ROLES[1].principal_id()
ALICE = {"Authorization": "Bearer alice-token"}
BOB = {"Authorization": "Bearer bob-token"}
_OBJECT = '{"id": 7, "name": "lamp", "price": 3}'
_NONCES = ["Xq7Lm2Rt9z", "Hb4Kp8Wd3s", "Tn6Vc1Jf5y", "Ga9Ze3Qu7m", "Pk2Ys8Bx4w"]


def _exchange(path, *, method="GET", headers=ALICE, body="", status=200, response=_OBJECT,
              ctype="application/json", base=BASE):
    request_headers = dict(headers)
    if body:
        request_headers["Content-Type"] = "application/json"
    return HttpExchange(url=base + path, method=method, request_headers=request_headers,
                        request_body=body, response_status=status,
                        response_headers={"Content-Type": ctype}, response_body=response)


def _endpoint(*exchanges):
    state = engagement.EngagementState(host="127.0.0.1")
    for ex in exchanges:
        state.record_template(ex.url, ex.method, ex)
    (ep,) = state.endpoints.values()
    return ep


def _replays(ep, headers=ALICE):
    return replayable_variants(ep, capture_identity_key(headers))


class MergeRuleTests(unittest.TestCase):
    def test_captures_differing_only_by_a_learned_token_are_replayed_once(self):
        ep = _endpoint(*[_exchange(f"/api/items/7?nonce={n}") for n in _NONCES[:4]])
        self.assertEqual(len(ep.capture_variants), 4)
        replays = _replays(ep)
        self.assertEqual(len(replays), 1)
        self.assertIs(replays[0], ep.capture_variants[0], "the first capture is replayed")

    def test_without_the_merge_every_capture_is_replayed(self):
        """Control: the same endpoint with distinct_replays patched out."""
        ep = _endpoint(*[_exchange(f"/api/items/7?nonce={n}") for n in _NONCES[:4]])
        with patch("harness.replay_dedupe.distinct_replays",
                   lambda variants, **kw: list(variants)):
            self.assertEqual(len(_replays(ep)), 4)

    def test_a_known_cache_buster_merges_from_two_captures(self):
        ep = _endpoint(_exchange("/api/items/7?_=1762689296"), _exchange("/api/items/7?_=1762689301"))
        self.assertEqual(len(_replays(ep)), 1)

    def test_a_token_seen_fewer_than_the_minimum_times_is_not_learned(self):
        ep = _endpoint(*[_exchange(f"/api/items/7?nonce={n}") for n in _NONCES[:MIN_SAMPLES - 1]])
        self.assertEqual(len(_replays(ep)), MIN_SAMPLES - 1)

    def test_a_token_the_server_handed_out_is_not_learned(self):
        echoed = [_exchange(f"/api/items/7?nonce={n}", response=json.dumps({"id": 7, "ref": n}))
                  for n in _NONCES[:4]]
        self.assertEqual(len(_replays(_endpoint(*echoed))), 4)

    def test_id_shaped_values_are_never_learned(self):
        for values in (["101", "102", "103", "104"], ["a3f9c2d1e8", "b7e1d4c2a9", "c1d2e3f4a5", "d9e8f7a6b5"],
                       ["apple", "melon", "lemon", "grape"]):
            with self.subTest(values=values):
                ep = _endpoint(*[_exchange(f"/api/items/list?pick={v}") for v in values])
                self.assertEqual(len(_replays(ep)), 4)

    def test_different_path_object_ids_stay_apart(self):
        ep = _endpoint(*[_exchange(f"/api/items/{i}?nonce={n}") for i, n in zip((7, 8, 9), _NONCES)])
        self.assertEqual(len(_replays(ep)), 3)

    def test_different_query_object_ids_stay_apart_whatever_their_shape(self):
        ids = ["Kd8Rw2Lp5x", "Mn3Qv7Ts1z", "Wb6Hy4Cg9k"]   # opaque, but named as an id
        ep = _endpoint(*[_exchange(f"/api/items/list?basketId={i}&nonce={n}") for i, n in zip(ids, _NONCES)])
        self.assertEqual(len(_replays(ep)), 3)

    def test_different_json_body_object_ids_stay_apart(self):
        ep = _endpoint(*[_exchange("/api/cart/items", method="POST", status=201,
                                   body=json.dumps({"BasketId": b, "nonce": n}))
                         for b, n in zip((1, 2, 3, 3), _NONCES)])
        replays = _replays(ep)
        self.assertEqual([json.loads(v["template"]["body"])["BasketId"] for v in replays], [1, 2, 3])

    def test_different_input_names_stay_apart(self):
        ep = _endpoint(_exchange(f"/api/items/list?sort=price&nonce={_NONCES[0]}"),
                       _exchange(f"/api/items/list?order=price&nonce={_NONCES[1]}"),
                       _exchange(f"/api/items/list?sort=price&nonce={_NONCES[2]}"))
        self.assertEqual(len(_replays(ep)), 2)

    def test_a_different_response_stays_apart(self):
        ep = _endpoint(_exchange(f"/api/items/7?nonce={_NONCES[0]}"),
                       _exchange(f"/api/items/7?nonce={_NONCES[1]}", status=403,
                                 response='{"error": "forbidden"}'),
                       _exchange(f"/api/items/7?nonce={_NONCES[2]}"),
                       _exchange(f"/api/items/7?nonce={_NONCES[3]}",
                                 response='{"id": 7, "name": "lamp", "price": 3, "owner": 2}'))
        self.assertEqual([v["response_status"] for v in _replays(ep)], [200, 403, 200])

    def test_identities_are_never_merged(self):
        ep = _endpoint(*[_exchange(f"/api/items/7?nonce={n}", headers=h)
                         for n, h in zip(_NONCES, (ALICE, BOB, ALICE, BOB, ALICE))])
        self.assertEqual(len(_replays(ep, ALICE)), 1)
        self.assertEqual(len(_replays(ep, BOB)), 1)
        self.assertNotEqual(_replays(ep, ALICE)[0]["identity_key"], _replays(ep, BOB)[0]["identity_key"])
        mixed = distinct_replays(ep.capture_variants)
        self.assertEqual(len(mixed), 2, "a mixed list still keeps one per identity")

    def test_polling_framing_merges_only_on_a_polling_transport(self):
        poll = [_exchange(f"/rt/?EIO=4&transport=polling&t=P{n}&sid={s}", ctype="text/plain",
                          response="2")
                for n, s in zip(("a1", "b2", "c3"), ("s1AbCdEfGhIj", "s2KlMnOpQrSt", "s3UvWxYzAbCd"))]
        self.assertEqual(len(_replays(_endpoint(*poll))), 1)
        plain = [_exchange(f"/rt/?transport=x&sid={s}", ctype="text/plain", response="2")
                 for s in ("s1AbCdEfGhIj", "s2KlMnOpQrSt", "s3UvWxYzAbCd")]
        self.assertEqual(len(_replays(_endpoint(*plain))), 3, "`sid` names an object elsewhere")


class PollingCapabilityTests(unittest.TestCase):
    def setUp(self):
        from harness.coverage_model import CHECKS_BY_ID
        from harness.validators.registry import ValidatorRegistry
        cfg = _config(mutating=False)
        self.registry = ValidatorRegistry(cfg)
        self.cmdi = CHECKS_BY_ID["WSTG-INJT-12"]

    def decide(self, url):
        from harness.validators.command_injection_validator import CommandInjectionValidator
        return self.registry.capability_for_check(
            self.cmdi, HttpExchange(url=url, method="GET"),
            validator=CommandInjectionValidator(allowed_hosts=["127.0.0.1"]))

    def test_an_injection_leg_on_a_polling_transport_is_inapplicable(self):
        decision = self.decide(BASE + "/rt/?EIO=4&transport=polling&t=Pa1")
        self.assertEqual((decision["status"], decision["reason_code"]),
                         ("unsupported", "protocol_inapplicable"))

    def test_the_same_leg_on_an_ordinary_query_is_ready(self):
        self.assertEqual(self.decide(BASE + "/api/items/list?q=lamp")["status"], "ready")
        self.assertEqual(self.decide(BASE + "/rt/?EIO=4&transport=websocket")["status"], "ready")


class LocateIdTests(unittest.TestCase):
    def locate(self, path):
        return _locate_id(HttpExchange(url=BASE + path, method="GET"))

    def test_an_identifier_named_query_key_outside_the_fixed_list_is_found(self):
        self.assertEqual(self.locate("/api/items/list?basketId=3"), ("query", "basketId", "3"))
        self.assertEqual(self.locate("/api/items/list?invoice_id=a3f9c2d1e8"),
                         ("query", "invoice_id", "a3f9c2d1e8"))

    def test_earlier_rules_keep_their_id(self):
        self.assertEqual(self.locate("/api/items/7?basketId=3"), ("path", 3, "7"))
        self.assertEqual(self.locate("/api/items/list?basketId=3&id=9"), ("query", "id", "9"))

    def test_controls_find_nothing(self):
        for path in ("/api/items/list?q=3",                       # not named as an id
                     "/api/items/list?basketId=lamp",             # not id-shaped
                     "/rt/?EIO=4&transport=polling&sid=1234"):    # transport framing
            with self.subTest(path=path):
                self.assertIsNone(self.locate(path))


class ShareSettingTests(unittest.TestCase):
    def test_committed_default_and_bounds(self):
        self.assertEqual(EngagementPolicy.from_config({}).coverage_endpoint_check_share, 0.05)
        self.assertEqual(EngagementPolicy.from_config(
            {"engagement": {"coverage_endpoint_check_share": 0}}).coverage_endpoint_check_share, 0.0)
        for bad in (True, -0.1, 1.5):
            with self.subTest(value=bad), self.assertRaises(ValueError):
                EngagementPolicy.from_config({"engagement": {"coverage_endpoint_check_share": bad}})


def _seeded(captures):
    """Stand-in for build_engagement: the endpoints of `captures` (path, kwargs)
    reached by both roles, with each capture recorded as a request template."""
    def build(base_url, roles, **kw):
        engagement_builder.register_role_sessions(kw.get("run_context"), base_url, roles)
        state = engagement.EngagementState(host="127.0.0.1")
        exchanges = [_exchange(path, base=base_url, **kwargs) for path, kwargs in captures]
        keys = {(ex.method, normalize_path(ex.url)) for ex in exchanges}
        state.ingest_role_crawl({"endpoints": [
            {"method": m, "path": p, "by_role": {r.role: 200 for r in roles},
             "reachable_roles": [r.role for r in roles], "object_scoped": "{id}" in p}
            for m, p in sorted(keys)], "idor_findings": []})
        for r in roles:
            state.ingest_identity(f"rolecrawl:{r.role}", r.role, source="seed")
        for ex in exchanges:
            state.record_template(ex.url, ex.method, ex)
        return state, SimpleNamespace(auth_bypass_candidates=[], idor_candidates=[], idor_findings=[],
                                      captured=[], errors=[], sensitive_file_hits=[], endpoints=[])
    return build


class DriveCallerTests(_EngagementCallerBase, unittest.TestCase):
    """investigate_engagement with the coverage drive on and the worklist stubbed
    out (its legs would cover the drive's cases first); the legs dispatched DURING
    the drive are recorded."""

    def _investigate(self, captures, *, engagement_cfg=None, leg_seconds=0.0, extra=()):
        target = self._target()
        calls = {"cross_identity": [], "command_injection": []}
        in_drive = {"on": False}
        real_drive = coverage_tracker.build_coverage_driven

        async def drive(*args, **kwargs):
            in_drive["on"] = True
            try:
                return await real_drive(*args, **kwargs)
            finally:
                in_drive["on"] = False

        def recorder(name):
            async def validate(self, finding, exchange, *args, **kwargs):
                if in_drive["on"]:
                    calls[name].append((exchange.url, exchange.request_headers.get("Authorization", "")))
                    if leg_seconds:
                        await asyncio.sleep(leg_seconds)
                return ValidationResult(name, "not_confirmed", "idor", summary="recorded")
            return validate

        def drive_config(*, mutating):
            cfg = _config(mutating=mutating)
            cfg["engagement"]["coverage_drive_legs"] = True
            cfg["engagement"].update(engagement_cfg or {})
            return cfg
        async def no_worklist(*args, **kwargs):
            return []   # the worklist's own legs would cover the drive's cases first
        patches = [patch("harness.engagement_builder.build_engagement", side_effect=_seeded(captures)),
                   patch("harness.worklist_investigator.investigate_worklist", no_worklist),
                   patch("harness.coverage_tracker.build_coverage_driven", drive),
                   patch("harness.validators.cross_identity_validator.CrossIdentityValidator.validate",
                         new=recorder("cross_identity")),
                   patch("harness.validators.command_injection_validator.CommandInjectionValidator.validate",
                         new=recorder("command_injection")), *extra]
        with patch("harness.test_engagement_transport_callers._config", drive_config):
            result, _rc, _model = self._run(target, max_requests=800, roles=list(_ROLES),
                                            extra_patches=patches)
        return result, calls

    @staticmethod
    def alice_urls(calls, name, fragment):
        return {url for url, auth in calls[name] if auth == "Bearer alice-token" and fragment in url}

    @staticmethod
    def cell(result, identity, endpoint, check_id):
        return next(c for c in result["coverage"]["phase_ledger"]["cells"]
                    if c["identity"] == identity and c["endpoint"] == endpoint and c["check"] == check_id)

    def test_the_drive_replays_a_repeated_capture_once(self):
        result, calls = self._investigate([(f"/api/items/7?nonce={n}", {}) for n in _NONCES[:4]])
        self.assertEqual(len(self.alice_urls(calls, "cross_identity", "/api/items/7")), 1, calls)
        self.assertEqual(result["coverage"]["replay_merge"]["endpoints"], ["GET /api/items/{id}"])

    def test_control_without_the_merge_the_drive_replays_every_capture(self):
        result, calls = self._investigate(
            [(f"/api/items/7?nonce={n}", {}) for n in _NONCES[:4]],
            extra=[patch("harness.replay_dedupe.distinct_replays", lambda variants, **kw: list(variants))])
        self.assertEqual(len(self.alice_urls(calls, "cross_identity", "/api/items/7")), 4, calls)
        self.assertNotIn("replay_merge", result["coverage"])

    def test_the_drive_still_replays_each_object_id(self):
        _result, calls = self._investigate(
            [(f"/api/items/{i}?nonce={n}", {}) for i, n in zip((7, 8, 9), _NONCES)])
        self.assertEqual(len(self.alice_urls(calls, "cross_identity", "/api/items/")), 3, calls)

    def test_a_polling_transport_gets_no_injection_leg_and_one_replay(self):
        poll = [(f"/rt/?EIO=4&transport=polling&t=P{n}&sid={s}", {"ctype": "text/plain", "response": "2"})
                for n, s in zip(("a1", "b2", "c3"), ("s1AbCdEfGhIj", "s2KlMnOpQrSt", "s3UvWxYzAbCd"))]
        result, calls = self._investigate(poll + [("/api/items/list?q=lamp", {})])
        self.assertEqual(self.alice_urls(calls, "command_injection", "/rt/"), set(), calls)
        disposition = next(d for d in result["coverage"]["capability_dispositions"]
                           if d["identity"] == ALICE_ID and d["endpoint"] == "GET /rt"
                           and d["check"] == "WSTG-INJT-12")
        self.assertEqual((disposition["status"], disposition["reason_code"]),
                         ("unsupported", "protocol_inapplicable"))
        # Control: an ordinary query parameter still gets the leg.
        self.assertTrue(self.alice_urls(calls, "command_injection", "/api/items/list"), calls)
        self.assertLessEqual(len(self.alice_urls(calls, "cross_identity", "/rt/")), 1, calls)

    def test_a_check_that_used_its_share_on_an_endpoint_stops_replaying_there(self):
        captures = [(f"/api/items/{i}", {}) for i in (7, 8, 9)]
        result, calls = self._investigate(
            captures, leg_seconds=0.4,
            engagement_cfg={"coverage_drive_seconds": 120, "coverage_endpoint_check_share": 0.0025})
        capped = {(c["endpoint"], c["check"], c["identity"]): c
                  for c in result["coverage"]["endpoint_check_time_capped"]}
        entry = capped[("GET /api/items/{id}", "WSTG-ATHZ-04", ALICE_ID)]
        self.assertEqual(entry["replays_not_run"], 2)
        self.assertGreaterEqual(entry["seconds_spent"], 0.3)
        self.assertTrue(self.cell(result, ALICE_ID, "GET /api/items/{id}", "WSTG-ATHZ-04")["detail"]
                        .startswith("endpoint_check_time_share:"))
        self.assertTrue(any("per-endpoint check time share" in e.get("error", "")
                            for e in result.get("errors", [])), result.get("errors"))

    def test_control_share_zero_replays_every_capture(self):
        captures = [(f"/api/items/{i}", {}) for i in (7, 8, 9)]
        result, calls = self._investigate(
            captures, leg_seconds=0.4,
            engagement_cfg={"coverage_drive_seconds": 120, "coverage_endpoint_check_share": 0})
        self.assertNotIn("endpoint_check_time_capped", result["coverage"])
        self.assertEqual(len(self.alice_urls(calls, "cross_identity", "/api/items/")), 3, calls)


if __name__ == "__main__":
    unittest.main()
