"""P2-1: BusinessContextAgent + Application Semantic Model tests.

Covers every acceptance criterion in IMPROVEMENT_BACKLOG.md's P2-1:

  1. ASM BUILD over a mini-shop fixture (browse -> cart -> checkout -> admin):
     expected roles + privilege order, the commerce workflow ordered correctly,
     price/role flagged client-trusted, and >= 1 ranked chaining hypothesis
     linking an object weakness to a sensitive sink.
  2. LOOP INTEGRATION: with the ASM applied the worklist re-ranks business-
     critical endpoints above generic ones; without it the ranking is unchanged
     (the negative control), asserted both at the EngagementState level and
     through the production caller seam (Orchestrator._apply_business_context).
  3. SAFETY: the agent NEVER sets confirmed=True, NEVER emits a validator-ready
     URL/command, and produces ZERO live sends when its flag is off.
  4. ANONYMIZATION: no raw body/value/id leaves the host by default -- only
     method/path-template/param-NAMES survive the projection.
  5. LEDGER: each chaining hypothesis is reconstructable to its originating
     hypothesis id + the (structure-only) evidence it rests on.

All deterministic and offline -- no live model, no network.
"""
import inspect
import types
import unittest
from pathlib import Path

import yaml

from harness import engagement
from harness import evidence_ledger
from harness import orchestrator_chain
from harness import business_context_agent
from harness.business_context_agent import BusinessContextAgent
from harness.application_semantic_model import (
    ApplicationSemanticModel, ChainingHypothesis, endpoint_key,
)
from harness.models import HttpExchange

_HARNESS = Path(__file__).resolve().parent


def _mini_shop_state() -> engagement.EngagementState:
    """A minimal e-commerce surface: browse -> cart -> checkout -> pay, plus an
    order object addressed by id and an admin user-management area. Templates
    carry parameter NAMES (values are irrelevant to the deterministic model)."""
    st = engagement.EngagementState(host="shop.test")

    def _ep(method, path, *, template=None, object_scoped=False, roles=None):
        ep = st._ep(method, path)
        if template is not None:
            ep.template = template
        ep.object_scoped = object_scoped
        ep.reachable_roles = list(roles or [])
        return ep

    _ep("GET", "/products", roles=["anonymous", "user"])
    _ep("GET", "/products/{id}", object_scoped=True, roles=["anonymous", "user"])
    _ep("POST", "/cart",
        template={"method": "POST", "query": "", "content_type": "application/json",
                  "body": '{"product_id": 1, "quantity": 2}', "object_id": None},
        roles=["user"])
    _ep("GET", "/cart", roles=["user"])
    _ep("POST", "/checkout",
        template={"method": "POST", "query": "", "content_type": "application/json",
                  "body": '{"price": 100, "quantity": 1, "coupon": "X"}', "object_id": None},
        roles=["user"])
    _ep("GET", "/orders/{id}", object_scoped=True, roles=["user"])
    _ep("POST", "/payment",
        template={"method": "POST", "query": "", "content_type": "application/json",
                  "body": '{"amount": 100, "card_token": "t"}', "object_id": None},
        roles=["user"])
    _ep("GET", "/admin/users", roles=["admin"])
    _ep("POST", "/admin/users/{id}",
        template={"method": "POST", "query": "", "content_type": "application/json",
                  "body": '{"role": "user", "is_admin": false}', "object_id": None},
        roles=["admin"])
    return st


class AsmBuildTests(unittest.TestCase):
    """Acceptance criterion 1: the agent emits the expected ASM for the fixture."""

    def setUp(self):
        evidence_ledger.reset_default_ledger()
        self.state = _mini_shop_state()
        self.asm = BusinessContextAgent().build_model(
            host="shop.test", surface=list(self.state.endpoints.values()),
            roles=["anonymous", "user", "admin"])

    def test_roles_inferred_with_privilege_order(self):
        by_name = {r.name: r for r in self.asm.roles}
        self.assertEqual(set(by_name), {"anonymous", "user", "admin"})
        self.assertLess(by_name["anonymous"].privilege_rank, by_name["user"].privilege_rank)
        self.assertLess(by_name["user"].privilege_rank, by_name["admin"].privilege_rank)

    def test_business_objects_include_order_object_scoped(self):
        objs = {o.name: o for o in self.asm.business_objects}
        self.assertIn("order", objs)
        self.assertTrue(objs["order"].object_scoped)

    def test_checkout_workflow_ordered_correctly(self):
        wfs = self.asm.workflows
        self.assertTrue(wfs, "no workflow inferred for the mini shop")
        wf = wfs[0]
        # cart must come before checkout, which must come before payment/order.
        def _first(label):
            return next((i for i, s in enumerate(wf.stages) if s == label), None)
        i_cart, i_checkout, i_payment = _first("cart"), _first("checkout"), _first("payment")
        self.assertIsNotNone(i_cart)
        self.assertIsNotNone(i_checkout)
        self.assertLess(i_cart, i_checkout)
        if i_payment is not None:
            self.assertLess(i_checkout, i_payment)

    def test_price_and_role_flagged_client_trusted(self):
        by_param = {v.param: v.kind for v in self.asm.value_flows}
        self.assertEqual(by_param.get("price"), "price")
        self.assertEqual(by_param.get("role"), "role")
        self.assertEqual(by_param.get("is_admin"), "role")

    def test_ranked_hypothesis_links_object_weakness_to_sink(self):
        # >= 1 hypothesis whose source is an object weakness and whose target is
        # a sensitive sink, carrying an idor class and the object's endpoint.
        linking = [h for h in self.asm.chaining_hypotheses
                   if "idor" in h.classes and "sink" in h.target]
        self.assertTrue(linking, "no object-weakness -> sink hypothesis was proposed")
        order_hyp = [h for h in linking
                     if any("/orders/{id}" in e for e in h.endpoints)
                     and any("payment" in e or "/payment" in e for e in h.endpoints)]
        self.assertTrue(order_hyp, "expected an IDOR-on-order -> payment-sink hypothesis")
        self.assertGreater(order_hyp[0].rank, 0.0)
        # hypotheses come back ranked (descending)
        ranks = [h.rank for h in self.asm.chaining_hypotheses]
        self.assertEqual(ranks, sorted(ranks, reverse=True))


class WorklistReRankTests(unittest.TestCase):
    """Acceptance criterion 2 (EngagementState level): applying the ASM lifts a
    business-critical endpoint above a generic one; NOT applying it leaves the
    ranking byte-for-byte identical (the negative control)."""

    def _two_endpoint_state(self):
        st = engagement.EngagementState(host="shop.test")
        chk = st._ep("POST", "/checkout")
        chk.template = {"method": "POST", "query": "", "content_type": "application/json",
                        "body": '{"price": 10}', "object_id": None}
        st._ep("GET", "/about")
        return st

    def test_absent_asm_leaves_ranking_unchanged(self):
        # Negative control: no apply_semantic_model call -> no business_score ->
        # fused_score identical to a state that never heard of the ASM.
        st = self._two_endpoint_state()
        for ep in st.endpoints.values():
            self.assertIsNone(ep.business_score)
        baseline = {e["path"]: e["score"] for e in st.worklist(50)}

        st2 = self._two_endpoint_state()
        again = {e["path"]: e["score"] for e in st2.worklist(50)}
        self.assertEqual(baseline, again)

    def test_applied_asm_reranks_business_endpoint_above_generic(self):
        st = self._two_endpoint_state()
        before = {e["path"]: e["score"] for e in st.worklist(50)}

        asm = BusinessContextAgent().build_model(
            host="shop.test", surface=list(st.endpoints.values()))
        scored = st.apply_semantic_model(asm)
        self.assertGreaterEqual(scored, 1)

        after = {e["path"]: e for e in st.worklist(50)}
        # /checkout got a positive business score and its total score rose.
        self.assertGreater(after["/checkout"]["business_score"], 0.0)
        self.assertGreater(after["/checkout"]["score"], before["/checkout"])
        # /about carries no business signal -> its score is unchanged.
        self.assertEqual(after["/about"]["business_score"], 0.0)
        self.assertEqual(after["/about"]["score"], before["/about"])
        # and the business endpoint now outranks the generic one.
        self.assertGreater(after["/checkout"]["score"], after["/about"]["score"])

    def test_applied_asm_records_hypotheses_as_blocked_proposals(self):
        st = _mini_shop_state()
        asm = BusinessContextAgent().build_model(
            host="shop.test", surface=list(st.endpoints.values()),
            roles=["anonymous", "user", "admin"])
        st.apply_semantic_model(asm)
        blocked = st.blocked()
        proposals = [t for t in blocked if t.get("kind") == "chain-hypothesis"]
        self.assertTrue(proposals, "chaining hypotheses were not surfaced as blocked proposals")
        for t in proposals:
            # a proposal is BLOCKED on operator review -- never auto-runnable.
            self.assertFalse(t.get("meta", {}).get("auto_runnable", False))
            self.assertTrue(t.get("meta", {}).get("proposed_only"))


class CallerSeamTests(unittest.TestCase):
    """Acceptance criterion 2 (production caller): Orchestrator._apply_business_context
    is the seam investigate_engagement actually calls, gated on the flag."""

    class _Orch(orchestrator_chain.ChainMixin):
        def __init__(self, enabled, cloud_reasoning=False):
            self.business_context_enabled = enabled
            self.config = {"business_context": {"enabled": enabled}}
            self.coordinator = types.SimpleNamespace(cloud_reasoning=cloud_reasoning)

    def test_flag_on_builds_and_applies_asm(self):
        st = _mini_shop_state()
        orch = self._Orch(enabled=True)
        asm = orch._apply_business_context(st, captured=None, roles=["user", "admin"])
        self.assertIsNotNone(asm)
        self.assertTrue(any(ep.business_score for ep in st.endpoints.values()),
                        "flag-on pass did not re-rank any endpoint")

    def test_flag_off_is_a_noop_negative_control(self):
        st = _mini_shop_state()
        orch = self._Orch(enabled=False)
        asm = orch._apply_business_context(st, captured=None, roles=["user", "admin"])
        self.assertIsNone(asm)
        # nothing was scored, and no proposal task was added -> zero effect.
        for ep in st.endpoints.values():
            self.assertIsNone(ep.business_score)
        self.assertEqual([t for t in st.blocked() if t.get("kind") == "chain-hypothesis"], [])

    def test_investigate_engagement_calls_the_seam_behind_the_flag(self):
        # Wiring proof (the method is expensive to drive end to end -- it needs a
        # live Ollama/transport stack -- so assert the production call site in
        # source, the same pattern test_engagement_policy uses for the driver
        # gate). This is what keeps the seam from being a dead helper.
        src = inspect.getsource(orchestrator_chain.ChainMixin.investigate_engagement)
        self.assertIn("self._apply_business_context(", src)
        self.assertIn("application_semantic_model", src)
        gate_src = inspect.getsource(orchestrator_chain.ChainMixin._apply_business_context)
        self.assertIn("business_context_enabled", gate_src)


class SafetyControlTests(unittest.TestCase):
    """Acceptance criterion 3: the ASM never confirms, never hands a validator a
    send target, and does zero live sends."""

    def setUp(self):
        self.st = _mini_shop_state()
        self.asm = BusinessContextAgent().build_model(
            host="shop.test", surface=list(self.st.endpoints.values()),
            roles=["anonymous", "user", "admin"])

    def test_no_confirmed_true_anywhere_in_the_model(self):
        # The serialized model must not assert any confirmation.
        blob = repr(self.asm.to_dict())
        self.assertNotIn("'confirmed': True", blob)
        for hyp in self.asm.chaining_hypotheses:
            self.assertFalse(getattr(hyp, "confirmed", False))

    def test_endpoints_are_templates_not_validator_ready_urls(self):
        # Every endpoint reference is a "METHOD /path" key (path template, ids
        # collapsed), never a concrete scheme://host URL a validator could send.
        for hyp in self.asm.chaining_hypotheses:
            for e in hyp.endpoints:
                self.assertNotIn("://", e)
                self.assertRegex(e, r"^[A-Z]+ /")
            # no field that reads as a command/url a validator would consume
            d = ChainingHypothesis.__dataclass_fields__
            self.assertNotIn("url", d)
            self.assertNotIn("command", d)

    def test_build_is_offline_no_transport_dependency(self):
        # The agent takes no run_context/transport and needs none: building the
        # model over the fixture completes with no network object in play, so it
        # cannot send. (Zero live sends when active flags are off.)
        agent = BusinessContextAgent()
        self.assertFalse(hasattr(agent, "run_context"))
        self.assertFalse(hasattr(agent, "transport"))
        params = inspect.signature(agent.build_model).parameters
        self.assertNotIn("run_context", params)
        # re-run to prove determinism + no external state needed
        asm2 = agent.build_model(host="shop.test",
                                 surface=list(self.st.endpoints.values()),
                                 roles=["anonymous", "user", "admin"])
        self.assertEqual(asm2.summary()["chaining_hypotheses"],
                         self.asm.summary()["chaining_hypotheses"])


class AnonymizationTests(unittest.TestCase):
    """Acceptance criterion 4: no raw body/value/id leaves the host by default --
    only method / path template / parameter NAMES survive the projection."""

    def _exchange_with_secrets(self):
        return HttpExchange(
            url="http://shop.test/orders/12345?token=SECRET_SESSION_VALUE",
            method="GET",
            request_headers={"Authorization": "Bearer SECRET_BEARER"},
            request_body='{"price": 999, "card_number": "4111111111111111"}',
            response_status=200,
            response_headers={"Content-Type": "application/json"},
            response_body='{"card_number": "4111111111111111", "cvv": "123"}',
        )

    def test_projection_keeps_names_drops_values_and_ids(self):
        agent = BusinessContextAgent()
        projected = agent.project_surface([], [self._exchange_with_secrets()],
                                          cloud_reasoning=False)
        self.assertTrue(projected)
        pe = projected[0]
        # the real id was collapsed to a template segment
        self.assertIn("/orders/{id}", pe.path)
        self.assertNotIn("12345", pe.path)
        # parameter NAMES survive, VALUES do not
        self.assertIn("token", pe.param_names)
        self.assertIn("price", pe.param_names)
        self.assertIn("card_number", pe.param_names)
        blob = f"{pe.path}|{pe.key}|{sorted(pe.param_names)}"
        for secret in ("SECRET_SESSION_VALUE", "SECRET_BEARER", "4111111111111111",
                       "999", "123"):
            self.assertNotIn(secret, blob)

    def test_built_model_default_is_not_from_raw_and_leaks_no_values(self):
        agent = BusinessContextAgent()
        asm = agent.build_model(host="shop.test", surface=[],
                                exchanges=[self._exchange_with_secrets()])
        self.assertFalse(asm.built_from_raw)
        blob = repr(asm.to_dict())
        for secret in ("SECRET_SESSION_VALUE", "SECRET_BEARER", "4111111111111111"):
            self.assertNotIn(secret, blob)

    def test_cloud_reasoning_flag_recorded_when_explicitly_enabled(self):
        agent = BusinessContextAgent()
        asm = agent.build_model(host="shop.test", surface=[], cloud_reasoning=True)
        self.assertTrue(asm.built_from_raw)


class LedgerTests(unittest.TestCase):
    """Acceptance criterion 5: each hypothesis is reconstructable to its origin
    (id) and the structure-only evidence it rests on."""

    def test_each_hypothesis_emits_a_reconstructable_ledger_event(self):
        led = evidence_ledger.reset_default_ledger()
        st = _mini_shop_state()
        asm = BusinessContextAgent().build_model(
            host="shop.test", surface=list(st.endpoints.values()),
            roles=["anonymous", "user", "admin"])
        self.assertTrue(asm.chaining_hypotheses)
        for hyp in asm.chaining_hypotheses:
            recon = led.reconstruct(hyp.id)
            # the "why we suspect" question is answered from the hypothesis event
            self.assertTrue(recon["why_tested"], f"no ledger origin for {hyp.id}")
            events = led.events_for(hyp.id)
            self.assertTrue(events)
            data = events[0].data
            self.assertEqual(data["kind"], "business_context_chain_hypothesis")
            self.assertEqual(data["source"], hyp.source)
            self.assertEqual(data["target"], hyp.target)
            self.assertEqual(data["endpoints"], hyp.endpoints)
            self.assertTrue(data["evidence"])
            self.assertFalse(data["confirmed"])

    def test_hypothesis_id_is_stable(self):
        a = ChainingHypothesis.make_id("h", "IDOR on order", "payment sink")
        b = ChainingHypothesis.make_id("h", "IDOR on order", "payment sink")
        c = ChainingHypothesis.make_id("h", "IDOR on user", "payment sink")
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)
        self.assertTrue(a.startswith("bch:"))


class ConfigDefaultTests(unittest.TestCase):
    """P2-1 ships OFF -- a local guard beside the shared SafeDefaultGuardTests."""

    def test_committed_config_has_business_context_disabled(self):
        with open(_HARNESS / "config.yaml") as f:
            cfg = yaml.safe_load(f) or {}
        self.assertIs(cfg.get("business_context", {}).get("enabled", False), False)
        self.assertFalse(business_context_agent.enabled(cfg))

    def test_orchestrator_reads_the_flag(self):
        from harness.orchestrator import Orchestrator
        init_src = inspect.getsource(Orchestrator.__init__)
        self.assertIn("self.business_context_enabled", init_src)
        self.assertIn('config.get("business_context", {})', init_src)


if __name__ == "__main__":
    unittest.main()
