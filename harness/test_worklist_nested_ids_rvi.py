"""Code review 02, batch RV-I (I06/I07): the worklist replays every captured path id, not just the leaf (R22).

Drives the production caller the way the reviewer's boundary_checks.py did, with
the reviewer's control as the negative control. Nothing leaves the machine:
requests are answered by a patched ``httpx.AsyncClient``.
"""
import asyncio
import unittest
from types import SimpleNamespace

from harness.engagement import EngagementState, template_from_exchange
from harness.test_default_history_caller import _exchange
from harness.worklist_investigator import _seed_exchange, investigate_worklist


class WorklistNestedIdTests(unittest.TestCase):
    """R22: each captured path parameter is preserved independently."""

    def _probed_urls(self, captured_path):
        ex = _exchange("http://shop.invalid" + captured_path)
        state = EngagementState(host="shop.invalid")
        state.record_template(ex.url, ex.method, ex)
        sent = []

        async def precondition(node, exchange):
            sent.append(exchange.url)
            return []

        async def probe(*args):
            raise AssertionError("agent must not run")

        asyncio.run(investigate_worklist(
            probe, state, "http://shop.invalid", [SimpleNamespace(role="anonymous", headers={})],
            precondition_fn=precondition, max_nodes=0))
        return sent

    def test_worklist_preserves_nested_captured_ids(self):
        self.assertEqual(self._probed_urls("/accounts/17/orders/42"),
                         ["http://shop.invalid/accounts/17/orders/42"])

    def test_three_levels_keep_every_id(self):
        self.assertEqual(self._probed_urls("/accounts/17/orders/42/items/7"),
                         ["http://shop.invalid/accounts/17/orders/42/items/7"])

    def test_worklist_single_id_control(self):
        self.assertEqual(self._probed_urls("/orders/42"), ["http://shop.invalid/orders/42"])

    def test_literal_segment_the_graph_does_not_collapse_is_not_mistaken_for_the_slot(self):
        # The dashed token is not an {id} slot; the leaf object_id must not be
        # copied over the real slot (/orders/{id}) as the old single-value fill did.
        self.assertEqual(self._probed_urls("/orders/42/items/deadbeef-1234-5678"),
                         ["http://shop.invalid/orders/42/items/deadbeef-1234-5678"])

    def test_seed_exchange_from_a_captured_node_template(self):
        # The shape the coverage-driven legs use (orchestrator_chain, helpers).
        ex = _exchange("http://shop.invalid/accounts/17/orders/42?expand=1")
        node = {"method": "GET", "path": "/accounts/{id}/orders/{id}",
                "template": template_from_exchange(ex)}
        seeded = _seed_exchange("http://shop.invalid", node, {}, "1")
        self.assertEqual(seeded.url, "http://shop.invalid/accounts/17/orders/42?expand=1")

    def test_node_without_a_template_still_uses_the_generic_fill(self):
        node = {"method": "GET", "path": "/accounts/{id}/orders/{id}"}
        self.assertEqual(_seed_exchange("http://shop.invalid", node, {}, "1").url,
                         "http://shop.invalid/accounts/1/orders/1")

    def test_template_without_path_ids_keeps_previous_single_id_behaviour(self):
        # A template persisted before path_ids existed still replays as it did.
        node = {"method": "GET", "path": "/orders/{id}",
                "template": {"method": "GET", "body": "", "query": "", "content_type": "",
                             "object_id": "42"}}
        self.assertEqual(_seed_exchange("http://shop.invalid", node, {}, "1").url,
                         "http://shop.invalid/orders/42")

    def test_captured_template_records_every_path_id_in_order(self):
        tmpl = template_from_exchange(_exchange("http://shop.invalid/accounts/17/orders/42"))
        self.assertEqual(tmpl["path_ids"], ["17", "42"])
        self.assertEqual(tmpl["object_id"], "42")   # the leaf, unchanged for old readers


if __name__ == "__main__":
    unittest.main()
