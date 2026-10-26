"""Captured variants survive graph storage and reach the worklist caller."""
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

from harness.engagement import EngagementState
from harness.models import HttpExchange
from harness.role_crawl import RoleSession
from harness.worklist_investigator import investigate_worklist


class CapturedVariantCallerTests(unittest.IsolatedAsyncioTestCase):
    async def exercise(self, *, drop=False, invalid=False):
        state = EngagementState('shop.test')
        roles = [RoleSession('user', {'Authorization': 'Bearer a'}, name='alice'),
                 RoleSession('user', {'Authorization': 'Bearer b'}, name='bob')]
        observations = [
            HttpExchange(url='http://shop.test:3002/api/items/42?q=one', method='GET',
                         request_headers=roles[0].headers, response_status=200, response_body='alice'),
            HttpExchange(url='http://shop.test:3002/api/items/43?q=two', method='GET',
                         request_headers=roles[1].headers, response_status=200, response_body='bob'),
            HttpExchange(url='http://shop.test:3002/api/search', method='POST',
                         request_headers={**roles[0].headers, 'Content-Type': 'application/json'},
                         request_body='{"q":"first"}', response_status=200, response_body='json'),
            HttpExchange(url='http://shop.test:3002/api/search', method='POST',
                         request_headers={**roles[1].headers, 'Content-Type': 'application/x-www-form-urlencoded'},
                         request_body='q=second', response_status=200, response_body='form'),
        ]
        if invalid:
            observations = [observations[2].model_copy(update={'request_body': ''}),
                            observations[0].model_copy(update={'url': 'http://shop.test:3001/foreign'}),
                            observations[1].model_copy(update={'request_headers': {'Authorization': 'Bearer foreign'}})]
        for ex in observations:
            state.record_template(ex.url, ex.method, ex)
            ep = state._ep(ex.method, __import__('harness.engagement', fromlist=['normalize_path']).normalize_path(ex.url))
            ep.reachable_roles = ['user']
        # The serialized snapshot is the persistence boundary; merge must retain
        # distinct equal-richness captures instead of choosing a URL winner.
        from harness import store
        from harness.engagement import persist_surface
        with tempfile.TemporaryDirectory() as temp, patch.object(store, '_DB_PATH', Path(temp) / 'state.db'):
            persist_surface(state)
            restored = EngagementState.from_dict(store.load_engagement(state.host))
        merged = EngagementState('shop.test')
        merged.merge_from(restored)
        if drop:
            for ep in merged.endpoints.values():
                ep.capture_variants = ep.capture_variants[:1]
        sent = []
        async def deterministic(node, ex):
            sent.append((ex.url, ex.request_headers.get('Authorization'), ex.request_body,
                         ex.response_body, ex.request_headers.get('Content-Type')))
            return []
        async def probe(*args):
            return {}
        summary = {}
        await investigate_worklist(probe, merged, 'http://shop.test:3002', roles,
                                   max_nodes=0, precondition_fn=deterministic,
                                   max_precondition_legs=20, summary_out=summary)
        return sent, summary

    async def test_distinct_shapes_and_principals_survive_reload_and_execute(self):
        sent, summary = await self.exercise()
        self.assertEqual(len(sent), 4)
        self.assertIn(('http://shop.test:3002/api/search', 'Bearer a', '{"q":"first"}',
                       'json', 'application/json'), sent)
        self.assertIn(('http://shop.test:3002/api/search', 'Bearer b', 'q=second',
                       'form', 'application/x-www-form-urlencoded'), sent)
        self.assertTrue(any('43?q=two' in row[0] and row[1] == 'Bearer b' for row in sent))
        self.assertNotIn('missing_template', summary['skipped_by_reason'])

    async def test_missing_body_foreign_identity_and_adjacent_port_do_not_execute(self):
        sent, summary = await self.exercise(invalid=True)
        self.assertEqual(sent, [])
        self.assertEqual(set(summary['skipped_by_reason']),
                         {'missing_body', 'missing_principal', 'scope_rejected'})
        self.assertTrue(all(row['next_action'] for row in summary['skipped']))

    async def test_dropped_variant_defect_is_detected(self):
        sent, _ = await self.exercise(drop=True)
        self.assertLess(len(sent), 4)
