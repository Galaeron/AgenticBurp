"""AR-09 (batch 09): the iterative worker offers only supported, ready mechanisms
and accounts for every proposal, through the production run_active_probe caller."""
import json
import unittest
from unittest.mock import patch

from harness.ollama_client import OllamaInvalidJSONError
from harness.test_experiment_cycle import _CycleCase
from harness.test_iterative_agent import _ScriptedOllama
from harness import test_iterative_experiments as _caller

VALID = _caller.VALID

DEPENDENT = dict(VALID, hypothesis='bch:comment-idor')
_scripted_chat = _ScriptedOllama.chat_json


async def _chat_or_raise(self, *args, **kwargs):
    """A scripted entry that is an exception is raised, as the client would.
    Every system prompt is kept too, so a test can read what was offered."""
    self.__dict__.setdefault('systems', []).append(kwargs.get('system_prompt', args[1] if len(args) > 1 else ''))
    if self._actions and isinstance(self._actions[0], Exception):
        self.calls += 1
        self.prompts.append(kwargs.get('user_prompt', args[2] if len(args) > 2 else ''))
        raise self._actions.pop(0)
    return await _scripted_chat(self, *args, **kwargs)


def _mechanisms(prompt, label):
    line = next((l for l in prompt.splitlines() if l.startswith(f'MECHANISMS {label}: ')), None)
    return None if line is None else json.loads(line.split(': ', 1)[1])


def _mutate(value):
    return {'action': 'mutate', 'location': 'body', 'param': 'title', 'value': value}


class WorkerMechanismTests(_CycleCase):
    probe = _caller.IterativeExperimentCallerTests.probe
    assert_completed = _caller.IterativeExperimentCallerTests.assert_completed

    def run_probe(self, actions, **options):
        with patch.object(_ScriptedOllama, 'chat_json', _chat_or_raise):
            return self.probe(actions, **options)

    @staticmethod
    def diagnostics(bundle):
        return bundle.result['iterative_result']['diagnostics']

    def test_prompt_offers_only_ready_mechanisms_and_refreshes_after_setup(self):
        bundle = self.run_probe([VALID, DEPENDENT], comments=True)
        first, second = bundle.model.prompts[0], bundle.model.prompts[1]
        self.assertEqual([m['hypothesis'] for m in _mechanisms(first, 'READY')], ['bch:note-idor'])
        unavailable = {m['hypothesis']: m for m in _mechanisms(first, 'UNAVAILABLE')}
        self.assertIn('bch:comment-idor', unavailable)
        self.assertTrue(unavailable['bch:comment-idor']['reason'])
        self.assertIn('bch:comment-idor', [m['hypothesis'] for m in _mechanisms(second, 'READY')])
        self.assert_completed(bundle, 2)

    def test_unplugged_readiness_view_is_detected_by_the_offer_assertion(self):
        from harness.orchestrator import Orchestrator
        with patch.object(Orchestrator, '_experiment_catalog', side_effect=RuntimeError('unplugged')):
            bundle = self.run_probe([VALID])
        self.assertIsNone(_mechanisms(bundle.model.prompts[0], 'READY'))
        self.assert_completed(bundle)  # the handoff itself stays authoritative

    def test_unavailable_engagements_offer_no_mechanism(self):
        for options in ({'enabled': False}, {'declaration': False}, {'expired': True}, {'context': False}):
            with self.subTest(options=options):
                bundle = self.run_probe([], **options)
                prompt = bundle.model.systems[0] + '\n' + bundle.model.prompts[0]
                self.assertFalse(_mechanisms(prompt, 'READY'))
                self.assertNotIn('"action": "experiment"', prompt)
                self.assertEqual(bundle.requests, [])

    def test_setup_then_dependent_records_useful_actions_and_evidence(self):
        bundle = self.run_probe([VALID, DEPENDENT], comments=True)
        self.assert_completed(bundle, 2)
        diag = self.diagnostics(bundle)
        self.assertEqual(diag['useful_unique_actions'], 2)
        self.assertTrue({p['proof_id'] for p in bundle.proofs} <= set(diag['evidence_attempt_ids']))
        self.assertEqual((diag['parse_errors'], diag['refusals'], diag['rejected_proposals']), (0, 0, 0))

    def test_parse_error_is_counted_and_the_run_continues(self):
        bundle = self.run_probe([OllamaInvalidJSONError('bad output SECRET_SENTINEL'), VALID])
        self.assert_completed(bundle)
        self.assertEqual(self.diagnostics(bundle)['parse_errors'], 1)
        self.assertNotEqual(bundle.result['iterative_result']['stop_reason'], 'error')
        self.assertNotIn('SECRET_SENTINEL', json.dumps(bundle.result))
        self.assertNotIn('SECRET_SENTINEL', '\n'.join(bundle.model.prompts))

    def test_refusal_only_from_the_explicit_verdict(self):
        bundle = self.run_probe([{'action': 'stop', 'verdict': 'refused', 'thought': 'declined'}])
        self.assertEqual(bundle.result['iterative_result']['stop_reason'], 'refused')
        self.assertEqual(self.diagnostics(bundle)['refusals'], 1)
        bundle = self.run_probe([{}])
        self.assertEqual(self.diagnostics(bundle)['refusals'], 0)
        self.assertEqual(self.diagnostics(bundle)['parse_errors'], 1)
        from harness.iterative_agent import IterativeAgent

        async def failed(*args, **kwargs):
            return None, 'request failed: connection reset'
        with patch.object(IterativeAgent, '_execute', failed):
            bundle = self.run_probe([_mutate('x')])
        diag = self.diagnostics(bundle)
        self.assertEqual((diag['refusals'], diag['blocked_attempts']), (0, 1))
        self.assertNotEqual(bundle.result['iterative_result']['stop_reason'], 'refused')

    def test_duplicate_cites_stable_attempt_id_and_new_action_still_sends(self):
        bundle = self.run_probe([_mutate('one'), _mutate('one'), _mutate('two')])
        sent = [r for r in bundle.requests if r[0] == 'POST']
        self.assertEqual(len(sent), 2)
        transcript = bundle.result['iterative_result']['transcript']
        first_id = transcript[0]['attempt_id']
        self.assertTrue(first_id.startswith('req:'))
        self.assertIn(first_id, bundle.model.prompts[2])
        self.assertEqual(transcript[1]['attempt_id'], first_id)
        self.assertNotEqual(transcript[2]['attempt_id'], first_id)
        diag = self.diagnostics(bundle)
        self.assertEqual((diag['duplicate_proposals'], diag['useful_unique_actions']), (1, 2))

    def test_unknown_action_and_out_of_scope_request_send_nothing(self):
        bundle = self.run_probe([{'action': 'delete_everything'}])
        self.assertEqual(bundle.requests, [])
        self.assertEqual(self.diagnostics(bundle)['rejected_proposals'], 1)
        bundle = self.run_probe([_mutate('x')], scope=False)
        self.assertEqual(bundle.requests, [])
        diag = self.diagnostics(bundle)
        self.assertEqual((diag['blocked_attempts'], diag['useful_unique_actions']), (1, 0))


if __name__ == '__main__':
    unittest.main()
