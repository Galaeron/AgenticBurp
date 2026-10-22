"""RV-T caller controls: declared entitlement, passive privacy and nested budgets."""
import contextlib
import unittest
from unittest.mock import patch
from harness import test_cross_identity_ownership_gate as ownership_fixture
from harness import test_run_engagement_run_bound as driver_fixture
from harness import test_external_lookup_privacy as privacy_fixture
from harness import test_sensitive_file_confirmation as file_fixture
from harness import config_schema, principals, ownership_declarations, engagement
from harness import orchestrator_chain
from harness.run_context import RunContext


class OwnershipDeclarationsCallerTests(ownership_fixture.OwnershipGateCallerTests, unittest.TestCase):
    def test_concurrent_targets_keep_opposing_declarations_isolated(self):
        import asyncio
        import httpx
        from harness.models import Finding, AgentReport, HttpExchange
        from harness.validators.cross_identity_validator import CrossIdentityValidator
        other = ownership_fixture._X2Fixture('vulnerable')
        self.addCleanup(other.close)
        cfg = ownership_fixture._config()
        cfg['authz'] = {'owners': {
            f'127.0.0.1:{self.fx.port}': [{'path': '/objects/7', 'owner': 'alice'}],
            f'127.0.0.1:{other.port}': [{'path': '/objects/7', 'public': True}]}}
        orch = ownership_fixture.Orchestrator(cfg)
        # Exercise the registered instance, which set_ownership mutates in place.
        original = orch.validator_registry._build_cross_identity()
        orch.validator_registry.validators = {'cross_identity': original}
        captures = []
        for target in (self.fx, other):
            url = target.url('/objects/7')
            response = httpx.get(url, headers={'Authorization': 'Bearer alice-token'})
            captures.append(HttpExchange(url=url, method='GET',
                request_headers={'Authorization': 'Bearer alice-token'}, response_status=200,
                response_headers={'Content-Type': 'application/json'}, response_body=response.text))
        real_validate = CrossIdentityValidator.validate
        async def go():
            barrier = asyncio.Event()
            arrived = 0
            async def interleave(validator, finding, exchange):
                nonlocal arrived
                arrived += 1
                if arrived == 2:
                    barrier.set()
                await asyncio.wait_for(barrier.wait(), timeout=5)
                return await real_validate(validator, finding, exchange)
            async def check(exchange):
                run = RunContext.create(allowed_hosts=['127.0.0.1'], config=cfg, max_requests=30,
                    gate_config={'active_enabled': True, 'allow_mutating_replay': False})
                origin = exchange.url.rsplit('/objects/', 1)[0]
                for name in ('alice', 'bob'):
                    run.sessions.register(name, name, {'Authorization': f'Bearer {name}-token'},
                                          allowed_origins=[origin], name=name)
                run.sessions.register('anonymous', 'anonymous', allowed_origins=[origin])
                finding = Finding(vulnerability_class='idor', confidence=0.6, summary='object read',
                    evidence='fixture', suggested_test='compare identities', basis='derived')
                async with run:
                    return await orch._validate_findings(exchange,
                        [AgentReport(agent='idor', model='fixture', findings=[finding])], run_context=run)
            with patch.object(CrossIdentityValidator, 'validate', interleave):
                return await asyncio.gather(*(check(exchange) for exchange in captures))
        private, public = asyncio.run(go())
        self.assertTrue(any(r.confirmed for r in private[0]))
        self.assertFalse(any(r.confirmed for r in public[0]))
        self.assertIsNone(original.ownership)

    def _configured(self, entries, *, path='/objects/7', host=None):
        cfg = ownership_fixture._config()
        cfg['authz'] = {'owners': {host or f'127.0.0.1:{self.fx.port}': entries}}
        with patch.object(ownership_fixture, '_config', return_value=cfg):
            return self._analyze(path, identities=(('alice', 'alice-token', 'user'), ('bob', 'bob-token', 'user')))

    def test_config_declaration_reaches_production_validator(self):
        response = self._configured([{'path': '/objects/7', 'owner': 'alice'}])
        self.assertTrue(any(r.confirmed for r in self._xid(response)))
        report = next(r for r in self._xid(response) if r.confirmed)
        self.assertIn('config authz.owners', report.evidence)
        self.assertIn('/objects/7', report.evidence)

    def test_authorized_shares_public_and_authenticated_never_confirm(self):
        for entry in ({'owner': 'alice', 'shared_with': ['bob']}, {'public': True}, {'authenticated': True}):
            with self.subTest(entry=entry):
                reports = self._xid(self._configured([dict(path='/objects/7', **entry)]))
                self.assertTrue(reports)
                self.assertFalse(any(r.confirmed for r in reports))
                self.assertEqual(reports[0].status, 'not_confirmed')

    def test_unknown_malformed_other_host_and_other_object_remain_leads(self):
        for entry, host in (({'path': '/objects/7', 'owner': 'missing'}, None),
                            ({'path': '/objects/7', 'public': 'true'}, None),
                            ({'path': '/objects/7', 'owner': 'alice'}, 'other.test'),
                            ({'path': '/objects/5', 'owner': 'alice'}, None)):
            with self.subTest(entry=entry, host=host):
                self._assert_lead(self._xid(self._configured([entry], host=host)))

    def test_exact_rule_overrides_broad_public_rule(self):
        response = self._configured([{'path': '/objects/**', 'public': True},
                                     {'path': 'GET /objects/7', 'owner': 'alice'}])
        self.assertTrue(any(r.confirmed for r in self._xid(response)))

    def test_disconnecting_loader_is_detected(self):
        with patch.object(ownership_fixture.Orchestrator, '_configure_ownership', return_value=None):
            response = self._configured([{'path': '/objects/7', 'owner': 'alice'}])
        self._assert_lead(self._xid(response))


class PassivePrivacyCallerTests(privacy_fixture._PrivacyTestBase, unittest.TestCase):
    def test_passive_profile_overrides_explicit_true(self):
        cfg = privacy_fixture._config(True)
        cfg['operating_profile'] = 'passive-only'
        orch, stub = privacy_fixture._build(cfg)
        out = self.analyze(orch, stub)
        self.assert_no_egress(out)
        self.assert_components_reached_the_lookups_stage(out)

    def test_removing_forced_off_knob_is_detected(self):
        cfg = privacy_fixture._config(True)
        cfg['operating_profile'] = 'passive-only'
        with patch.object(config_schema, '_PASSIVE_FORCE_OFF_KNOBS', tuple(
                k for k in config_schema._PASSIVE_FORCE_OFF_KNOBS if k != 'privacy.external_lookups')):
            orch, stub = privacy_fixture._build(cfg)
        out = self.analyze(orch, stub)
        self.assertTrue(out.recorder.requests)


class DriverCeilingCallerTests(driver_fixture.RunEngagementRunBoundTests, unittest.TestCase):
    def test_borrowed_driver_refuses_mutation_even_when_parent_allows_it(self):
        from harness.orchestrator import Orchestrator
        from harness.models import AnalysisResponse
        outcomes = []
        async def mutation(orch, exchange, **kwargs):
            outcomes.append(await kwargs['run_context'].executor().send(
                'POST', self.target.base + '/api/write', capability='analysis_probe', max_redirects=0))
            return AnalysisResponse(coordinator_model='fixture', dispatched_agents=[], agent_reports=[],
                                    summary='', test_plans=[])
        cfg = driver_fixture._config(runs_max=20)
        cfg['engagement']['driver_max_requests'] = 10
        parent = RunContext.create(allowed_hosts=['127.0.0.1'], config=cfg, max_requests=20,
            gate_config={'active_enabled': True, 'allow_mutating_replay': True})
        self._drive(cfg, enclosing=parent, scripted=False,
                    extra_patches=(patch.object(Orchestrator, '_analyze_inner', mutation),))
        self.assertTrue(outcomes)
        self.assertFalse(any(outcome.ok for outcome in outcomes))
        self.assertTrue(all(method == 'GET' for method, _ in self.target.requests))
        self.assertTrue(parent.gate.config.allow_mutating_replay)

    def test_driver_ceiling_includes_nested_analysis_sends(self):
        cfg = driver_fixture._config(runs_max=20)
        cfg['engagement']['driver_max_requests'] = 3
        result = self._drive(cfg)
        self.assertEqual(len(self.target.requests), 3)
        self.assertEqual(result['run']['driver_requests_used'], 3)
        self.assertTrue(self.target.probes())

    def test_driver_cannot_extend_parent_remaining_budget(self):
        cfg = driver_fixture._config(runs_max=20)
        cfg['engagement']['driver_max_requests'] = 9
        parent = RunContext.create(allowed_hosts=['127.0.0.1'], config=cfg, max_requests=4)
        parent.budget.reserve(2)
        self._drive(cfg, enclosing=parent)
        self.assertEqual(len(self.target.requests), 2)
        self.assertEqual(parent.budget.used, 4)

    def test_zero_driver_budget_sends_nothing(self):
        cfg = driver_fixture._config(runs_max=20)
        cfg['engagement']['driver_max_requests'] = 0
        self._drive(cfg)
        self.assertEqual(self.target.requests, [])

    def test_removing_child_budget_is_detected(self):
        @contextlib.asynccontextmanager
        async def unbounded(run, maximum):
            yield run
        cfg = driver_fixture._config(runs_max=20)
        cfg['engagement']['driver_max_requests'] = 3
        with patch.object(orchestrator_chain, '_driver_scope', unbounded):
            self._drive(cfg)
        self.assertGreater(len(self.target.requests), 3)


class OwnershipModelTests(unittest.TestCase):
    def test_malformed_engagement_owners_do_not_break_merge(self):
        state = engagement.EngagementState(host='app.test')
        other = engagement.EngagementState.from_dict({'host': 'app.test', 'owners': 42})
        state.merge_from(other)
        self.assertEqual(state.owners, [])

    def test_shares_only_and_tie_order(self):
        entries = [{'path': '/reports/*', 'shared_with': ['alice']},
                   {'path': '/reports/*', 'public': True}]
        ledger = ownership_declarations.load_ownership({'authz': {'owners': {'app.test': entries}}},
                                                       'https://app.test', [{'name': 'alice'}])
        ref = principals.declared_reference('https://app.test/reports/q3')
        self.assertEqual(ledger.authorization(principals.Principal('alice'), ref), principals.AuthzDecision.UNKNOWN)
        self.assertEqual(ledger.authorization(principals.Principal('bob'), ref), principals.AuthzDecision.UNKNOWN)
        ledger = ownership_declarations.load_ownership({'authz': {'owners': {'app.test': entries[:1]}}},
                                                       'https://app.test', [{'name': 'alice'}])
        self.assertEqual(ledger.authorization(principals.Principal('bob'), ref), principals.AuthzDecision.UNAUTHORIZED)

    def test_engagement_round_trip_and_loader(self):
        state = engagement.EngagementState(host='app.test')
        state.owners = [{'path': '/items/7', 'owner': 'alice'}]
        state = engagement.EngagementState.from_dict(state.to_dict())
        ledger = ownership_declarations.load_ownership({}, 'https://app.test', [{'name': 'alice'}], engagement_owners=state.owners)
        self.assertEqual(ledger.authorization(principals.Principal('bob'), principals.declared_reference('https://app.test/items/7')), principals.AuthzDecision.UNAUTHORIZED)
        self.assertEqual(ledger.authorization(principals.Principal('bob'), principals.declared_reference('https://app.test/items/8')), principals.AuthzDecision.UNKNOWN)

    def test_config_schema_reports_malformed_declarations(self):
        result = config_schema.validate_config({'authz': {'owners': {'app.test': [{'path': '/', 'public': 'true'}]}}})
        self.assertTrue(any('public must be a boolean' in w for w in result.warnings))


class SensitiveSeverityCallerTests(file_fixture.SensitiveFileConfirmationCallerTests, unittest.TestCase):
    def test_empty_credential_assignments_are_medium_real_value_is_high(self):
        empty = ('APP_NAME=fixture\nPASSWORD=\nAPI_KEY=   \nSECRET=""\n'
                 "TOKEN=''\nPRIVATE_KEY='   '\nACCESS_KEY=\" \t \"\n"
                 'DB_PASSWORD= # intentionally empty\nPUBLIC_URL=https://example.test/\n')
        for body, expected in ((empty, 'medium'), (empty + 'API_TOKEN=fixture-secret\n', 'high')):
            with self.subTest(expected=expected), patch.object(file_fixture, '_DOTENV', body):
                findings, _, records = self._investigate(catch_all=False)
            self.assertTrue(findings['/.env']['confirmed'])
            self.assertEqual(findings['/.env']['severity'], expected)
            record = next(r for r in records if r['path'] == '/.env')
            self.assertEqual(record['contains_credentials'], expected == 'high')
            self.assertNotIn('fixture-secret', findings['/.env']['evidence'])

    def test_served_candidates_are_low_and_redirect_is_informational(self):
        findings, _, _ = self._investigate(catch_all=False)
        self.assertEqual(findings['/.env']['severity'], 'high')
        self.assertEqual(findings['/.env.local']['severity'], 'info')
        self.assertEqual(findings['/.env.production']['severity'], 'low')
        self.assertEqual(findings['/.env.dev']['severity'], 'low')

    def test_restoring_old_severity_is_detected_through_caller(self):
        from harness import api_surface_discovery as asd
        real = asd.sensitive_file_finding
        def old_severity(record):
            finding = real(record)
            if not finding['confirmed']:
                finding['severity'] = 'medium' if record.get('outcome') in ('unknown_type', 'signature_mismatch') else 'low'
            return finding
        findings, _, _ = self._investigate(catch_all=False, extra_patches=(patch.object(asd, 'sensitive_file_finding', old_severity),))
        self.assertNotEqual(findings['/.env.local']['severity'], 'info')

    def test_class_table(self):
        from harness.api_surface_discovery import sensitive_file_finding
        for structure, credentials, expected in [('private_key', False, 'high'), ('dotenv', True, 'high'), ('dotenv', False, 'medium'), ('git_config', False, 'medium'), ('zip_archive', False, 'medium')]:
            result = sensitive_file_finding({'path': '/artifact', 'status': 200, 'confirmed': True, 'structure': structure, 'contains_credentials': credentials})
            self.assertEqual(result['severity'], expected)


from harness import test_principal_access_matrix as matrix_fixture


class EngagementOwnershipCallerTests(matrix_fixture.X2InvestigateEngagementTests, unittest.TestCase):
    def _declared_investigation(self, *, disconnect=False):
        from harness import engagement_builder
        from harness.orchestrator import Orchestrator
        real_build = engagement_builder.build_engagement
        async def declared_build(*args, **kwargs):
            state, crawl = await real_build(*args, **kwargs)
            state.owners = [{'path': '/api/invoices/*', 'owner': 'alice'},
                            {'path': '/api/announcements/**', 'authenticated': True}]
            return state, crawl
        faults = [lambda: patch.object(engagement_builder, 'build_engagement', declared_build)]
        if disconnect:
            faults.append(lambda: patch.object(Orchestrator, '_configure_ownership', return_value=None))
        return self._investigate(faults=faults)

    def test_engagement_list_reaches_chain_confirmation(self):
        result = self._declared_investigation()
        self.assertTrue(self._confirmed_idor(result, matrix_fixture.INVOICES))
        self.assertFalse(self._confirmed_idor(result, matrix_fixture.SHARED))

    def test_disconnecting_engagement_loader_is_detected(self):
        result = self._declared_investigation(disconnect=True)
        self.assertFalse(self._confirmed_idor(result, matrix_fixture.INVOICES))
