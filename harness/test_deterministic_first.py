"""Caller-level regression for deterministic confirmation before model review."""
from __future__ import annotations

import asyncio
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import yaml

from harness import engagement_builder, missing_auth_probe, role_crawl, worklist_investigator
from harness.engagement import EngagementState
from harness.models import Finding, HttpExchange
from harness.orchestrator import Orchestrator
from harness.role_crawl import RoleSession
from harness.validators.base import ValidationResult
from harness.validators.sqlmap import SqlmapValidator


_HARNESS = Path(__file__).resolve().parent
BASE = "http://shop.test/"
CAPTURE = HttpExchange(
    method="GET",
    url=f"{BASE}filter?category=Pets",
    request_headers={},
    response_status=200,
    response_headers={"Content-Type": "text/html"},
    response_body="pets",
)


def _config() -> dict:
    cfg = yaml.safe_load((_HARNESS / "config.yaml").read_text(encoding="utf-8")) or {}
    cfg.setdefault("coordinator", {})["cloud_primary"] = False
    cfg.setdefault("critique", {})["enabled"] = False
    cfg.setdefault("validators", {})["active_enabled"] = True
    cfg["validators"]["allow_mutating_replay"] = False
    cfg.setdefault("iterative_agent", {})["enabled"] = True
    eng = cfg.setdefault("engagement", {})
    eng["auto_escalate"] = False
    eng["feature_crawl"] = False
    eng["coverage_drive_legs"] = False
    cfg.setdefault("server", {})["allowed_hosts"] = ["shop.test"]
    return cfg


async def _build(base_url, roles, **kwargs):
    state = EngagementState(host="shop.test")
    state._ep("GET", "/filter")
    rc = role_crawl.RoleCrawlResult(base_url=base_url)
    rc.captured.append(CAPTURE)
    return state, rc


class DeterministicFirstCallerTest(unittest.TestCase):
    def _run(self, *, stop_on_confirm: bool, objective_class: str | None = None,
             validator_confirms: bool = True):
        events: list[str] = []
        captured_exchange: dict[str, HttpExchange] = {}

        async def investigate(*args, **kwargs):
            events.append("worklist")
            node = {"method": "GET", "path": "/filter",
                    "template": {"method": "GET", "query": "category=Pets",
                                 "body": "", "content_type": "", "object_id": None}}
            ex = worklist_investigator._seed_exchange(BASE, node, {}, "1")
            captured_exchange["value"] = ex
            findings = await kwargs["precondition_fn"](node, ex)
            return [{"path": "/filter", "method": "GET",
                     "findings_detail": findings, "confirmed": bool(findings)}]

        async def review(*args, **kwargs):
            events.append("review")
            return 0

        confirmed = ValidationResult(
            validator="sqlmap",
            status="confirmed" if validator_confirms else "not_confirmed",
            finding_class="sqli", confidence=0.99,
            confirmed=validator_confirms, summary="boolean differential",
            evidence="true/false responses differed",
        )
        orch = Orchestrator(_config())
        orch.allowed_hosts = ["shop.test"]
        with patch.object(engagement_builder, "build_engagement", new=_build), \
             patch.object(worklist_investigator, "investigate_worklist", new=investigate), \
             patch("harness.orchestrator_chain.review_captured_exchanges", new=review), \
             patch("harness.orchestrator_chain.universal_header_audit",
                   new=AsyncMock(return_value=0)), \
             patch.object(SqlmapValidator, "validate", new=AsyncMock(return_value=confirmed)), \
             patch.object(orch, "_persist_confirmation_proof",
                          new=AsyncMock(return_value=(False, None, "test"))):
            result = asyncio.run(orch.investigate_engagement(
                BASE, [RoleSession("anonymous", {})], max_nodes=1,
                max_chain_rounds=0, discovery_max_probes=1,
                stop_on_confirm=stop_on_confirm,
                objective_class=objective_class))
        return events, result, captured_exchange.get("value")

    def test_sqli_confirmation_runs_and_short_circuits_model_review(self):
        events, result, exchange = self._run(stop_on_confirm=True)
        self.assertEqual(events, ["worklist"])
        self.assertEqual(exchange.url, f"{BASE}filter?category=Pets")
        findings = result["outcomes"][0]["findings_detail"]
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0]["confirmed"])
        self.assertEqual(findings[0]["confirmed_by_leg"], "sqlmap")
        self.assertTrue(result["stopped_on_confirmation"])
        self.assertEqual(result["coverage"], {})

    def test_objective_preflight_uses_capture_before_ranked_worklist(self):
        events, result, exchange = self._run(
            stop_on_confirm=True, objective_class="sqli")
        self.assertEqual(events, [])
        self.assertIsNone(exchange)
        self.assertEqual(result["outcomes"][0]["path"], "/filter")
        self.assertEqual(
            result["outcomes"][0]["stop_reason"],
            "deterministic_confirmation")
        self.assertTrue(result["stopped_on_confirmation"])

    def test_default_broad_run_reviews_content_after_deterministic_sweep(self):
        events, result, _ = self._run(stop_on_confirm=False)
        self.assertEqual(events, ["worklist", "review"])
        self.assertTrue(result["outcomes"][0]["confirmed"])

    def test_scoped_negative_returns_without_broad_model_review(self):
        events, result, _ = self._run(
            stop_on_confirm=True, objective_class="sqli",
            validator_confirms=False)
        self.assertEqual(events, ["worklist"])
        self.assertFalse(result["stopped_on_confirmation"])
        self.assertEqual(result["outcomes"][0]["findings_detail"], [])

    def test_anonymous_admin_route_is_routed_to_missing_auth_probe(self):
        # RV-O O7: renamed from ..._reaches_missing_auth_probe_and_confirms; the
        # probe outcome is mocked, so this pins only the routing to the probe.
        admin_exchange = HttpExchange(
            method="GET", url=f"{BASE}administrator-panel",
            request_headers={}, response_status=200,
            response_headers={"Content-Type": "text/html"},
            response_body="<h1>Admin panel</h1>")

        async def build_admin(base_url, roles, **kwargs):
            state = EngagementState(host="shop.test")
            state.ingest_role_crawl({"endpoints": [{
                "method": "GET", "path": "/administrator-panel",
                "by_role": {"anonymous": 200},
                "reachable_roles": ["anonymous"], "object_scoped": False,
                "template": {"method": "GET", "query": "", "body": "",
                             "content_type": "", "object_id": None},
            }]})
            rc = role_crawl.RoleCrawlResult(base_url=base_url)
            rc.captured.append(admin_exchange)
            return state, rc

        async def investigate(*args, **kwargs):
            node = {"method": "GET", "path": "/administrator-panel",
                    "reachable_roles": ["anonymous"],
                    "template": {"method": "GET", "query": "", "body": "",
                                 "content_type": "", "object_id": None}}
            ex = worklist_investigator._seed_exchange(BASE, node, {}, "1")
            findings = await kwargs["precondition_fn"](node, ex)
            return [{"path": node["path"], "method": "GET",
                     "findings_detail": findings, "confirmed": bool(findings)}]

        outcome = missing_auth_probe.ProbeOutcome(
            method="GET", url=f"{BASE}administrator-panel",
            classification="missing_auth", unauth_status=200, unauth_len=20,
            finding=Finding(
                vulnerability_class="missing_authentication", confidence=0.85,
                severity="high", summary="admin panel served anonymously",
                evidence="credential-stripped GET returned 200",
                suggested_test="", basis="derived", confirmed=True))
        orch = Orchestrator(_config())
        orch.allowed_hosts = ["shop.test"]
        with patch.object(engagement_builder, "build_engagement", new=build_admin), \
             patch.object(worklist_investigator, "investigate_worklist", new=investigate), \
             patch("harness.orchestrator_chain.review_captured_exchanges", new=AsyncMock(return_value=0)), \
             patch("harness.missing_auth_probe.probe",
                   new=AsyncMock(return_value=outcome)) as probe, \
             patch.object(orch, "_persist_confirmation_proof",
                          new=AsyncMock(return_value=(False, None, "test"))):
            result = asyncio.run(orch.investigate_engagement(
                BASE, [RoleSession("anonymous", {})], max_nodes=1,
                max_chain_rounds=0, discovery_max_probes=1,
                stop_on_confirm=True, objective_class="auth_bypass"))

        probe.assert_awaited_once()
        finding = result["outcomes"][0]["findings_detail"][0]
        self.assertTrue(finding["confirmed"])
        self.assertEqual(finding["confirmed_by_leg"], "missing_auth")
        self.assertTrue(result["stopped_on_confirmation"])


if __name__ == "__main__":
    unittest.main()
