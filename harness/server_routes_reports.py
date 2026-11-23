"""Coverage and report routes: the report and SARIF exports, engagement leads, handoff,
app map and write-ups, and a finding's evidence reconstruction.

ARC-9: split out of harness/server.py. build_router(srv, router) adds these
routes to `router` (harness.server passes app.router) and reads per-process
state and the helpers tests patch through server module `srv`
(srv.orchestrator, srv._require_auth, ...) at request time, so each server
module gets its own state."""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, Header, HTTPException, Query
from fastapi.responses import JSONResponse, PlainTextResponse



def build_router(srv, router: APIRouter | None = None) -> APIRouter:
    """The reports routes, bound to server module `srv`, added to `router`
    (a new APIRouter when none is given)."""
    router = APIRouter() if router is None else router

    @router.get("/report")
    async def report(url: str, authorization: str | None = Header(default=None),
                     engagement_id: str = Query(default="", max_length=128),
                     captured_principal_id: str | None = Query(default=None, max_length=128)):
        """
        Analyst-facing Markdown writeup of everything found for `url`'s host
        so far -- report_generator.py, wired here for the first time. The
        module was fully built and tested (test_report_generator.py) but had
        no caller anywhere: no endpoint, no CLI hook, nothing -- found during
        a dead-code audit prompted by the same pattern already found and
        fixed once this session for retry_policy.py/payload_library.py.
        Passing the live orchestrator's effort ledger (not omitted, unlike
        the module's own standalone-script default) gets cost-aware ordering
        of unconfirmed findings for real, in-session token-spend data.
        """
        srv._require_auth(authorization)
        srv._require_read_auth(authorization)
        from harness import report_generator
        # Pass the effective config so an operator's reporting.* surfacing gates
        # (config.local.yaml) actually apply to this live report; all gates ship
        # OFF, so the default report is byte-identical.
        markdown = await __import__("asyncio").to_thread(
            report_generator.generate_report_for_host, url, srv.orchestrator.effort_budget.ledger,
            config=srv.config,
            engagement_id=engagement_id,
            captured_principal=captured_principal_id,
        )
        if not engagement_id:
            markdown = "> Shared site history (unnamed engagement). Use engagement_id to select a named partition.\n\n" + markdown
        return PlainTextResponse(markdown, media_type="text/markdown")

    @router.get("/report/sarif")
    async def report_sarif(url: str, authorization: str | None = Header(default=None),
                           engagement_id: str = Query(default="", max_length=128),
                           captured_principal_id: str | None = Query(default=None, max_length=128)):
        """
        RA-3: the SAME findings /report renders as Markdown, as a SARIF 2.1.0
        JSON document (sarif_adapter.py) instead -- so findings are portable
        into SARIF-consuming triage/CI tools (a dashboard, a ticketing
        pipeline, another scanner's aggregator). sarif_adapter.py
        (export_issues_to_sarif/validate_sarif_shape) was fully built and
        tested (test_sarif_adapter.py) but had no caller anywhere, same
        dead-code pattern as /report's own docstring above. A separate route
        (not a `?format=` switch on /report) so /report's existing Markdown
        contract stays byte-for-byte untouched. Takes the same `url` query
        param as /report; a host with no stored findings still gets a
        schema-valid SARIF document with zero results, not an error.

        R07/RA-6: originally built directly on group_findings_into_issues +
        export_issue -- the raw, un-enriched chain -- which silently dropped the
        persisted proof-attempt history (a retest) and any operator merge
        override (P1.8) that the canonical report_generator.export_issues_for_host
        (and therefore the Markdown /report and the MCP issues resource) already
        apply, and ignored the reporting.* surfacing gates /report honors (RA-5).
        Now built from export_issues_for_host itself (proofs_by_case + merges,
        config-gated) so a SARIF consumer sees the SAME view as the Markdown
        report, not a second, less-complete one. Passing the effective config
        applies an operator's reporting.* gates the same way /report does; SARIF
        has no "leads" section, so a finding the gates would demote is OMITTED
        from `results` instead (RA-6) -- never a confirmed/oracle-verified or
        other concrete finding, per each gate predicate's own recall guard. Every
        gate ships OFF, so the default SARIF is byte-identical to the pre-R07
        output.
        """
        srv._require_auth(authorization)
        srv._require_read_auth(authorization)
        from harness import report_generator, sarif_adapter
        from harness import evidence_ledger
        exports = await asyncio.to_thread(report_generator.export_issues_for_host, url, config=srv.config,
                                          engagement_id=engagement_id, captured_principal=captured_principal_id)
        source_revision = evidence_ledger.Provenance.capture().code_version
        doc = sarif_adapter.export_issues_to_sarif(exports, source_revision=source_revision)
        doc["runs"][0]["properties"]["engagement_id"] = engagement_id
        doc["runs"][0]["properties"]["state_partition"] = "explicit-engagement" if engagement_id else "shared-site-history"
        return JSONResponse(doc)

    def _leads_investigation(host: str, job_id: str) -> tuple[dict, dict]:
        """(result, meta) of the named or newest finished investigation for `host`
        whose durable result is readable; ({}, meta) when there is none."""
        import json
        journal = srv._job_store()
        jobs = [journal.get(job_id)] if job_id else journal.list(host)
        for job in jobs:
            if not job or job.get("host") != host or not job.get("result_ref"):
                continue
            try:
                return (json.loads(journal.read_result(job["job_id"])),
                        {"job_id": job["job_id"], "used": True, "note": "newest readable result"})
            except (ValueError, OSError, __import__("sqlite3").Error):
                continue
        return {}, {"job_id": None, "used": False,
                    "note": "no readable investigation result; blocked_on uses stored findings and the ledger only"}

    @router.get("/engagement/{host}/leads")
    async def engagement_leads(host: str, authorization: str | None = Header(default=None),
                               engagement_id: str = Query(default="", max_length=128),
                               captured_principal_id: str | None = Query(default=None, max_length=128),
                               job_id: str = Query(default="", max_length=128)):
        """HU-2: the ranked queue of unproven leads for a host, each with its recorded
        request (secrets redacted) or an explicit no-request reason, the one change to
        make, the expected positive/negative, and a typed blocked_on. Read-only: sends
        no traffic. Shape documented in harness/leads.py."""
        srv._require_auth(authorization)
        srv._require_read_auth(authorization)
        from harness import leads
        url = host if "//" in host else f"http://{host}/"
        investigation, meta = await asyncio.to_thread(_leads_investigation, host, job_id)
        try:
            items = await asyncio.to_thread(leads.build_leads, url, engagement_id=engagement_id,
                                            captured_principal=captured_principal_id,
                                            investigation=investigation)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from None
        return {"schema_version": leads.SCHEMA_VERSION, "host": host, "engagement_id": engagement_id,
                "sends_traffic": False, "investigation": meta, "lead_count": len(items), "leads": items}

    @router.get("/engagement/{host}/handoff")
    async def engagement_handoff_view(host: str, authorization: str | None = Header(default=None)):
        """HU-5: the newest run's handoff for this host (what was not tested) and the
        target change log of every run on it. Reads run artifacts; sends nothing."""
        srv._require_auth(authorization)
        srv._require_read_auth(authorization)
        from harness import run_handoff
        return await asyncio.to_thread(run_handoff.latest_for_host, host,
                                       run_handoff.output_dir_for(srv.config))

    @router.get("/engagement/{host}/map")
    async def engagement_app_map_view(host: str,
                                      engagement_id: str = Query(default="", max_length=128),
                                      authorization: str | None = Header(default=None)):
        """HU-3: the application map built from the store (roles, objects with owners and
        id patterns, endpoints by role outcome, value fields, captured workflows), with
        the stored semantic model overlaid as `proposed`. No model call; sends nothing."""
        srv._require_auth(authorization)
        srv._require_read_auth(authorization)
        from harness import app_map
        return await asyncio.to_thread(app_map.build_map, host.lower(), engagement_id=engagement_id)

    @router.get("/engagement/{host}/writeups")
    async def engagement_writeups(host: str, authorization: str | None = Header(default=None),
                                  engagement_id: str = Query(default="", max_length=128),
                                  captured_principal_id: str | None = Query(default=None, max_length=128)):
        """HU-6: one Markdown write-up per proof-bound issue (harness/writeups.py), drawn
        only from the recorded proof. Empty unless writeups.export_markdown is on. Sends nothing."""
        srv._require_auth(authorization)
        srv._require_read_auth(authorization)
        from harness import report_generator, writeups
        url = host if "//" in host else f"http://{host}/"
        enabled = writeups.settings(srv.config)["export_markdown"]
        exports = (await asyncio.to_thread(report_generator.export_issues_for_host, url, config=srv.config,
                                           engagement_id=engagement_id,
                                           captured_principal=captured_principal_id)) if enabled else []
        items = [{"issue_id": e.get("issue_id"), **e["writeup"]} for e in exports if e.get("writeup")]
        return {"host": host, "engagement_id": engagement_id, "enabled": enabled, "sends_traffic": False,
                "writeup_count": len(items), "writeups": items}

    @router.get("/findings/{finding_ref}/evidence")
    async def finding_evidence(finding_ref: str, authorization: str | None = Header(default=None),
                              engagement_id: str = Query(default="", max_length=128),
                              captured_principal_id: str | None = Query(default=None, max_length=128)):
        """P0-1: the EvidenceLedger's audit-grade reconstruction of one finding --
        why it was tested, what was sent, what came back, why it was concluded
        (vulnerable or not), and what was never tested -- plus the minimal recipe
        to reproduce it. Read-only: this exposes what the pipeline already
        recorded, never a live re-test. Reads the durable store (not the
        in-memory ledger) so it works even after a server restart."""
        srv._require_auth(authorization)
        srv._require_read_auth(authorization)
        from harness import evidence_ledger
        reconstruction = await __import__("asyncio").to_thread(
            evidence_ledger.reconstruct_persisted, finding_ref, engagement_id=engagement_id,
            captured_principal=captured_principal_id)
        recipe = await __import__("asyncio").to_thread(
            evidence_ledger.reproduction_recipe_persisted, finding_ref, engagement_id=engagement_id,
            captured_principal=captured_principal_id)
        if not reconstruction.get("event_count"):
            raise HTTPException(status_code=404, detail="no evidence-ledger events for this finding_ref")
        return {"reconstruction": reconstruction, "reproduction_recipe": recipe}

    return router
