"""The flagship investigation job routes (R18): start (P1-7 pre-admission, then the P1-8
bounded admission), list, poll, fetch the result and cancel. The job registry itself
stays in harness.server: one shared state.

ARC-9: split out of harness/server.py. build_router(srv, router) adds these
routes to `router` (harness.server passes app.router) and reads per-process
state and the helpers tests patch through server module `srv`
(srv.orchestrator, srv._require_auth, ...) at request time, so each server
module gets its own state."""
from __future__ import annotations

import asyncio
import logging
import time as _time
import uuid as _uuid
from pathlib import Path

from fastapi import APIRouter, Header, HTTPException, Query
from pydantic import BaseModel as _BaseModel, Field, StrictBool

import harness.run_manifest as _run_manifest
from harness import security, store
from harness.models import HttpExchange
from harness.ollama_client import OllamaCloudModelRefusedError
from harness.server_admission import _ACTIVE_TRAFFIC
from harness.server_routes_active import _role_sessions
from harness.server_routes_engagement import _declarations_target

log = logging.getLogger("harness.server")


def _cancelled_instrumentation(run_context, job_id: str) -> dict:
    """{instrumentation, costs} for a cancelled job's partial result, from the
    RunInstrumentation investigate_engagement left on its run (R11-4b): a cancelled
    job reported no phase_timings, so its manifest's were empty. The phase the
    cancel interrupted is closed as interrupted. {} when no engagement started;
    {"instrumentation_error": ...} when the snapshot failed (never hides the cancel)."""
    instr = getattr(run_context, "instrumentation", None)
    if instr is None:
        return {}
    try:
        instr.phases.abort()
        return instr.result_blocks()
    except Exception as exc:
        log.warning("cancelled job %s: instrumentation snapshot failed (%s)", job_id, type(exc).__name__)
        return {"instrumentation_error": type(exc).__name__}


class InvestigateRequest(_BaseModel):
    base_url: str
    roles: list[dict] = []
    max_nodes: int = 8
    step_budget: int = 16
    max_chain_rounds: int = 2
    seed_exchanges: list[HttpExchange] = []
    active_discovery: bool = True
    # Per-request cap on active-discovery probes, bounded at use exactly like
    # the analysis request's field above (max(1, min(v, 20000))). The default
    # equals investigate_engagement's own default, so omitting it changes nothing.
    discovery_max_probes: int = 6000
    # Cap on the method+path operations discovery probes with every role. None
    # takes engagement.discovery_max_endpoints (default 0: no cap, the whole surface).
    discovery_max_endpoints: int | None = None
    resume_job_id: str | None = None
    # I16: the operator's engagement declarations for this run (saved lists apply
    # only through use_saved_declarations below).
    # protected_paths: patterns in docs/PROTECTED_ROUTES.md syntax for this target;
    # owners: authz.owners entries ({path, owner | public | authenticated,
    # shared_with}). Malformed entries are ignored with a warning, never confirm.
    protected_paths: list[str] = Field(default_factory=list, max_length=1000)
    owners: list[dict] = Field(default_factory=list, max_length=1000)
    # I16 persistence: opt in to the declarations saved for this target with
    # PUT /engagement/{host}/declarations. Off by default: saved lists never apply
    # to a request that did not ask. Per field, a non-empty request list REPLACES
    # the saved one (never merged); an empty request field takes the saved list.
    use_saved_declarations: StrictBool = False


def build_router(srv, router: APIRouter | None = None) -> APIRouter:
    """The investigate routes, bound to server module `srv`, added to `router`
    (a new APIRouter when none is given)."""
    router = APIRouter() if router is None else router

    @router.post("/engagement/{host}/investigate", dependencies=_ACTIVE_TRAFFIC)
    async def engagement_investigate(host: str, req: InvestigateRequest,
                                     authorization: str | None = Header(default=None)):
        """Start the flagship graph-driven investigation as a background JOB and return
        a job_id to poll. The job is cancellable. This is the single API entry to
        investigate_engagement (R18)."""
        srv._require_auth(authorization)
        try:  # SEC-1: refuse before a job exists, so the client sees why (409)
            from harness import model_egress
            model_egress.refuse_cloud_models(
                srv.orchestrator.config, model_egress.agent_models_of(srv.orchestrator.agent_manager))
        except OllamaCloudModelRefusedError as e:
            raise srv._cloud_run_refused(e)
        srv._require_target_fetch(req.base_url, bulk=True)
        if not req.base_url:
            raise HTTPException(status_code=400, detail="base_url is required")
        from harness import role_crawl
        from harness.run_context import RunContext
        from urllib.parse import urlsplit

        # P1-7 pre-admission check -- runs BEFORE any job/task is created or any
        # target request is made. An investigation start request must use scope
        # that is ALREADY pre-authorized (orchestrator.allowed_hosts, sourced from
        # config.yaml server.allowed_hosts); it may never grant new scope by the
        # mere act of naming a base_url (that was the prior bug this closes: the
        # target host used to be auto-added to allowed_hosts here). Host
        # normalization: lowercase, host-only (no port, no scheme) -- the same
        # normalization ScopePolicy.host_of/in_scope use elsewhere, so a request
        # to "shop.test:8080" and "SHOP.TEST" both normalize to "shop.test".
        def _norm_host(raw: str) -> str:
            # Accept either a bare hostname (the route {host} path param) or a
            # full URL (base_url); urlsplit on a bare host with no scheme puts it
            # in .path, not .hostname, so fall back to stripping a port manually.
            parsed = urlsplit(raw if "//" in raw else f"//{raw}")
            host = parsed.hostname
            if host is None:
                host = raw.split(":", 1)[0].split("/", 1)[0]
            return host.lower()

        target_host = _norm_host(req.base_url)
        route_host = _norm_host(host)
        if not target_host:
            raise HTTPException(status_code=400, detail="base_url has no resolvable host")
        if route_host != target_host:
            raise HTTPException(
                status_code=400,
                detail=f"route host {host!r} does not match base_url host {target_host!r}")
        allowed_hosts = {(h or "").lower() for h in (srv.orchestrator.allowed_hosts or [])}
        from harness.scope_lock import host_in_scope
        if not host_in_scope(req.base_url, allowed_hosts, active_mode=True):
            raise HTTPException(
                status_code=403,
                detail=f"target {req.base_url!r} is not in pre-authorized scope "
                       f"(server.allowed_hosts); investigate cannot grant new scope")

        # I16 persistence, opt-in only: resolve the saved declarations into the request
        # before anything reads its lists (journal key, kwargs), so a run that opted in
        # behaves exactly like one that sent the same lists itself.
        declarations_source = None
        if req.use_saved_declarations:
            saved = await asyncio.to_thread(store.load_engagement_declarations,
                                            *_declarations_target(host, req.base_url)) or {}
            declarations_source = {}
            update = {}
            for _field in ("protected_paths", "owners"):
                if getattr(req, _field):
                    declarations_source[_field] = "request"
                elif saved.get(_field):
                    update[_field] = saved[_field]
                    declarations_source[_field] = "saved"
                else:
                    declarations_source[_field] = "none"
            if update:
                req = req.model_copy(update=update)

        # P1-8 admission bound -- an ADDITIONAL gate that runs strictly AFTER
        # P1-7's route/base_url-consistency and pre-authorized-scope checks
        # above, never before or in place of them. First release any terminal
        # jobs past their retention window (frees capacity room), then reject if
        # concurrent running/cancelling jobs are already at the cap. This is a
        # simple hard rejection (no queue): a 503 with Retry-After, since the
        # server has finite job capacity and the caller can just retry later.
        srv._evict_expired_jobs()
        coverage_checkpoint = None
        journal_on = bool((srv.config.get('runs', {}) or {}).get('journal', False))
        journal_root = None
        journal_key = srv._journal_context_key(srv.config, req) if journal_on else ''
        # The attempts this job continues (oldest first): its accounting counts them all.
        prior_attempts: list[str] = []

        if req.resume_job_id:
            journal = srv._job_store()
            prior = journal.get(req.resume_job_id)
            if not prior or _norm_host(prior['host']) != target_host:
                raise HTTPException(status_code=404, detail='unknown prior job for this target')
            def _origin(url):
                parsed = urlsplit(url)
                return parsed.scheme.lower(), parsed.hostname, parsed.port or (443 if parsed.scheme.lower() == 'https' else 80)
            if prior['status'] not in srv._TERMINAL_STATUSES or _origin(prior['base_url']) != _origin(req.base_url):
                raise HTTPException(status_code=409, detail='prior job is not terminal or has a different target origin')
            from harness.coverage_tracker import resume_context_key
            prior_root = prior.get('journal_root') or req.resume_job_id
            # A job saved before attempt_run_ids existed names its root and itself.
            prior_attempts = [r for r in (prior.get('attempt_run_ids') or []) if isinstance(r, str) and r] \
                or [prior_root, req.resume_job_id]
            result_missing = False
            try:
                import json
                prior_result = json.loads(await asyncio.to_thread(journal.read_result, req.resume_job_id))
                coverage_checkpoint = (prior_result.get('coverage') or {}).get('checkpoint')
            except (ValueError, OSError, __import__('sqlite3').Error, AttributeError):
                result_missing = True
            if not result_missing:
                if not isinstance(coverage_checkpoint, dict) or coverage_checkpoint.get('context_key') != resume_context_key(srv.config):
                    raise HTTPException(status_code=409, detail='prior coverage is unavailable or source/configuration changed')
            else:
                # An interrupted job has no result. With the run journal on, the units it
                # journaled stand in for one, if this configuration is the one that wrote them;
                # the coverage checkpoint then comes from the journal, inside the run.
                if not journal_on:
                    raise HTTPException(status_code=409, detail='prior result is missing or corrupt')
                from harness.run_journal import RunJournal
                prior_units = RunJournal(srv._run_journal_path(), prior_root, journal_key)
                if not await asyncio.to_thread(prior_units.has_any):
                    if await asyncio.to_thread(prior_units.has_any, any_context=True):
                        raise HTTPException(status_code=409,
                                            detail='prior coverage is unavailable or source, configuration '
                                                   'or request inputs changed')
                    raise HTTPException(status_code=409, detail='prior result is missing or corrupt')
                # Only an interrupted job resumes from its journal; a finished one keeps
                # the result-and-checkpoint path above.
                journal_root = prior_root
        running_count = sum(1 for j in srv._INVESTIGATE_JOBS.values() if j["status"] in srv._RUNNING_STATUSES)
        if running_count >= srv._MAX_RUNNING_JOBS:
            raise HTTPException(
                status_code=503,
                detail=f"investigation job capacity reached ({running_count}/{srv._MAX_RUNNING_JOBS} "
                       f"running); retry later",
                headers={"Retry-After": "5"})

        roles = _role_sessions(req.roles) or [role_crawl.RoleSession(role="anonymous", headers={})]
        job_id = _uuid.uuid4().hex[:12]
        runs_cfg = (srv.config.get("runs", {}) or {})
        run_context = RunContext.create(
            run_id=job_id, allowed_hosts=allowed_hosts,
            gate_config=srv._live_validators_gate_config(),
            max_requests=runs_cfg.get("max_requests"), config=srv.config,
            timeout=float(runs_cfg.get("request_timeout_seconds", 15.0)))
        # E7: the run's journal, rooted at this job, or at the prior job's root when resuming.
        if journal_on:
            try:
                from harness.run_journal import RunJournal
                run_context.run_journal = RunJournal(
                    srv._run_journal_path(), journal_root or job_id, journal_key, roles=roles)
                await asyncio.to_thread(run_context.run_journal.prune)
            except Exception as exc:
                run_context.run_journal = None
                log.warning('run journal unavailable (%s); this job is not journaled', type(exc).__name__)
        output_dir = Path(runs_cfg.get('output_dir') or Path(srv.__file__).parent / 'run-output')
        # HU-5: the run's handoff + change log, persisted beside the manifest as it runs.
        from harness import run_handoff
        run_handoff.attach(run_context, host=host, base_url=req.base_url, output_dir=output_dir)
        job: dict = {"job_id": job_id, "host": host, "base_url": req.base_url,
                     "status": "running", "task": None, "result": None, "error": None,
                     "started_at": _time.time(), "finished_at": None,
                     "manifest_path": str(output_dir / f'{job_id}.json'), "run_context": run_context,
                     "journal_root": (run_context.run_journal.root_job_id
                                      if run_context.run_journal is not None else None),
                     "attempt_run_ids": list(dict.fromkeys([*prior_attempts, job_id]))}
        try:
            _, admitted = srv._job_store().create(job)
            if not admitted:
                raise ValueError('duplicate job identity')
        except Exception:
            await run_context.aclose()
            raise HTTPException(status_code=503, detail='durable job admission unavailable',
                                headers={'Retry-After': '5'}) from None

        try:
            manifest = _run_manifest.RunManifest.start(
                run_id=job_id, target_identifier=host, config=security.sanitize_data(srv.config),
                cache_namespace=run_context.cache_namespace, output_dir=runs_cfg.get("output_dir"),
                model_versions={"coordinator": srv.orchestrator.coordinator_model,
                            "critique": __import__("harness.coordinator", fromlist=["reasoning_model"]).reasoning_model(srv.config),
                            "surface_prioritization": (srv.config.get("surface_prioritization") or {}).get("model", srv.orchestrator.coordinator_model),
                            "agents": sorted({getattr(a, "model", "")
                                              for a in srv.orchestrator.agent_manager.agents.values()
                                              if getattr(a, "model", "")}),
                            # P1.1: which provider actually served each role this run --
                            # "ollama" unless config explicitly opted a role into a
                            # remote provider. Read from config, not from a live
                            # provider object, so this never touches an API key.
                            "coordinator_provider": (srv.config.get("coordinator") or {}).get("provider", "ollama"),
                            "critique_provider": (srv.config.get("critique") or {}).get("provider", "ollama"),
                            # AR-10 P2: whether Ollama calls ran with thinking on
                            # (ollama.think); "off" means no reasoning-mode result.
                            "think": __import__("harness.ollama_client", fromlist=["think_setting"]).think_setting(
                                (srv.config.get("ollama") or {}).get("think")),
                            # Which wire protocol served the model calls (ollama.api) and
                            # the output cap / reasoning effort it ran with.
                            "model_backend": __import__("harness.ollama_client", fromlist=["backend_setting"]).backend_setting(
                                srv.config.get("ollama"))})
        except Exception:
            job.update(status='error', finished_at=_time.time(),
                       error='job manifest initialization failed; no work was scheduled')
            srv._save_job_status(job)
            await run_context.aclose()
            raise HTTPException(status_code=503, detail='job manifest initialization unavailable',
                                headers={'Retry-After': '5'}) from None

        def _finish_manifest(status, *, result=None, error=None):
            run_handoff.finish(run_context, status, result)
            try:
                # ARC-3: the run's request-ceiling outcome (stop_reason budget_exhausted).
                manifest.finish(status, result=security.sanitize_data(result), error=error,
                                request_ceiling=run_context.budget.state())
            except Exception as exc:
                # Artifact persistence loss is not an unhandled async task failure.
                # Keep cancellation visible, but never advertise a completed durable
                # record when its terminal manifest could not be written.
                job['delivery_error'] = 'manifest persistence failed; execution record is incomplete'
                log.warning('job manifest persistence failed (%s)', type(exc).__name__)

        async def _run():
            try:
                # Finding persistence and diagnostics use this task-local binding.
                # The engagement job is a separate background task from /analyze,
                # so it must establish the run coordinate itself.
                from harness import telemetry
                telemetry.bind_current_run(run_context.run_id)
                async with run_context:
                    job["result"] = await srv.orchestrator.investigate_engagement(
                        req.base_url, roles,
                        max_nodes=max(1, min(req.max_nodes, 100)),
                        step_budget=max(1, min(req.step_budget, 64)),
                        max_chain_rounds=max(0, min(req.max_chain_rounds, 10)),
                        run_context=run_context,
                        seed_exchanges=req.seed_exchanges,
                        active_discovery=req.active_discovery,
                        discovery_max_probes=max(1, min(req.discovery_max_probes, 20000)),
                        **({'discovery_max_endpoints': max(0, min(req.discovery_max_endpoints, 100000))}
                           if req.discovery_max_endpoints is not None else {}),
                        **({'protected_paths': req.protected_paths} if req.protected_paths else {}),
                        **({'owners': req.owners} if req.owners else {}),
                        **({'coverage_checkpoint': coverage_checkpoint} if coverage_checkpoint is not None else {}))
                job["result"].setdefault("run_id", run_context.run_id)
                if declarations_source is not None:
                    job["result"].setdefault("declarations_source", declarations_source)
                job["result"].setdefault("cache_namespace", run_context.cache_namespace)
                job["result"].setdefault("request_count", run_context.budget.used)
                # Use the persisted, proof-resolved projection of this run and the
                # attempts it resumed. Raw model flags and repeated validator records
                # are not issue counts.
                from harness.assessment_health import headline_counts
                from harness.issues import count_units
                attempts = job["attempt_run_ids"]
                rows = srv._attempt_findings(req.base_url, attempts)
                proven, accounting = srv._attempt_accounting(attempts, [*rows, *job["result"].get("findings", [])])
                job["result"]["attempt_run_ids"] = list(attempts)
                job["result"]["confirmed_issues"] = len(proven)
                job["result"]["confirmed_issue_refs"] = proven
                job['result']['issue_accounting'] = accounting
                # EFF-3: the per-case vulnerability groups and their root causes, each
                # beside its unit; the records' three counts in finding_summary.
                job['result'].update(headline_counts(accounting))
                job['result']['confirmed_issues_unit'] = 'proof_bound_cases'
                job["result"]["finding_summary"] = {
                    "records": len(rows), "proof_bound_confirmed_cases": len(proven),
                    "unproven_records": sum(not (r.get("confirmed") and r.get("proof_status") == "resolved") for r in rows),
                    "scoreboard_mapping": "not supplied", "issue_counts": accounting['counts'],
                    "issue_units": count_units(rows)}
                job["status"] = "done"
                _finish_manifest("done", result=job["result"])
            except asyncio.CancelledError:
                job["status"] = "cancelled"
                # Persist evidence already produced by this run even if the chain
                # never returned its final result. Recovery never resumes execution.
                attempts = job["attempt_run_ids"]
                job['result'] = {'partial': True, 'run_id': run_context.run_id,
                                 'attempt_run_ids': list(attempts),
                                 'request_count': run_context.budget.used,
                                 'findings': srv._attempt_findings(req.base_url, attempts)}
                # r9's last attempt was cancelled and reported no count at all. The
                # accounting is best effort here: it must never hide the cancel.
                try:
                    from harness.assessment_health import headline_counts
                    proven, accounting = srv._attempt_accounting(attempts, job['result']['findings'])
                    job['result'].update(
                        confirmed_issues=len(proven), confirmed_issue_refs=proven,
                        issue_accounting=accounting, confirmed_issues_unit='proof_bound_cases',
                        **headline_counts(accounting))
                except Exception as exc:
                    job['result']['accounting_error'] = type(exc).__name__
                    log.warning("cancelled job %s: issue accounting failed (%s)", job_id, type(exc).__name__)
                # R11-4b: the same instrumentation block (phase_timings, sqlmap_targeting,
                # ...) and costs a finished job reports, from the engagement's recorder;
                # the phase the cancel interrupted is closed as interrupted. Best effort.
                job['result'].update(_cancelled_instrumentation(run_context, job_id))
                _finish_manifest("cancelled", result=job['result'])
                raise
            except Exception as e:  # a failed job must report, never crash the server
                job["status"] = "error"
                job["error"] = security.safe_error_summary(e)
                _finish_manifest("error", error=job["error"])
                log.warning("investigate job %s failed (%s)", job_id, type(e).__name__)
            finally:
                job["finished_at"] = _time.time()
                # P1-8: the job just reached a terminal state -- release the
                # Task and RunContext references (the run_context's "async with"
                # above already closed its transport) so they're eligible for
                # GC. The job dict itself, including its result/error/
                # manifest_path, stays in _INVESTIGATE_JOBS and readable for
                # _JOB_RETENTION_SECONDS; _evict_expired_jobs() drops the whole
                # dict once that window (or the retained-terminal-job cap) is
                # exceeded.
                job["task"] = None
                job["run_context"] = None
                job['result_available'] = job.get('result') is not None
                srv._save_job_status(job)

        def _ensure_cancelled(task):
            # Cancellation before the coroutine's first step never enters its
            # try/finally. Preserve terminal polling in that scheduling window too.
            if task.cancelled() and job['status'] in srv._RUNNING_STATUSES:
                job.update(status='cancelled', finished_at=_time.time(), task=None, run_context=None)
                try:
                    _finish_manifest('cancelled')
                finally:
                    srv._save_job_status(job)

        job["task"] = asyncio.create_task(_run())
        job['task'].add_done_callback(_ensure_cancelled)
        srv._INVESTIGATE_JOBS[job_id] = job
        return srv._job_public(job)

    @router.get("/engagement/{host}/investigate")
    async def engagement_investigate_list(host: str, authorization: str | None = Header(default=None)):
        """List investigation jobs for a host (newest-first status only)."""
        srv._require_auth(authorization)
        srv._require_read_auth(authorization)
        srv._evict_expired_jobs()
        durable = {j['job_id']: j for j in srv._job_store().list(host)}
        durable.update({jid: j for jid, j in srv._INVESTIGATE_JOBS.items() if j['host'] == host})
        jobs = list(durable.values())
        jobs.sort(key=lambda j: j.get("started_at") or 0, reverse=True)
        return {"host": host, "jobs": [srv._job_public(j) for j in jobs]}

    @router.get("/engagement/{host}/investigate/{job_id}")
    async def engagement_investigate_status(host: str, job_id: str,
                                            authorization: str | None = Header(default=None)):
        """Poll a job; the full investigate_engagement result is included once done."""
        srv._require_auth(authorization)
        srv._require_read_auth(authorization)
        srv._evict_expired_jobs()
        job = srv._INVESTIGATE_JOBS.get(job_id) or srv._job_store().get(job_id)
        if not job or job["host"] != host:
            # P1-8: an evicted/expired job_id lands here too (its dict was
            # dropped by _evict_expired_jobs), same as a job_id that never
            # existed -- see _evict_expired_jobs's docstring for why this is a
            # single documented 404 rather than a distinct "410 Gone".
            raise HTTPException(status_code=404, detail="unknown job")
        return srv._job_public(job, include_result=True)

    @router.get("/engagement/{host}/investigate/{job_id}/result")
    async def engagement_investigate_result(host: str, job_id: str,
                                            offset: int = Query(default=0, ge=0),
                                            limit: int = Query(default=262144, ge=1, le=262144),
                                            authorization: str | None = Header(default=None)):
        """Authenticated byte chunks of canonical, redacted JSON (SHA256 over all bytes)."""
        srv._require_auth(authorization)
        srv._require_read_auth(authorization)
        srv._evict_expired_jobs()
        journal = srv._job_store()
        job = journal.get(job_id)
        if not job or job['host'] != host:
            raise HTTPException(status_code=404, detail='unknown job')
        if not job.get('result_ref'):
            raise HTTPException(status_code=409, detail='result is not yet available')
        try:
            content = await asyncio.to_thread(journal.read_result, job_id)
        except ValueError:
            raise HTTPException(status_code=503, detail='result artifact missing or corrupt') from None
        except (OSError, __import__('sqlite3').Error):
            raise HTTPException(status_code=503, detail='result storage unavailable') from None
        if offset > len(content):
            raise HTTPException(status_code=416, detail='offset exceeds result size')
        end = min(offset + limit, len(content))
        import base64
        return {'offset': offset, 'next_offset': end if end < len(content) else None,
                'size_bytes': len(content), 'sha256': job['result_sha256'],
                'encoding': 'base64', 'data': base64.b64encode(content[offset:end]).decode('ascii')}

    @router.post("/engagement/{host}/investigate/{job_id}/cancel")
    async def engagement_investigate_cancel(host: str, job_id: str,
                                            authorization: str | None = Header(default=None)):
        """Request cancellation of a running job (asyncio task cancellation)."""
        srv._require_auth(authorization)
        srv._evict_expired_jobs()
        job = srv._INVESTIGATE_JOBS.get(job_id) or srv._job_store().get(job_id)
        if not job or job["host"] != host:
            raise HTTPException(status_code=404, detail="unknown job")
        task = job.get("task")
        if task is None and job['status'] in srv._RUNNING_STATUSES:
            raise HTTPException(status_code=409, detail='job belongs to another live process; cancellation was not sent')
        if task is not None and not task.done():
            context = job.get("run_context")
            if context is not None:
                context.cancel.cancel()
            task.cancel()
            if job["status"] == "running":
                job["status"] = "cancelling"
            srv._save_job_status(job)
        return srv._job_public(job)

    return router
