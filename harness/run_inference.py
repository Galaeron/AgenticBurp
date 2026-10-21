"""Task/run-local usage views with one unchanged aggregate admission budget."""
from contextvars import ContextVar
from copy import copy
from functools import wraps
import inspect

from harness.effort import EffortBudget

_CURRENT = ContextVar('run_inference_owner', default=None)


def current(owner):
    binding = _CURRENT.get()
    return binding[1] if binding and binding[0] is owner else None


class RunEffortBudget:
    """A distinct receipt ledger; all admission and UI settings stay aggregate.

    Recording once in each ledger is intentional: the parent is the cumulative
    operator budget, while this view owns only this run's provider receipts.
    """
    def __init__(self, parent):
        self.parent = parent
        self.local = EffortBudget(parent.mode)
        self.run_id = ''

    @property
    def ledger(self):
        return self.local.ledger

    @property
    def spent(self):
        return self.local.spent

    @property
    def remaining(self):
        return self.parent.remaining

    @property
    def _reserved(self):
        return self.local._reserved

    def __getattr__(self, name):
        return getattr(self.parent, name)

    def allow(self):
        return self.parent.allow()

    def reserve(self, estimated_tokens):
        allowed, reason = self.parent.reserve(estimated_tokens)
        if allowed:
            self.local.reserve(estimated_tokens)
        return allowed, reason

    def commit(self, kind, model, prompt_tokens, completion_tokens, reserved=0, **meta):
        meta['run_id'] = self.run_id
        self.parent.commit(kind, model, prompt_tokens, completion_tokens, reserved=reserved, **meta)
        return self.local.commit(kind, model, prompt_tokens, completion_tokens, reserved=reserved, **meta)

    def record(self, kind, model, prompt_tokens, completion_tokens, **meta):
        meta['run_id'] = self.run_id
        self.parent.record(kind, model, prompt_tokens, completion_tokens, **meta)
        return self.local.record(kind, model, prompt_tokens, completion_tokens, **meta)

    def release(self, reserved):
        self.parent.release(reserved)
        self.local.release(reserved)

    def accounting(self):
        return {**self.local.accounting(), 'remaining_admission_tokens': self.parent.remaining}


class InferenceView:
    def __init__(self, owner):
        self.budget = RunEffortBudget(owner._aggregate_effort_budget)
        self.pipeline = copy(owner._analysis_pipeline_template)
        self.pipeline.effort_budget = self.budget


def attach(owner, context):
    """Associate the already-bound view with the actual context before dispatch."""
    view = current(owner)
    if view is None:
        return
    owners = getattr(context, '_inference_owners', None)
    if owners is None:
        owners = context._inference_owners = {}
    owners[owner._inference_owner_id] = view
    view.budget.run_id = context.run_id


def isolate_inference(fn):
    signature = inspect.signature(fn)
    @wraps(fn)
    async def wrapped(self, *args, **kwargs):
        # Legacy mixin test doubles have no production ownership assembly.
        if not hasattr(self, '_aggregate_effort_budget'):
            return await fn(self, *args, **kwargs)
        supplied = signature.bind(self, *args, **kwargs).arguments.get('run_context')
        view = (getattr(supplied, '_inference_owners', {}).get(self._inference_owner_id)
                if supplied is not None else None)
        if view is None:
            view = InferenceView(self)
            if supplied is not None:
                owners = getattr(supplied, '_inference_owners', None)
                if owners is None:
                    owners = supplied._inference_owners = {}
                owners[self._inference_owner_id] = view
                view.budget.run_id = supplied.run_id
        token = _CURRENT.set((self, view))
        try:
            return await fn(self, *args, **kwargs)
        finally:
            _CURRENT.reset(token)
    return wrapped
