"""A fresh model-call pacer for one test (O11 of the 2026-10-17 audit).

Every OllamaClient in a process shares one token limiter,
rate_limiter.get_token_limiter("ollama"): a 10-call burst, then one call every
6 s (harness/test_model_pacer.py pins it). A test runner runs many tests in one
process, so the calls of earlier tests pace a later test's calls, up to 6 s
each, by an amount that depends on test order. fresh_model_pacer(testcase)
gives the test its own limiter registry, so it starts with the shipped values
and a full bucket, and restores the shared registry when the test ends.

Product code is unchanged: the pacer still paces every call inside the test.
Call it before the test builds its first OllamaClient (a client takes the
limiter when it is built)."""
from harness import rate_limiter


def fresh_model_pacer(testcase) -> None:
    """Swap in a fresh limiter registry for `testcase`, once per test."""
    if getattr(testcase, "_fresh_model_pacer", False):
        return   # a second client in the same test shares the first one's pacer
    testcase._fresh_model_pacer = True
    testcase.addCleanup(setattr, rate_limiter, "_registry", rate_limiter._registry)
    testcase.addCleanup(delattr, testcase, "_fresh_model_pacer")
    rate_limiter._registry = None
