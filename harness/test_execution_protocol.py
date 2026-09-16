import asyncio
from harness.models import HttpExchange, Finding
from harness import planner, store

def test_plan_binds_to_exchange_hash():
    e=HttpExchange(url="https://example.test/item?id=1", method="GET",
                   request_headers={"Host":"example.test"}, request_body="")
    f=Finding(vulnerability_class="idor", confidence=.7, summary="x", evidence="y",
              suggested_test="compare identities", basis="derived")
    plans=planner.plans_for_findings(e,[f])
    assert plans and plans[0].source_exchange_hash == planner.exchange_fingerprint(e)
    assert plans[0].execution_plane == "burp"

def test_hash_changes_when_request_changes():
    e=HttpExchange(url="https://example.test/item?id=1", method="GET")
    e2=e.model_copy(update={"url":"https://example.test/item?id=2"})
    assert planner.exchange_fingerprint(e) != planner.exchange_fingerprint(e2)


def test_confirmation_requires_matching_typed_executor(monkeypatch, tmp_path):
    monkeypatch.setattr(store, "_DB_PATH", tmp_path / "state.db")
    e=HttpExchange(url="https://example.test/item?id=1", method="GET")
    f=Finding(vulnerability_class="idor", confidence=.7, summary="x", evidence="y",
              suggested_test="compare identities", basis="derived")
    plan=planner.plans_for_findings(e,[f])[0]
    store.persist_test_plans(e,[plan])
    bad=__import__('harness.models', fromlist=['ValidationSubmission']).ValidationSubmission(plan_id=plan.id, status="confirmed", confidence=.9, confirmed=True,
        summary="x", evidence="y", executor="burp:arbitrary", source_exchange_hash=plan.source_exchange_hash)
    ok, reason=store.persist_validation_submission(bad)
    assert not ok and "executor" in reason


def test_non_confirmation_capability_cannot_confirm(monkeypatch, tmp_path):
    # command_injection_validation is deliberately left off store.py's
    # confirmation_capabilities allowlist (timing-based evidence is
    # noisier than the other replay/probe capabilities -- see that
    # module's comment), unlike xss's reflection_context_validation,
    # which was added to the allowlist alongside this test's writing.
    monkeypatch.setattr(store, "_DB_PATH", tmp_path / "state.db")
    e=HttpExchange(url="https://example.test/form", method="POST")
    f=Finding(vulnerability_class="command_injection", confidence=.7, summary="x", evidence="y",
              suggested_test="timing differential", basis="derived")
    plan=planner.plans_for_findings(e,[f])[0]
    store.persist_test_plans(e,[plan])
    sub=__import__('harness.models', fromlist=['ValidationSubmission']).ValidationSubmission(plan_id=plan.id, status="confirmed", confidence=.9, confirmed=True,
        summary="x", evidence="y", executor=f"burp:{plan.capability}", source_exchange_hash=plan.source_exchange_hash)
    ok, reason=store.persist_validation_submission(sub)
    assert not ok and "cannot mark" in reason
