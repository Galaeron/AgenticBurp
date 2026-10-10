"""SC-12: durable WorkItem queue -- caller-level tests + negative controls.

Every test drives the public :class:`harness.work_queue.WorkQueue` API (the
adapter seam callers/UI are meant to use), backed by a real temp SQLite DB
(store._DB_PATH monkeypatched, same isolation pattern as test_store.py). The
three SC-12 acceptance criteria each get a positive test AND a negative control:

  1. crash + replay -> no duplicate external mutations, no lost work
     (CrashReplayTests, plus DoneItemNeverReleasedTests as the structural control)
  2. two concurrent engagements cannot share items/credentials/budget
     (EngagementIsolationTests)
  3. a failed task is retryable without changing its proof identity
     (RetryIdentityTests)
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from harness import store, work_queue
from harness.work_queue import WorkQueue, WorkItem, compute_item_id


class _Clock:
    """Deterministic, advanceable clock so lease expiry / crash replay are
    exercised without real sleeping."""

    def __init__(self, start: float = 1000.0):
        self.t = float(start)

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += float(seconds)


class _QueueTestBase(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._original_db_path = store._DB_PATH
        store._DB_PATH = Path(self._tmpdir.name) / "test_work_queue.db"
        self.clock = _Clock()

    def tearDown(self):
        store._DB_PATH = self._original_db_path
        self._tmpdir.cleanup()


# ---------------------------------------------------------------------------
# Proof identity
# ---------------------------------------------------------------------------
class IdentityTests(unittest.TestCase):
    def test_identity_is_stable_for_same_logical_work(self):
        a = compute_item_id("eng", "case1", "confirm.sqli", "alice", {"leg": "boolean"})
        b = compute_item_id("eng", "case1", "confirm.sqli", "alice", {"leg": "boolean"})
        self.assertEqual(a, b)
        self.assertTrue(a.startswith("wi:"))

    def test_identity_changes_with_payload_principal_capability_case_or_engagement(self):
        base = compute_item_id("eng", "case1", "confirm.sqli", "alice", {"leg": "boolean"})
        self.assertNotEqual(base, compute_item_id("eng", "case1", "confirm.sqli", "alice", {"leg": "time"}))
        self.assertNotEqual(base, compute_item_id("eng", "case1", "confirm.sqli", "bob", {"leg": "boolean"}))
        self.assertNotEqual(base, compute_item_id("eng", "case1", "confirm.xss", "alice", {"leg": "boolean"}))
        self.assertNotEqual(base, compute_item_id("eng", "case2", "confirm.sqli", "alice", {"leg": "boolean"}))
        self.assertNotEqual(base, compute_item_id("other", "case1", "confirm.sqli", "alice", {"leg": "boolean"}))

    def test_identity_is_independent_of_payload_key_order(self):
        a = compute_item_id("eng", "c", "cap", "p", {"a": 1, "b": 2})
        b = compute_item_id("eng", "c", "cap", "p", {"b": 2, "a": 1})
        self.assertEqual(a, b)


# ---------------------------------------------------------------------------
# Enqueue / lease / complete happy path + idempotent enqueue
# ---------------------------------------------------------------------------
class EnqueueLeaseCompleteTests(_QueueTestBase):
    def test_enqueue_lease_complete_roundtrip(self):
        q = WorkQueue("eng", worker="w1", clock=self.clock)
        item = q.enqueue("confirm.sqli", case_ref="c1", principal="alice",
                         payload={"leg": "boolean"})
        self.assertIsNotNone(item)
        self.assertEqual(item.status, "pending")
        self.assertEqual(item.attempt, 0)

        leased = q.lease()
        self.assertEqual(leased.item_id, item.item_id)
        self.assertEqual(leased.status, "leased")
        self.assertEqual(leased.attempt, 1)
        self.assertEqual(leased.lease_owner, "w1")

        self.assertTrue(q.complete(leased, result_ref="proof-1"))
        done = q.get(item.item_id)
        self.assertEqual(done.status, "done")
        self.assertEqual(done.result_ref, "proof-1")

    def test_reenqueue_same_work_is_idempotent_no_duplicate_row(self):
        q = WorkQueue("eng", clock=self.clock)
        first = q.enqueue("cap", case_ref="c", payload={"n": 1})
        again = q.enqueue("cap", case_ref="c", payload={"n": 1})
        self.assertEqual(first.item_id, again.item_id)
        self.assertEqual(len(q.items()), 1)

    def test_different_payload_is_a_distinct_item(self):
        q = WorkQueue("eng", clock=self.clock)
        a = q.enqueue("cap", case_ref="c", payload={"n": 1})
        b = q.enqueue("cap", case_ref="c", payload={"n": 2})
        self.assertNotEqual(a.item_id, b.item_id)
        self.assertEqual(len(q.items()), 2)

    def test_higher_priority_is_leased_first(self):
        q = WorkQueue("eng", clock=self.clock)
        q.enqueue("cap", case_ref="lo", payload={"n": 1}, priority=1)
        q.enqueue("cap", case_ref="hi", payload={"n": 2}, priority=9)
        leased = q.lease()
        self.assertEqual(leased.case_ref, "hi")


# ---------------------------------------------------------------------------
# Criterion 1: crash + replay -> no duplicate external mutations, no lost work
# ---------------------------------------------------------------------------
class CrashReplayTests(_QueueTestBase):
    def test_crash_after_effect_then_replay_does_not_duplicate_or_lose_work(self):
        # A worker performs an external mutation keyed idempotently on the
        # item's stable proof identity, then records completion. We simulate a
        # crash BETWEEN the effect and the completion, then replay.
        effects: dict[str, int] = {}

        def run_once(queue, *, crash: bool):
            item = queue.lease()
            self.assertIsNotNone(item, "expected a leasable item")
            # external mutation, deduped on the durable proof identity
            if item.item_id not in effects:
                effects[item.item_id] = 0
                _did_mutation = True
            else:
                _did_mutation = False
            if _did_mutation:
                effects[item.item_id] += 1
            if crash:
                return item  # process dies before complete()
            self.assertTrue(queue.complete(item, result_ref="proof"))
            return item

        q1 = WorkQueue("eng", worker="w1", lease_seconds=100.0, clock=self.clock)
        item = q1.enqueue("confirm.sqli", case_ref="c1", payload={"leg": "boolean"})

        # First run crashes after the external effect, before completion.
        crashed = run_once(q1, crash=True)
        self.assertEqual(effects[crashed.item_id], 1)
        self.assertEqual(q1.get(item.item_id).status, "leased")  # stuck under w1's lease

        # Replay by a fresh worker after the lease expires.
        self.clock.advance(200.0)
        q2 = WorkQueue("eng", worker="w2", lease_seconds=100.0, clock=self.clock)
        self.assertEqual(q2.reclaim(), 1)  # crashed lease recovered -> no lost work
        replayed = run_once(q2, crash=False)

        # No duplicate external mutation (same proof identity was deduped)...
        self.assertEqual(replayed.item_id, item.item_id)
        self.assertEqual(effects[item.item_id], 1)
        # ...and the work is not lost: it eventually completed with a result.
        final = q2.get(item.item_id)
        self.assertEqual(final.status, "done")
        self.assertEqual(final.result_ref, "proof")

    def test_reclaim_only_touches_expired_leases(self):
        q = WorkQueue("eng", worker="w1", lease_seconds=100.0, clock=self.clock)
        q.enqueue("cap", case_ref="c1", payload={"n": 1})
        leased = q.lease()
        # Not yet expired -> reclaim is a no-op, lease still held.
        self.clock.advance(50.0)
        self.assertEqual(q.reclaim(), 0)
        self.assertEqual(q.get(leased.item_id).status, "leased")
        # Past expiry -> reclaimed back to pending.
        self.clock.advance(100.0)
        self.assertEqual(q.reclaim(), 1)
        self.assertEqual(q.get(leased.item_id).status, "pending")


class DoneItemNeverReleasedTests(_QueueTestBase):
    """Structural negative control for criterion 1: once done, an item is
    terminal -- no reclaim sweep or lease can ever re-dispatch it, so replay
    cannot re-run a completed external effect regardless of worker behaviour."""

    def test_completed_item_is_never_reclaimed_or_re_leased(self):
        q = WorkQueue("eng", worker="w1", lease_seconds=100.0, clock=self.clock)
        item = q.enqueue("cap", case_ref="c1", payload={"n": 1})
        leased = q.lease()
        self.assertTrue(q.complete(leased, result_ref="r"))

        self.clock.advance(10_000.0)  # long past any lease horizon
        self.assertEqual(q.reclaim(), 0)               # done items are not reclaimed
        self.assertIsNone(q.lease())                   # and never re-leased
        self.assertEqual(q.get(item.item_id).status, "done")

    def test_completing_a_non_leased_item_is_a_no_op(self):
        q = WorkQueue("eng", clock=self.clock)
        item = q.enqueue("cap", case_ref="c1", payload={"n": 1})
        # pending (never leased) -> complete refuses
        self.assertFalse(q.complete(item, result_ref="r"))
        self.assertEqual(q.get(item.item_id).status, "pending")
        # completing twice: second attempt is a no-op
        leased = q.lease()
        self.assertTrue(q.complete(leased, result_ref="r1"))
        self.assertFalse(q.complete(leased, result_ref="r2"))
        self.assertEqual(q.get(item.item_id).result_ref, "r1")  # not overwritten


# ---------------------------------------------------------------------------
# Criterion 2: engagement isolation (items, credentials/principal, budget)
# ---------------------------------------------------------------------------
class EngagementIsolationTests(_QueueTestBase):
    def test_lease_never_crosses_engagements(self):
        qa = WorkQueue("engA", worker="wa", clock=self.clock)
        qb = WorkQueue("engB", worker="wb", clock=self.clock)
        qa.enqueue("cap.a", case_ref="ca", principal="alice", payload={"x": 1}, priority=1)
        # B's item has HIGHER priority; A must still never see it.
        qb.enqueue("cap.b", case_ref="cb", principal="bob", payload={"y": 1}, priority=9)

        la = qa.lease()
        self.assertEqual(la.engagement_id, "engA")
        self.assertEqual(la.principal, "alice")
        self.assertNotIn("y", la.payload)  # B's payload never leaks to A

        lb = qb.lease()
        self.assertEqual(lb.engagement_id, "engB")
        self.assertEqual(lb.principal, "bob")

        # A has nothing left and never picks up B's remaining/again work.
        self.assertIsNone(qa.lease())

    def test_budget_reservations_are_per_engagement(self):
        qa = WorkQueue("engA", budget_cap=10.0, clock=self.clock)
        qb = WorkQueue("engB", budget_cap=10.0, clock=self.clock)
        qa.enqueue("cap", case_ref="ca", payload={"x": 1}, budget_reservation=8.0)
        qb.enqueue("cap", case_ref="cb", payload={"y": 1}, budget_reservation=3.0)
        # A's 8.0 reservation does not reduce B's remaining budget and vice versa.
        self.assertAlmostEqual(qa.remaining_budget(), 2.0)
        self.assertAlmostEqual(qb.remaining_budget(), 7.0)

    def test_items_listing_is_scoped_to_the_engagement(self):
        qa = WorkQueue("engA", clock=self.clock)
        qb = WorkQueue("engB", clock=self.clock)
        qa.enqueue("cap", case_ref="ca", payload={"x": 1})
        qb.enqueue("cap", case_ref="cb", payload={"y": 1})
        self.assertEqual([i.engagement_id for i in qa.items()], ["engA"])
        self.assertEqual([i.engagement_id for i in qb.items()], ["engB"])


# ---------------------------------------------------------------------------
# Criterion 3: a failed task is retryable without changing its proof identity
# ---------------------------------------------------------------------------
class RetryIdentityTests(_QueueTestBase):
    def test_fail_then_retry_keeps_identity_and_increments_attempt(self):
        q = WorkQueue("eng", worker="w", default_max_attempts=3, clock=self.clock)
        item = q.enqueue("cap.x", case_ref="cr", principal="p", payload={"a": 1})
        id0 = item.item_id

        l1 = q.lease()
        self.assertEqual(l1.attempt, 1)
        self.assertEqual(q.fail(l1, "boom"), "pending")

        after_fail = q.get(id0)
        self.assertEqual(after_fail.item_id, id0)        # identity unchanged
        self.assertEqual(after_fail.status, "pending")   # retryable
        self.assertEqual(after_fail.attempt, 1)          # attempt preserved
        self.assertEqual(after_fail.last_error, "boom")

        l2 = q.lease()
        self.assertEqual(l2.item_id, id0)                # same proof identity
        self.assertEqual(l2.attempt, 2)                  # re-incremented on re-lease
        self.assertTrue(q.complete(l2, result_ref="proof"))
        self.assertEqual(q.get(id0).item_id, id0)

    def test_reenqueue_after_failure_does_not_fork_identity(self):
        q = WorkQueue("eng", worker="w", clock=self.clock)
        item = q.enqueue("cap.x", case_ref="cr", principal="p", payload={"a": 1})
        q.fail(q.lease(), "boom")
        # Re-proposing the identical work returns the SAME item, not a new one.
        again = q.enqueue("cap.x", case_ref="cr", principal="p", payload={"a": 1})
        self.assertEqual(again.item_id, item.item_id)
        self.assertEqual(len(q.items()), 1)

    def test_exhausting_attempts_marks_dead_without_changing_identity(self):
        q = WorkQueue("eng", worker="w", default_max_attempts=2, clock=self.clock)
        item = q.enqueue("cap.x", case_ref="cr", payload={"a": 1})
        id0 = item.item_id

        self.assertEqual(q.fail(q.lease(), "e1"), "pending")  # attempt 1 < 2
        self.assertEqual(q.fail(q.lease(), "e2"), "dead")     # attempt 2 == 2
        dead = q.get(id0)
        self.assertEqual(dead.status, "dead")
        self.assertEqual(dead.item_id, id0)                   # identity survives
        self.assertIsNone(q.lease())                          # dead is not runnable


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------
class DependencyTests(_QueueTestBase):
    def test_dependent_item_is_not_leased_until_dependency_done(self):
        q = WorkQueue("eng", worker="w", clock=self.clock)
        t1 = q.enqueue("cap.t1", case_ref="c", payload={"step": 1}, priority=1)
        # t2 depends on t1 and has HIGHER priority -- must still wait for t1.
        t2 = q.enqueue("cap.t2", case_ref="c", payload={"step": 2}, priority=9,
                       depends_on=[t1.item_id])

        first = q.lease()
        self.assertEqual(first.item_id, t1.item_id)
        # Negative control: with t1 leased-not-done, t2 stays blocked.
        self.assertIsNone(q.lease())

        self.assertTrue(q.complete(first, result_ref="r1"))
        second = q.lease()
        self.assertEqual(second.item_id, t2.item_id)


# ---------------------------------------------------------------------------
# Budget cap enforcement + release
# ---------------------------------------------------------------------------
class BudgetTests(_QueueTestBase):
    def test_enqueue_refused_when_reservation_exceeds_cap(self):
        q = WorkQueue("eng", budget_cap=5.0, clock=self.clock)
        self.assertIsNotNone(q.enqueue("cap", case_ref="c1", payload={"n": 1},
                                       budget_reservation=3.0))
        # 3.0 + 4.0 > 5.0 -> refused, no row written, budget unchanged.
        self.assertIsNone(q.enqueue("cap", case_ref="c2", payload={"n": 2},
                                    budget_reservation=4.0))
        self.assertEqual(len(q.items()), 1)
        self.assertAlmostEqual(q.remaining_budget(), 2.0)
        # 3.0 + 2.0 == 5.0 -> fits exactly.
        self.assertIsNotNone(q.enqueue("cap", case_ref="c3", payload={"n": 3},
                                       budget_reservation=2.0))
        self.assertAlmostEqual(q.remaining_budget(), 0.0)

    def test_dead_item_releases_its_budget_reservation(self):
        q = WorkQueue("eng", budget_cap=10.0, worker="w", default_max_attempts=1,
                      clock=self.clock)
        q.enqueue("cap", case_ref="c1", payload={"n": 1}, budget_reservation=5.0)
        self.assertAlmostEqual(q.remaining_budget(), 5.0)
        self.assertEqual(q.fail(q.lease(), "boom"), "dead")  # attempt 1 == max 1
        self.assertAlmostEqual(q.remaining_budget(), 10.0)   # reservation released

    def test_no_cap_means_unbounded_and_no_remaining_budget(self):
        q = WorkQueue("eng", clock=self.clock)
        self.assertIsNone(q.remaining_budget())
        self.assertIsNotNone(q.enqueue("cap", case_ref="c1", payload={"n": 1},
                                       budget_reservation=10_000.0))


# ---------------------------------------------------------------------------
# Concurrency: BEGIN IMMEDIATE must make leasing exclusive
# ---------------------------------------------------------------------------
class ConcurrentLeaseExclusivityTests(_QueueTestBase):
    """Real-threads control for the core of criterion 1: leasing is a
    transactional read-modify-write (BEGIN IMMEDIATE), so under contention no
    item is ever handed to two workers (no duplicate dispatch) and none is
    dropped (no lost work). Uses the real clock + a long lease so nothing
    expires mid-test; items are leased but never completed, so `pending` only
    ever shrinks -- a worker sees None only once every item is claimed."""

    def test_no_item_is_leased_twice_under_concurrency(self):
        import threading

        item_count, worker_count = 30, 8
        producer = WorkQueue("eng", worker="producer", lease_seconds=3600.0)
        for n in range(item_count):
            producer.enqueue("cap", case_ref=f"c{n}", payload={"n": n})

        barrier = threading.Barrier(worker_count)
        leased: list[str] = []
        errors: list[BaseException] = []
        lock = threading.Lock()

        def worker(i: int):
            q = WorkQueue("eng", worker=f"w{i}", lease_seconds=3600.0)
            mine: list[str] = []
            try:
                barrier.wait(timeout=5)
                while True:
                    item = q.lease()
                    if item is None:
                        break
                    mine.append(item.item_id)
            except BaseException as exc:  # noqa: BLE001 -- surface to main thread
                with lock:
                    errors.append(exc)
            finally:
                with lock:
                    leased.extend(mine)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(worker_count)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=20)

        self.assertEqual(errors, [], f"lease raised under concurrency: {errors}")
        self.assertEqual(len(leased), item_count)        # no lost work
        self.assertEqual(len(set(leased)), item_count)   # no item leased twice


# ---------------------------------------------------------------------------
# Store-level transactional guards (below the WorkQueue adapter)
# ---------------------------------------------------------------------------
class StoreLevelGuardTests(_QueueTestBase):
    def _row(self, item_id="wi:1", engagement_id="eng", **kw):
        base = dict(item_id=item_id, engagement_id=engagement_id, case_ref="c",
                    capability="cap", principal="p", payload={"n": 1},
                    priority=0, depends_on=[], budget_reservation=0.0,
                    attempt=0, max_attempts=3,
                    created_at=self.clock(), updated_at=self.clock())
        base.update(kw)
        return base

    def test_enqueue_returns_inserted_then_duplicate(self):
        self.assertEqual(store.enqueue_work_item(self._row()), "inserted")
        self.assertEqual(store.enqueue_work_item(self._row()), "duplicate")

    def test_fail_on_missing_item_reports_missing(self):
        self.assertEqual(store.fail_work_item("wi:nope", now=self.clock()), "missing")

    def test_fail_on_non_leased_item_leaves_it_unchanged(self):
        store.enqueue_work_item(self._row(item_id="wi:x"))
        # pending, never leased -> fail is a no-op that reports current status.
        self.assertEqual(store.fail_work_item("wi:x", error="e", now=self.clock()), "pending")
        row = store.get_work_item("wi:x")
        self.assertEqual(row["attempt"], 0)
        self.assertEqual(row["last_error"], "")

    def test_complete_on_missing_item_is_false(self):
        self.assertFalse(store.complete_work_item("wi:nope", result_ref="r", now=self.clock()))


if __name__ == "__main__":
    unittest.main()
