"""Tests for the penetration task graph (VulnBot-style dependency DAG)."""
import unittest

from harness import task_graph
from harness.task_graph import TaskGraph, READY, BLOCKED, DONE, FAILED, SKIPPED


class TaskGraphTests(unittest.TestCase):
    def test_add_ready_by_default(self):
        g = TaskGraph()
        t = g.add("analyze", "/x", reason="test it")
        self.assertEqual(t.status, READY)
        self.assertEqual(len(g.ready()), 1)

    def test_add_idempotent(self):
        g = TaskGraph()
        g.add("analyze", "/x")
        g.add("analyze", "/x")
        self.assertEqual(len(g.tasks), 1)

    def test_dependency_blocks_until_done(self):
        g = TaskGraph()
        a = g.add("obtain", "cred")
        g.add("recrawl", "admin", depends_on=[a.id])
        self.assertEqual(len(g.ready()), 1)          # only the obtain
        self.assertEqual(len(g.blocked()), 1)        # recrawl blocked
        g.mark(a.id, DONE)
        self.assertEqual(len(g.blocked()), 0)        # unlocked
        self.assertEqual({t.target for t in g.ready()}, {"admin"})  # cred is DONE, admin now ready

    def test_failed_dependency_keeps_dependent_blocked(self):
        g = TaskGraph()
        a = g.add("obtain", "cred")
        g.add("recrawl", "admin", depends_on=[a.id])
        g.mark(a.id, FAILED)
        self.assertEqual(len(g.blocked()), 1)        # a prereq that FAILED does not unlock
        self.assertTrue(g.failed())

    def test_needs_blocks_until_resolved(self):
        g = TaskGraph()
        t = g.add("obtain", "admin-session", needs="human credentials")
        self.assertEqual(t.status, BLOCKED)
        g.resolve_need(t.id)
        self.assertEqual(t.status, READY)

    def test_needs_and_dependency_both_required(self):
        g = TaskGraph()
        dep = g.add("confirm", "sqli")
        t = g.add("obtain", "creds", depends_on=[dep.id], needs="human")
        g.resolve_need(t.id)                          # need cleared, but dep still pending
        self.assertEqual(t.status, BLOCKED)
        g.mark(dep.id, DONE)
        g.resolve_need(t.id)
        self.assertEqual(t.status, READY)

    def test_mark_by_kind_target(self):
        g = TaskGraph()
        g.add("recrawl_area", "/admin")
        g.mark_by("recrawl_area", "/admin", DONE)
        self.assertEqual(g.tasks["recrawl_area:/admin"].status, DONE)

    def test_finished_task_not_resurrected(self):
        g = TaskGraph()
        t = g.add("analyze", "/x")
        g.mark(t.id, DONE)
        g.add("analyze", "/x")                        # re-add is a no-op
        self.assertEqual(g.tasks["analyze:/x"].status, DONE)

    def test_roundtrip(self):
        g = TaskGraph()
        a = g.add("obtain", "cred")
        g.add("recrawl", "admin", depends_on=[a.id], needs="")
        g.mark(a.id, DONE)
        g2 = TaskGraph.from_dict(g.to_dict())
        self.assertEqual(len(g2.tasks), 2)
        self.assertEqual({t.target for t in g2.ready()}, {"admin"})  # cred DONE, admin ready

    def test_skipped_required_dependency_keeps_dependent_blocked(self):
        # weakness #14: skipping a REQUIRED prerequisite must NOT unlock dependents.
        g = TaskGraph()
        a = g.add("obtain", "admin-session")                     # required, not optional
        g.add("confirm", "admin-api", depends_on=[a.id])
        g.mark(a.id, SKIPPED)
        self.assertEqual(g.tasks["confirm:admin-api"].status, BLOCKED)

    def test_skipped_optional_dependency_unlocks_dependent(self):
        g = TaskGraph()
        a = g.add("recon", "banner", optional=True)              # optional prerequisite
        g.add("analyze", "x", depends_on=[a.id])
        g.mark(a.id, SKIPPED)
        self.assertEqual(g.tasks["analyze:x"].status, READY)

    def test_optional_round_trips(self):
        from harness.task_graph import Task
        t = Task(id="recon:x", kind="recon", target="x", optional=True)
        self.assertTrue(Task.from_dict(t.to_dict()).optional)


if __name__ == "__main__":
    unittest.main()
