"""Tests for the V1 live activity feed."""
import unittest

from activity_feed import ActivityFeed


class ActivityFeedTests(unittest.TestCase):
    def setUp(self):
        self.f = ActivityFeed(maxlen=5)

    def test_publish_assigns_monotonic_seq(self):
        a = self.f.publish("dispatch", "one")
        b = self.f.publish("agent_done", "two", agent="sqli")
        self.assertEqual(a.seq, 1)
        self.assertEqual(b.seq, 2)
        self.assertEqual(b.agent, "sqli")

    def test_since_returns_only_newer(self):
        self.f.publish("a", "1")
        self.f.publish("a", "2")
        third = self.f.publish("a", "3")
        out = self.f.since(2)
        self.assertEqual([e["seq"] for e in out["events"]], [3])
        self.assertEqual(out["latest_seq"], third.seq)

    def test_since_zero_returns_all_held(self):
        for i in range(3):
            self.f.publish("a", str(i))
        out = self.f.since(0)
        self.assertEqual(len(out["events"]), 3)

    def test_ring_buffer_bounds_and_reports_dropped(self):
        for i in range(8):  # maxlen 5 -> seq 1..3 age out
            self.f.publish("a", str(i))
        out = self.f.since(1)  # asking for >1, but oldest held is seq 4
        self.assertGreater(out["dropped"], 0)
        self.assertEqual([e["seq"] for e in out["events"]], [4, 5, 6, 7, 8])

    def test_no_dropped_when_caught_up(self):
        for i in range(3):
            self.f.publish("a", str(i))
        out = self.f.since(2)
        self.assertEqual(out["dropped"], 0)

    def test_snapshot_limits(self):
        for i in range(5):
            self.f.publish("a", str(i))
        self.assertEqual(len(self.f.snapshot(limit=2)["events"]), 2)

    def test_publish_never_raises(self):
        # Even with a weird level/detail it returns an event, not an exception.
        ev = self.f.publish("k", "m", level="error", weird={"x": object()})
        self.assertIsNotNone(ev)

    def test_clear(self):
        self.f.publish("a", "1")
        self.f.clear()
        self.assertEqual(self.f.snapshot()["events"], [])


class ActivityEndpointTests(unittest.TestCase):
    def setUp(self):
        import server as server_module
        import activity_feed
        activity_feed.feed.clear()
        self.af = activity_feed
        from fastapi.testclient import TestClient
        self.client = TestClient(server_module.app, base_url="http://localhost")

    def test_endpoint_snapshot_and_since(self):
        self.af.publish("dispatch", "hello", detail={"agents": ["sqli"]})
        r = self.client.get("/activity")
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertTrue(body["events"])
        latest = body["latest_seq"]
        # nothing new since latest
        r2 = self.client.get("/activity", params={"since": latest})
        self.assertEqual(r2.json()["events"], [])


if __name__ == "__main__":
    unittest.main()
