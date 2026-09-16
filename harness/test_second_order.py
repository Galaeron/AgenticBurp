"""Tests for second-order confirmation (V22 SQLi, V17 IDOR) + the chaining
composition rules that identify the plant->trigger (A,B) candidate pairs."""
import asyncio
import unittest

from harness import second_order
from harness import chaining


# --- V22: second-order SQLi boolean differential -----------------------------

class SecondOrderSqliTests(unittest.TestCase):
    def test_confirms_when_read_depends_on_planted_boolean(self):
        """A vulnerable B: the stored value is concatenated into a query, so the
        TRUE marker returns rows and the FALSE marker returns nothing."""
        stored = {"v": ""}

        async def plant(val):
            stored["v"] = val

        async def trigger():
            # simulate: B builds  SELECT ... WHERE note='<stored>'
            # TRUE marker -> the OR makes the whole set match -> many rows;
            # FALSE marker -> nothing matches -> empty.
            if stored["v"].endswith("'1'='1"):
                return "row1 alice\nrow2 bob\nrow3 carol\nrow4 dave"
            return ""

        res = asyncio.run(second_order.confirm_second_order_sqli(plant=plant, trigger=trigger))
        self.assertTrue(res.confirmed, res.evidence)

    def test_not_confirmed_when_read_is_inert(self):
        """A safe B: the stored value is parameterised, so B's response is
        identical regardless of the planted boolean."""
        stored = {"v": ""}

        async def plant(val):
            stored["v"] = val

        async def trigger():
            return "static content, same every time"

        res = asyncio.run(second_order.confirm_second_order_sqli(plant=plant, trigger=trigger))
        self.assertFalse(res.confirmed, res.evidence)

    def test_not_confirmed_on_literal_echo_of_payload(self):
        """R12 NEGATIVE CONTROL: B merely REFLECTS the stored value. The two
        responses differ only because the echoed payloads differ ('1'='1' vs
        '1'='2') -- display, not SQL evaluation. Before the fix this false-confirmed
        (raw similarity < threshold); masking the reflection must prevent that."""
        stored = {"v": ""}

        async def plant(val):
            stored["v"] = val

        async def trigger():
            v = stored["v"]
            return f"{v} | {v} | {v}"   # payload dominates a short response

        res = asyncio.run(second_order.confirm_second_order_sqli(plant=plant, trigger=trigger))
        self.assertFalse(res.confirmed, res.evidence)
        self.assertIn("reflect", res.reason.lower())

    def test_confirmed_when_result_set_changes_despite_reflection(self):
        """The payload IS reflected, but the RESULT SET also changes with the
        boolean -> a genuine second-order SQLi that survives masking."""
        stored = {"v": ""}

        async def plant(val):
            stored["v"] = val

        async def trigger():
            v = stored["v"]
            if v.endswith("'1'='1"):
                return f"echo:{v}\nrow1\nrow2\nrow3\nrow4\nrow5"
            return f"echo:{v}\n0 results"

        res = asyncio.run(second_order.confirm_second_order_sqli(plant=plant, trigger=trigger))
        self.assertTrue(res.confirmed, res.evidence)

    def test_reset_called_between_plants(self):
        calls = {"reset": 0, "plant": 0}

        async def plant(val):
            calls["plant"] += 1

        async def trigger():
            return "same"

        async def reset():
            calls["reset"] += 1

        asyncio.run(second_order.confirm_second_order_sqli(plant=plant, trigger=trigger, reset=reset))
        self.assertEqual(calls["plant"], 2)
        self.assertEqual(calls["reset"], 2)


# --- V17: second-order IDOR (plant as id1, read as id2) ----------------------

class SecondOrderIdorTests(unittest.TestCase):
    def test_confirms_cross_identity_read_of_planted_object(self):
        store = {"obj": ""}

        async def plant(marker):
            store["obj"] = marker  # identity 1 stores it

        async def read_as_other():
            return f"here is the object: {store['obj']}"  # identity 2 sees it -> IDOR

        res = asyncio.run(second_order.confirm_second_order_idor(
            plant=plant, read_as_other=read_as_other))
        self.assertTrue(res.confirmed, res.evidence)

    def test_not_confirmed_when_scoped(self):
        store = {"obj": ""}

        async def plant(marker):
            store["obj"] = marker

        async def read_as_other():
            return "403 forbidden -- not your object"  # properly scoped

        res = asyncio.run(second_order.confirm_second_order_idor(
            plant=plant, read_as_other=read_as_other))
        self.assertFalse(res.confirmed, res.evidence)


# --- composition rules that surface the (A,B) candidate --------------------

class CompositionRuleTests(unittest.TestCase):
    def _detect(self, findings):
        return {f.vulnerability_class for f in chaining.detect(findings)}

    def test_second_order_sqli_chain_composed(self):
        findings = [
            {"url": "https://t.test/api/profile", "vulnerability_class": "mass_assignment",
             "severity": "medium", "confidence": 0.6, "summary": "stored input persists"},
            {"url": "https://t.test/api/search", "vulnerability_class": "sqli",
             "severity": "high", "confidence": 0.6, "summary": "sqli suspected"},
        ]
        sigs = self._detect(findings)
        self.assertIn("potential-attack-chain:second_order_sqli", sigs)

    def test_second_order_idor_chain_composed(self):
        findings = [
            {"url": "https://t.test/api/comments", "vulnerability_class": "stored xss",
             "severity": "medium", "confidence": 0.6, "summary": "stored comment"},
            {"url": "https://t.test/api/tickets/1", "vulnerability_class": "idor",
             "severity": "high", "confidence": 0.6, "summary": "object reachable cross-identity"},
        ]
        sigs = self._detect(findings)
        self.assertIn("potential-attack-chain:second_order_idor", sigs)

    def test_no_second_order_chain_without_a_write(self):
        findings = [
            {"url": "https://t.test/api/search", "vulnerability_class": "sqli",
             "severity": "high", "confidence": 0.6, "summary": "sqli"},
        ]
        sigs = self._detect(findings)
        self.assertNotIn("potential-attack-chain:second_order_sqli", sigs)


class CandidateAndAutoConfirmTests(unittest.TestCase):
    def _findings(self):
        return [
            {"url": "https://t.test/api/profile", "vulnerability_class": "mass_assignment",
             "severity": "medium", "confidence": 0.6, "summary": "stored input persists"},
            {"url": "https://t.test/api/search", "vulnerability_class": "sqli",
             "severity": "high", "confidence": 0.6, "summary": "sqli suspected"},
        ]

    def test_second_order_candidates_structured_pair(self):
        cands = chaining.second_order_candidates(self._findings())
        self.assertTrue(any(c["signature"] == "second_order_sqli" for c in cands))
        c = next(c for c in cands if c["signature"] == "second_order_sqli")
        self.assertEqual(c["kind"], "sqli")
        self.assertEqual(c["a"]["url"], "https://t.test/api/profile")  # the write
        self.assertEqual(c["b"]["url"], "https://t.test/api/search")   # the read

    def test_auto_confirm_folds_confirmed_finding(self):
        cands = chaining.second_order_candidates(self._findings())

        async def confirm_sqli(a_url, b_url):
            return second_order.SecondOrderResult(confirmed=True, reason="boolean differential bit",
                                                  evidence="TRUE vs FALSE diverged")

        async def confirm_idor(a_url, b_url):
            return second_order.SecondOrderResult(confirmed=False, reason="n/a")

        out = asyncio.run(second_order.auto_confirm_candidates(
            cands, confirm_sqli=confirm_sqli, confirm_idor=confirm_idor))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["vulnerability_class"], "second_order_sqli")
        self.assertTrue(out[0]["confirmed"])
        self.assertEqual(out[0]["severity"], "critical")

    def test_auto_confirm_nothing_when_differential_flat(self):
        cands = chaining.second_order_candidates(self._findings())

        async def confirm_sqli(a_url, b_url):
            return second_order.SecondOrderResult(confirmed=False, reason="flat")

        async def confirm_idor(a_url, b_url):
            return second_order.SecondOrderResult(confirmed=False, reason="scoped")

        out = asyncio.run(second_order.auto_confirm_candidates(
            cands, confirm_sqli=confirm_sqli, confirm_idor=confirm_idor))
        self.assertEqual(out, [])

    def test_auto_confirm_scope_gate_and_cap(self):
        cands = chaining.second_order_candidates(self._findings())
        calls = {"n": 0}

        async def confirm_sqli(a_url, b_url):
            calls["n"] += 1
            return second_order.SecondOrderResult(confirmed=False, reason="x")

        async def confirm_idor(a_url, b_url):
            return second_order.SecondOrderResult(confirmed=False, reason="x")

        # scope gate rejects everything -> no confirm call
        out = asyncio.run(second_order.auto_confirm_candidates(
            cands, confirm_sqli=confirm_sqli, confirm_idor=confirm_idor,
            is_allowed=lambda u: False))
        self.assertEqual(out, [])
        self.assertEqual(calls["n"], 0)


if __name__ == "__main__":
    unittest.main()
