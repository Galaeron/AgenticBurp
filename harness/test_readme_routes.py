"""The README's endpoint table and its Burp-plane dispatch paragraph agree with harness/server.py.

c3 (ARC-4, ARC-12) added `POST /test-plans/{id}/dispatch` and typed refusal codes. The README lists every
route in its table in `METHOD /path` form; this module requires each to be a real route of server.py (a
route renamed or removed fails here), the dispatch route to be listed, and the refusal table to be the
(status, reason) set server.py maps, so a new or renamed code fails until the README follows.
"""
import ast
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = (ROOT / "README.md").read_text(encoding="utf-8")
SERVER = ast.parse((ROOT / "harness/server.py").read_text(encoding="utf-8"))


def _normal(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "{}", path)


def server_routes() -> set[tuple[str, str]]:
    found = set()
    for node in ast.walk(SERVER):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                if (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
                        and isinstance(dec.func.value, ast.Name) and dec.func.value.id == "app"
                        and dec.args and isinstance(dec.args[0], ast.Constant)):
                    found.add((dec.func.attr.upper(), _normal(dec.args[0].value)))
    return found


def plane_refusals() -> dict[str, int]:
    """reason -> HTTP status, from the `_PLANE_REFUSALS` literal in server.py."""
    for node in ast.walk(SERVER):
        if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "_PLANE_REFUSALS" for t in node.targets):
            table = ast.literal_eval(node.value)
            return {reason: status for reason, (status, _message) in table.items()}
    raise AssertionError("server.py has no _PLANE_REFUSALS")


def readme_routes(text: str) -> set[tuple[str, str]]:
    """(METHOD, normalised path) for each `METHOD /path` code span in the endpoint table's first column."""
    start = text.index("| Endpoint | Purpose |")
    rows = []
    for line in text[start:].splitlines()[2:]:
        if not line.startswith("|"):
            break
        rows.append(line.split("|")[1])
    return {(m[1], _normal(m[2])) for row in rows for m in re.finditer(r"`(GET|POST|PUT|DELETE) (/[^`]*)`", row)}


def readme_refusals(text: str) -> dict[str, int]:
    start = text.index("| Status | Reason codes |")
    out = {}
    for line in text[start:].splitlines()[2:]:
        match = re.fullmatch(r"\|\s*(\d{3})\s*\|(.+)\|", line)
        if not match:
            break
        for reason in re.findall(r"`([a-z_]+)`", match[2]):
            out[reason] = int(match[1])
    return out


class ReadmeRouteTests(unittest.TestCase):
    def test_every_route_in_the_readme_table_is_a_real_route(self):
        listed, real = readme_routes(README), server_routes()
        self.assertTrue(listed)
        self.assertEqual(sorted(listed - real), [])

    def test_the_dispatch_route_is_listed(self):
        self.assertIn(("POST", "/test-plans/{}/dispatch"), readme_routes(README))
        self.assertIn(("POST", "/validation-results"), readme_routes(README))

    def test_the_guard_notices_a_route_that_does_not_exist(self):
        stale = README.replace("`POST /test-plans/{id}/dispatch`", "`POST /test-plans/{id}/send`")
        self.assertIn(("POST", "/test-plans/{}/send"), readme_routes(stale) - server_routes())


class RefusalTableTests(unittest.TestCase):
    def test_the_readme_refusal_codes_are_the_ones_the_server_maps(self):
        self.assertEqual(readme_refusals(README), plane_refusals())

    def test_the_guard_notices_a_dropped_or_renamed_code(self):
        dropped = README.replace("`plan_terminal`", "`plan_closed`")
        self.assertNotEqual(readme_refusals(dropped), plane_refusals())
        moved = README.replace("| 404 | `unknown_plan` |", "| 409 | `unknown_plan` |")
        self.assertNotEqual(readme_refusals(moved), plane_refusals())

    def test_the_paragraph_names_the_policy_the_route_returns(self):
        for needle in ("dispatch_nonce", "active_enabled", "allow_mutating_replay", "request_budget", "runs.max_requests"):
            self.assertIn(needle, README)


if __name__ == "__main__":
    unittest.main()
