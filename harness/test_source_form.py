"""Tests for the shared in-session source-form replay primitive (LB-1).

harness.validators.source_form.fetch_source_form is the single place that now
does what stored_xss_validator, file_upload_validator, auth_sequence_validator
and client_trust_validator each used to reimplement: GET a candidate source
page IN THE CALLER'S SESSION, extract its forms, and hand them to a
caller-supplied `select` to pick the form (or move to the next candidate).

Offline and deterministic: a fake/stub transport stands in for
GatedAsyncClient, so no live network is exercised.
"""
import unittest

from harness import global_throttle
from harness.feature_workflow import FormAction, FormField
from harness.validators.source_form import CSRF_FIELD_RE, SourceForm, fetch_source_form


class _Resp:
    def __init__(self, text: str, content_type: str = "text/html"):
        self.text = text
        self._headers = {"content-type": content_type}

    @property
    def headers(self):
        return self._headers


class _FakeClient:
    """Records every GET it receives and serves a canned page per URL."""

    def __init__(self, pages: dict[str, _Resp]):
        self._pages = pages
        self.calls: list[tuple[str, str, dict | None]] = []

    async def request(self, method, url, *, headers=None, **kwargs):
        self.calls.append((method, url, headers))
        if url not in self._pages:
            raise LookupError(f"fake client has no page for {url}")
        return self._pages[url]


_STALE_TOKEN = "stale-session-token"
_FRESH_TOKEN = "fresh-session-token"

_LOGIN_PAGE_HTML = f"""
<html><body>
<form method="POST" action="/login">
  <input type="hidden" name="csrf" value="{_FRESH_TOKEN}">
  <input type="text" name="username" value="">
  <input type="password" name="password" value="">
</form>
</body></html>
"""

_NO_FORM_HTML = "<html><body><p>Nothing here -- no form on this page.</p></body></html>"


def setUpModule():
    global_throttle.configure(0)


class FetchSourceFormTests(unittest.IsolatedAsyncioTestCase):
    async def test_csrf_refreshed_from_freshly_get_source_page_not_stale_captured_one(self):
        """(a) The CSRF field value returned comes from the page this call just
        GOT, never the stale value the validator captured during the crawl."""
        client = _FakeClient({"https://shop.test/login": _Resp(_LOGIN_PAGE_HTML)})

        def select(forms):
            return next((f for f in forms if f.action.endswith("/login")), None)

        found = await fetch_source_form(client, ["https://shop.test/login"], {}, select)
        self.assertIsNotNone(found)
        self.assertIsInstance(found, SourceForm)
        csrf_field = next(f for f in found.form.fields if CSRF_FIELD_RE.search(f.name))
        self.assertEqual(csrf_field.value, _FRESH_TOKEN)
        self.assertNotEqual(csrf_field.value, _STALE_TOKEN)

    async def test_structural_non_csrf_fields_are_preserved(self):
        """(b) Non-CSRF structural fields (names, types) on the matched form
        come through unchanged -- the helper doesn't drop or rename them."""
        client = _FakeClient({"https://shop.test/login": _Resp(_LOGIN_PAGE_HTML)})

        def select(forms):
            return next((f for f in forms if f.action.endswith("/login")), None)

        found = await fetch_source_form(client, ["https://shop.test/login"], {}, select)
        names = {f.name for f in found.form.fields}
        self.assertEqual(names, {"csrf", "username", "password"})
        types = {f.name: f.type for f in found.form.fields}
        self.assertEqual(types["password"], "password")
        self.assertEqual(types["csrf"], "hidden")

    async def test_source_page_derivation_gets_the_right_derived_url(self):
        """(c) fetch_source_form GETs the candidate URL(s) given to it, in
        order, in the caller's own client/session -- nothing else."""
        client = _FakeClient({
            "https://shop.test/referer-page": _Resp(_NO_FORM_HTML),
            "https://shop.test/login": _Resp(_LOGIN_PAGE_HTML),
        })

        def select(forms):
            return next((f for f in forms if f.action.endswith("/login")), None)

        found = await fetch_source_form(
            client, ["https://shop.test/referer-page", "https://shop.test/login"], {}, select)
        self.assertIsNotNone(found)
        self.assertEqual(found.source_url, "https://shop.test/login")
        # Both candidates were GET-ed, in order, before the match was found.
        requested_urls = [url for _method, url, _headers in client.calls]
        self.assertEqual(requested_urls,
                         ["https://shop.test/referer-page", "https://shop.test/login"])

    async def test_no_matching_form_yields_no_fabricated_result(self):
        """Negative control: a source page with no matching form must not
        fabricate a form/body -- fetch_source_form returns None so the caller
        falls back to its own captured-body behavior."""
        client = _FakeClient({"https://shop.test/blog": _Resp(_NO_FORM_HTML)})

        def select(forms):
            return next((f for f in forms if f.action.endswith("/comment")), None)

        found = await fetch_source_form(client, ["https://shop.test/blog"], {}, select)
        self.assertIsNone(found)

    async def test_non_html_candidate_is_skipped(self):
        """A JSON-API candidate (no HTML form to mine) is skipped, not treated
        as a match -- mirrors each validator's original content-type guard."""
        client = _FakeClient({
            "https://shop.test/api/login": _Resp('{"ok": true}', content_type="application/json"),
        })

        def select(forms):
            return forms[0] if forms else None

        found = await fetch_source_form(client, ["https://shop.test/api/login"], {}, select)
        self.assertIsNone(found)

    async def test_select_rejecting_every_candidate_falls_through_to_none(self):
        client = _FakeClient({
            "https://shop.test/a": _Resp(_LOGIN_PAGE_HTML),
            "https://shop.test/b": _Resp(_LOGIN_PAGE_HTML),
        })
        found = await fetch_source_form(
            client, ["https://shop.test/a", "https://shop.test/b"], {}, lambda forms: None)
        self.assertIsNone(found)
        self.assertEqual(len(client.calls), 2)  # tried both candidates


class FormActionShapeSanityTests(unittest.TestCase):
    """Sanity check that the dataclasses this module relies on still shape the
    way the four validators assume (name/type/value, method/action/fields)."""

    def test_formaction_and_formfield_shape(self):
        form = FormAction(method="POST", action="https://x.test/f", fields=[
            FormField(name="csrf", type="hidden", value="t"),
        ])
        self.assertEqual(form.fields[0].name, "csrf")
        self.assertEqual(form.fields[0].type, "hidden")
        self.assertEqual(form.fields[0].value, "t")


if __name__ == "__main__":
    unittest.main()
