"""Tests for burp_sitemap: parsing a Burp site-map export into analyzable
HttpExchanges, with the credential-bearing shapes (pickle cookie, XML body,
URL param) preserved -- the whole reason to import a human's browsing."""
import base64
import unittest

from harness import burp_sitemap
from harness import engagement


def _item_xml(method, path, request_raw, response_raw, *, host="target.test",
              protocol="https", port=443, status=200, b64=True, mimetype="JSON",
              url=None):
    def _enc(raw):
        if b64:
            return base64.b64encode(raw.encode()).decode(), "true"
        return raw, "false"
    req_text, req_attr = _enc(request_raw)
    resp_text, resp_attr = _enc(response_raw)
    url = url or f"{protocol}://{host}{path}"
    return f"""  <item>
    <url><![CDATA[{url}]]></url>
    <host ip="127.0.0.1">{host}</host>
    <port>{port}</port>
    <protocol>{protocol}</protocol>
    <method><![CDATA[{method}]]></method>
    <path><![CDATA[{path}]]></path>
    <request base64="{req_attr}"><![CDATA[{req_text}]]></request>
    <status>{status}</status>
    <mimetype>{mimetype}</mimetype>
    <response base64="{resp_attr}"><![CDATA[{resp_text}]]></response>
    <comment></comment>
  </item>"""


def _doc(*items):
    return "<?xml version=\"1.0\"?>\n<items burpVersion=\"2023\">\n" + "\n".join(items) + "\n</items>"


class ParseTests(unittest.TestCase):
    def test_parses_get_with_query_and_headers(self):
        req = ("GET /api/tickets/1?next=/dashboard HTTP/1.1\r\n"
               "Host: target.test\r\n"
               "Cookie: session=abc123\r\n"
               "Accept: application/json\r\n\r\n")
        resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"id\":1}"
        items = burp_sitemap.parse_sitemap(_doc(_item_xml(
            "GET", "/api/tickets/1", req, resp)))
        self.assertEqual(len(items), 1)
        it = items[0]
        self.assertEqual(it.method, "GET")
        self.assertEqual(it.status, 200)
        self.assertEqual(it.request_headers.get("Cookie"), "session=abc123")
        # request-line target carries the query the <path> element strips
        self.assertIn("next=/dashboard", it.path)
        self.assertEqual(it.response_body, '{"id":1}')

    def test_multiple_set_cookie_headers_preserved(self):
        # weakness #9: repeated Set-Cookie headers must not collapse to one.
        _, headers, _ = burp_sitemap._split_message(
            "HTTP/1.1 200 OK\r\nSet-Cookie: a=1; Path=/\r\nSet-Cookie: b=2; HttpOnly\r\n\r\nbody")
        self.assertIn("a=1", headers["Set-Cookie"])
        self.assertIn("b=2", headers["Set-Cookie"])   # both cookies survive

    def test_repeated_non_cookie_header_combined(self):
        _, headers, _ = burp_sitemap._split_message(
            "HTTP/1.1 200 OK\r\nVia: 1.1 a\r\nVia: 1.1 b\r\n\r\n")
        self.assertEqual(headers["Via"], "1.1 a, 1.1 b")

    def test_plaintext_request_response(self):
        req = "POST /api/login HTTP/1.1\nHost: target.test\n\nuser=alice"
        resp = "HTTP/1.1 401 Unauthorized\n\n"
        items = burp_sitemap.parse_sitemap(_doc(_item_xml(
            "POST", "/api/login", req, resp, b64=False, status=401)))
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].method, "POST")
        self.assertEqual(items[0].request_body, "user=alice")
        self.assertEqual(items[0].status, 401)

    def test_malformed_item_skipped_not_fatal(self):
        good = _item_xml("GET", "/ok", "GET /ok HTTP/1.1\r\nHost: target.test\r\n\r\n",
                         "HTTP/1.1 200 OK\r\n\r\nok")
        # A second item with a non-numeric port + empty request should still parse
        # (defensive) and not sink the good one.
        bad = ("  <item><method><![CDATA[GET]]></method><host>target.test</host>"
               "<port>notaport</port><protocol>https</protocol><path>/bad</path>"
               "<request base64=\"false\"><![CDATA[]]></request>"
               "<response base64=\"false\"><![CDATA[]]></response></item>")
        items = burp_sitemap.parse_sitemap(_doc(good, bad))
        self.assertGreaterEqual(len(items), 1)
        self.assertTrue(any(i.path == "/ok" for i in items))

    def test_non_burp_xml_raises(self):
        with self.assertRaises(ValueError):
            burp_sitemap.parse_sitemap("not xml at all <<<")

    def test_xxe_doctype_is_rejected(self):
        # An XXE payload (external entity) must be refused before parsing, not
        # resolved -- the Bandit B313 hardening.
        xxe = ('<?xml version="1.0"?>\n'
               '<!DOCTYPE items [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>\n'
               '<items><item><path>&xxe;</path></item></items>')
        with self.assertRaises(ValueError) as ctx:
            burp_sitemap.parse_sitemap(xxe)
        self.assertIn("DTD/ENTITY", str(ctx.exception))

    def test_billion_laughs_entity_declaration_rejected(self):
        bomb = ('<?xml version="1.0"?>\n'
                '<!DOCTYPE lolz [ <!ENTITY lol "lol"> ]>\n'
                '<items><item><path>&lol;</path></item></items>')
        with self.assertRaises(ValueError):
            burp_sitemap.parse_sitemap(bomb)


class ExchangeTests(unittest.TestCase):
    def test_url_reconstructed_without_default_port(self):
        req = "GET /a HTTP/1.1\r\nHost: target.test\r\n\r\n"
        resp = "HTTP/1.1 200 OK\r\n\r\nx"
        # no <url> element -> reconstruct from protocol/host/port/path
        item_xml = _item_xml("GET", "/a", req, resp, url="")
        exs = burp_sitemap.load_exchanges(_doc(item_xml), allowed_hosts=["target.test"])
        self.assertEqual(len(exs), 1)
        self.assertEqual(exs[0].url, "https://target.test/a")

    def test_scope_gate_drops_out_of_scope(self):
        req = "GET /x HTTP/1.1\r\nHost: evil.test\r\n\r\n"
        resp = "HTTP/1.1 200 OK\r\n\r\nx"
        xml = _doc(
            _item_xml("GET", "/x", req, resp, host="target.test"),
            _item_xml("GET", "/x", req, resp, host="evil.test",
                      url="https://evil.test/x"),
        )
        exs = burp_sitemap.load_exchanges(xml, allowed_hosts=["target.test"])
        self.assertEqual(len(exs), 1)
        self.assertEqual(exs[0].url, "https://target.test/x")

    def test_pickle_cookie_preserved_for_deser_leg(self):
        """The V26 case: a base64-pickle session cookie only exists in a real
        browsing session. Importing it must preserve the cookie so the
        deserialization leg's sink detector recognises it."""
        import pickle
        blob = base64.b64encode(pickle.dumps({"user": "alice"})).decode()
        req = (f"GET /dashboard HTTP/1.1\r\nHost: target.test\r\n"
               f"Cookie: session={blob}\r\n\r\n")
        resp = "HTTP/1.1 200 OK\r\n\r\n<html>hi</html>"
        exs = burp_sitemap.load_exchanges(
            _doc(_item_xml("GET", "/dashboard", req, resp)),
            allowed_hosts=["target.test"])
        self.assertEqual(len(exs), 1)
        # the deser leg's own sink detector must see the pickle cookie
        from harness.validators.deserialization_oob_validator import DeserializationOobValidator
        sinks = DeserializationOobValidator()._sink_candidates(exs[0])
        self.assertTrue(any(loc == "cookie" for loc, _ in sinks),
                        "imported pickle cookie was not recognised as a deser sink")

    def test_xml_body_preserved_for_xxe_shape(self):
        req = ("POST /api/tickets/import HTTP/1.1\r\nHost: target.test\r\n"
               "Content-Type: application/xml\r\n\r\n<?xml version=\"1.0\"?><ticket/>")
        resp = "HTTP/1.1 200 OK\r\n\r\nok"
        exs = burp_sitemap.load_exchanges(
            _doc(_item_xml("POST", "/api/tickets/import", req, resp, mimetype="XML")),
            allowed_hosts=["target.test"])
        self.assertEqual(len(exs), 1)
        self.assertTrue(exs[0].request_body.lstrip().startswith("<?xml"))
        self.assertEqual(exs[0].request_headers.get("Content-Type"), "application/xml")


class SeedStateTests(unittest.TestCase):
    def test_seeds_surface_endpoints(self):
        req1 = "GET /api/tickets/1 HTTP/1.1\r\nHost: target.test\r\n\r\n"
        resp1 = "HTTP/1.1 200 OK\r\n\r\n{\"id\":1,\"body\":\"data\"}"
        req2 = "GET /api/admin/users HTTP/1.1\r\nHost: target.test\r\n\r\n"
        resp2 = "HTTP/1.1 200 OK\r\n\r\n[{\"u\":1}]"
        exs = burp_sitemap.load_exchanges(
            _doc(_item_xml("GET", "/api/tickets/1", req1, resp1),
                 _item_xml("GET", "/api/admin/users", req2, resp2)),
            allowed_hosts=["target.test"])
        state = engagement.EngagementState(host="target.test")
        n = burp_sitemap.seed_engagement_state(state, exs)
        self.assertEqual(n, 2)
        # object-scoped path collapsed to {id}
        keys = set(state.endpoints.keys())
        self.assertIn("GET /api/tickets/{id}", keys)
        self.assertIn("GET /api/admin/users", keys)
        ep = state.endpoints["GET /api/tickets/{id}"]
        self.assertTrue(ep.object_scoped)
        self.assertIn("imported:burp", ep.reachable_roles)


if __name__ == "__main__":
    unittest.main()
