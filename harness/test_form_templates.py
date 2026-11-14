"""Forms on fetched HTML documents become request templates (engagement.form_templates).

The fixture is a generic loopback app. Its shell has no `<a href>` at all; its
bundle names a few server-rendered pages by path (as an SPA references the pages it
sends the user to), so the role crawl fetches them while the HTML crawler never
reaches one through a link -- the r9 shape, where a page fetched thousands of times
never had its forms captured:
  - /account/profile: a filled edit form (POST) with a hidden anti-CSRF token, a
    select and a textarea; resubmitting it unchanged re-saves the same values;
  - /account/notes: a create-shaped POST form (empty textarea): an unchanged submit
    would create, so it cannot be restored;
  - /account/stamp: a filled POST form whose server rewrites a field on every save
    (the change is not undone by resubmitting);
  - /account/lookup: a GET form;
  - /account/secure: a form with a password field;
  - /account/about: a page with no form.

Covered here, through build_engagement (the production caller):
  - the templates, hidden token preserved in the template and its value in no log
    line or summary; the no-forms page produces nothing;
  - the switch off: no template, no POST;
  - baseline in passive mode (writes off): nothing submitted, each POST form skipped
    with the reason;
  - baseline with writes on: the edit form submitted once unchanged and marked
    restored after the re-read; the create-shaped form skipped with its reason; the
    rewriting form marked restore_failed with the changed field named;
plus the FormAction helpers that build a submission from a parsed form.
"""
import asyncio
import json
import logging
import os
import secrets
import shutil
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import yaml

from harness import cache, engagement_builder, feature_workflow, form_capture, store
from harness.role_crawl import RoleSession

_HARNESS = Path(__file__).resolve().parent
LOW = RoleSession("user", {"Authorization": "Bearer low-token"}, name="low-user")
TOKEN = "tok-" + secrets.token_hex(12)

_SHELL = """<!doctype html><html><head><title>Desk</title></head>
<body><main id="app"></main><script src="/static/app.js"></script></body></html>"""
_APP_JS = """(function () {
  var pages = {profile: "/account/profile", notes: "/account/notes",
               stamp: "/account/stamp", lookup: "/account/lookup",
               secure: "/account/secure", about: "/account/about"};
  fetch("/api/status").then(function (r) { return r.json(); });
  window.deskPages = pages;
})();
"""


class _Handler(BaseHTTPRequestHandler):
    posts: list = []
    store: dict = {}

    @classmethod
    def reset(cls):
        cls.posts = []
        cls.store = {"name": "Ada", "theme": "dark", "bio": "line one\nline two",
                     "label": "v1", "rev": 1}

    def _page(self, path):
        s = _Handler.store
        token = f'<input type="hidden" name="csrf_token" value="{TOKEN}">'
        if path == "/account/profile":
            return (f"<html><body><form method='post' action='/account/profile'>{token}"
                    f"<input name='display_name' value='{s['name']}'>"
                    "<select name='theme'>"
                    + "".join(f"<option{' selected' if t == s['theme'] else ''}>{t}</option>"
                              for t in ("light", "dark"))
                    + f"</select><textarea name='bio'>{s['bio']}</textarea>"
                    "<button type='submit' name='save' value='1'>Save</button>"
                    "</form></body></html>")
        if path == "/account/notes":
            return (f"<html><body><form method='post' action='/account/notes'>{token}"
                    "<textarea name='note'></textarea><button>Add</button></form></body></html>")
        if path == "/account/stamp":
            return (f"<html><body><form method='post' action='/account/stamp'>{token}"
                    f"<input name='label' value='{s['label']}'><button>Save</button>"
                    "</form></body></html>")
        if path == "/account/lookup":
            return ("<html><body><form action='/account/lookup'><input name='ref' value=''>"
                    "</form></body></html>")
        if path == "/account/secure":
            return (f"<html><body><form method='post' action='/account/secure'>{token}"
                    "<input type='password' name='current' value='hunter2'>"
                    "<input name='email' value='a@example.test'></form></body></html>")
        if path == "/account/about":
            return "<html><body><h1>About</h1><p>No forms here.</p></body></html>"
        return None

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/":
            return self._reply(200, _SHELL, "text/html")
        if path == "/static/app.js":
            return self._reply(200, _APP_JS, "application/javascript")
        if path == "/api/status":
            return self._reply(200, json.dumps({"ok": True}), "application/json")
        page = self._page(path)
        if page is None:
            return self._reply(404, "", "text/plain")
        self._reply(200, page, "text/html; charset=utf-8")

    def do_POST(self):
        path = urlsplit(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        form = {k: v[0] for k, v in parse_qs(self.rfile.read(length).decode(),
                                              keep_blank_values=True).items()}
        _Handler.posts.append((path, sorted(form)))
        if form.get("csrf_token") != TOKEN:
            return self._reply(403, "bad token", "text/plain")
        s = _Handler.store
        if path == "/account/profile":
            s.update(name=form.get("display_name", ""), theme=form.get("theme", ""),
                     bio=form.get("bio", ""))
        elif path == "/account/stamp":
            s["rev"] += 1
            s["label"] = f"v{s['rev']}"     # the server rewrites the field on every save
        self._reply(200, "<html><body>saved</body></html>", "text/html")

    def _reply(self, code, text, ctype):
        body = text.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _config(*, writes: bool) -> dict:
    with open(_HARNESS / "config.yaml") as f:
        cfg = yaml.safe_load(f) or {}
    cfg.setdefault("coordinator", {})["cloud_primary"] = False
    for name in ("autonomous_discovery", "github_advisories", "kev_check", "package_registry_checks"):
        cfg.setdefault(name, {})["enabled"] = False
    cfg.setdefault("server", {})["allowed_hosts"] = ["127.0.0.1"]
    cfg.setdefault("validators", {}).update(active_enabled=writes, allow_mutating_replay=writes)
    return cfg


# --------------------------------------------------------------------------
# FormAction helpers
# --------------------------------------------------------------------------

class FormActionHelpersTest(unittest.TestCase):
    _HTML = """<form method="post" action="/save" enctype="multipart/form-data">
      <input type="hidden" name="t" value="abc">
      <input name="title" value="Hello &amp; bye">
      <input type="checkbox" name="opt" checked><input type="checkbox" name="off" value="y">
      <input type="radio" name="r" value="a"><input type="radio" name="r" value="b" checked>
      <input name="gone" value="x" disabled>
      <input type="password" name="pw" value="secret">
      <input type="file" name="doc" accept=".txt,image/png">
      <textarea name="body">
first</textarea>
      <input type="submit" name="go" value="Go"><input type="submit" name="other" value="No">
    </form>"""

    def test_submission_follows_the_browser_rules(self):
        form = feature_workflow.extract_forms(self._HTML, "http://app.test/page")[0]
        entries = form.submission_entries()
        names = [n for n, _v, _f in entries]
        self.assertEqual(names, ["t", "title", "opt", "r", "pw", "doc", "body", "go"])
        values = {n: v for n, v, _f in entries}
        self.assertEqual(values["title"], "Hello & bye")
        self.assertEqual(values["opt"], "on")
        self.assertEqual(values["r"], "b")
        self.assertEqual(values["pw"], "")            # a password value is never carried
        self.assertEqual(values["body"], "first")
        self.assertEqual([n for n, _v, f in entries if f], ["doc"])
        self.assertIn({"name": "pw", "type": "password"}, form.field_schema())
        self.assertNotIn("secret", json.dumps(form.field_schema()))
        self.assertIn({"name": "doc", "type": "file", "accept": ".txt,image/png"},
                      form.field_schema())

    def test_current_request_builds_multipart_urlencoded_and_get(self):
        form = feature_workflow.extract_forms(self._HTML, "http://app.test/page")[0]
        url, body, ctype = form.current_request()
        self.assertEqual(url, "http://app.test/save")
        self.assertTrue(ctype.startswith("multipart/form-data; boundary="))
        self.assertIn('name="doc"; filename=""', body)
        self.assertIn("abc", body)
        get = feature_workflow.extract_forms(
            "<form action='/find?old=1#x'><input name='q' value='a b'></form>",
            "http://app.test/")[0]
        self.assertEqual(get.current_request(), ("http://app.test/find?q=a+b", "", ""))


# --------------------------------------------------------------------------
# Through build_engagement
# --------------------------------------------------------------------------

class BuildEngagementFormTemplatesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="form_templates_")
        cls._orig_store_db, cls._orig_cache = store._DB_PATH, cache._cache
        store._DB_PATH = Path(cls._tmp) / "state.db"
        cache.init_cache(db_path=os.path.join(cls._tmp, "cache.db"))
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        store._DB_PATH, cache._cache = cls._orig_store_db, cls._orig_cache
        shutil.rmtree(cls._tmp, ignore_errors=True)

    def _build(self, form_config, *, writes=False, seeds=None):
        from harness.orchestrator_helpers import per_run_gate_config
        from harness.run_context import RunContext
        cfg = _config(writes=writes)
        _Handler.reset()
        out = {}

        async def build():
            async with RunContext.create(allowed_hosts=["127.0.0.1"], config=cfg,
                                         gate_config=per_run_gate_config(cfg)) as ctx:
                state, result = await engagement_builder.build_engagement(
                    self.base, [LOW], allowed_hosts=["127.0.0.1"], crawl_max_pages=6,
                    active_discovery=False, run_context=ctx,
                    **({"seed_exchanges": seeds} if seeds else {}),
                    **({"form_templates_config": form_config} if form_config is not None else {}))
                out["changes"] = ctx.change_log.entries() if ctx.change_log else []
                return state, result

        with self.assertLogs(level="DEBUG") as logs:
            logging.getLogger("harness.form_capture").debug("form templates test start")
            state, result = asyncio.run(build())
        out["log"] = "\n".join(logs.output)
        return state, result, out

    @staticmethod
    def _templates(result, source=form_capture.TEMPLATE_SOURCE):
        return {(c["method"], urlsplit(c["url"]).path): c for c in result.captured
                if c.get("capture_source") == source}

    def test_forms_become_templates_with_the_token_kept_and_never_logged(self):
        state, result, out = self._build({"enabled": True})
        templates = self._templates(result)
        self.assertEqual(set(templates), {("POST", "/account/profile"), ("POST", "/account/notes"),
                                          ("POST", "/account/stamp"), ("GET", "/account/lookup")})
        profile = templates[("POST", "/account/profile")]
        body = parse_qs(profile["request_body"], keep_blank_values=True)
        self.assertEqual(body["csrf_token"], [TOKEN])          # hidden field as rendered
        self.assertEqual(body["display_name"], ["Ada"])
        self.assertEqual(body["theme"], ["dark"])
        self.assertEqual(body["bio"], ["line one\nline two"])
        self.assertEqual(body["save"], ["1"])
        self.assertIsNone(profile["response_status"])
        self.assertEqual(profile["request_headers"]["Authorization"], "Bearer low-token")
        self.assertEqual(profile["request_headers"]["Content-Type"],
                         "application/x-www-form-urlencoded")
        self.assertTrue(profile["request_headers"]["Referer"].endswith("/account/profile"))
        self.assertIn("csrf_token:hidden", profile["analyst_note"])
        self.assertNotIn(TOKEN, profile["analyst_note"])
        # The endpoint's replay template carries the real form body.
        ep = state.endpoints.get("POST /account/profile")
        self.assertIsNotNone(ep, sorted(state.endpoints))
        self.assertIn("csrf_token=", ep.template["body"])
        self.assertEqual(templates[("GET", "/account/lookup")]["url"],
                         self.base + "/account/lookup?ref=")
        # The token value is in no log line and not in the reported summary.
        self.assertIn("form templates", out["log"])
        self.assertNotIn(TOKEN, out["log"])
        self.assertNotIn(TOKEN, json.dumps(result.form_templates))
        # Passive: nothing was submitted.
        self.assertEqual(_Handler.posts, [])

    def test_control_password_and_no_form_pages_produce_no_template(self):
        # The role crawl keeps no capture of a page with a password field (it reads
        # as a login page), so the page comes in as a supplied browser capture.
        from harness.models import HttpExchange
        _Handler.reset()
        secure = HttpExchange(
            url=self.base + "/account/secure", method="GET",
            request_headers={"Authorization": "Bearer low-token"}, response_status=200,
            response_headers={"Content-Type": "text/html"},
            response_body=_Handler._page(None, "/account/secure"))
        _state, result, out = self._build({"enabled": True}, seeds=[secure])
        skipped = {s["form"]: s["reason"] for s in result.form_templates["skipped"]}
        self.assertIn("password value is never stored", skipped["POST /account/secure"])
        templated = [c for c in result.captured
                     if c.get("capture_source") == form_capture.TEMPLATE_SOURCE]
        self.assertNotIn("/account/secure", [urlsplit(c["url"]).path for c in templated])
        self.assertNotIn("hunter2", json.dumps(templated))
        self.assertNotIn("hunter2", out["log"])
        # The page with no form: fetched and captured, but nothing is mined from it.
        self.assertTrue(any(urlsplit(c["url"]).path == "/account/about" for c in result.captured))
        sources = {t["source"] for t in result.form_templates["templates"]}
        self.assertNotIn("/account/about", sources)
        self.assertNotIn("/account/about", [urlsplit(c["url"]).path for c in templated])
        # Documents with a form: the four the crawl fetched and the supplied one.
        self.assertEqual(result.form_templates["documents"], 5)

    def test_control_switch_off_adds_nothing_and_sends_nothing(self):
        for config in (None, {"enabled": False, "baseline": True}):
            with self.subTest(config=config):
                state, result, _out = self._build(config, writes=True)
                self.assertEqual(self._templates(result), {})
                self.assertIsNone(getattr(result, "form_templates", None))
                self.assertNotIn("POST /account/profile", state.endpoints)
                self.assertEqual(_Handler.posts, [])

    def test_control_baseline_with_writes_off_submits_nothing(self):
        _state, result, out = self._build({"enabled": True, "baseline": True}, writes=False)
        self.assertEqual(_Handler.posts, [])
        self.assertEqual(out["changes"], [])
        outcomes = {b["form"]: b for b in result.form_templates["baselines"]}
        self.assertEqual(set(outcomes), {"POST /account/profile", "POST /account/notes",
                                         "POST /account/stamp"})
        for entry in outcomes.values():
            self.assertEqual(entry["outcome"], "skipped")
            self.assertIn("writes are off", entry["reason"])
        self.assertEqual(self._templates(result, form_capture.BASELINE_SOURCE), {})

    def test_baseline_submits_an_edit_form_unchanged_and_checks_the_restore(self):
        _state, result, out = self._build({"enabled": True, "baseline": True}, writes=True)
        outcomes = {b["form"]: b for b in result.form_templates["baselines"]}
        # The filled edit form: one unchanged submit, the re-read shows the same values.
        profile = outcomes["POST /account/profile"]
        self.assertEqual((profile["outcome"], profile["restore"]), ("submitted", "restored"))
        self.assertEqual(_Handler.store["name"], "Ada")
        self.assertEqual(_Handler.store["bio"], "line one\nline two")
        answered = self._templates(result, form_capture.BASELINE_SOURCE)
        self.assertEqual(answered[("POST", "/account/profile")]["response_status"], 200)
        self.assertNotIn(("POST", "/account/profile"), self._templates(result))
        # A create-shaped form is never sent: it could not be restored.
        notes = outcomes["POST /account/notes"]
        self.assertEqual(notes["outcome"], "skipped")
        self.assertIn("cannot be restored", notes["reason"])
        self.assertNotIn("/account/notes", [p for p, _f in _Handler.posts])
        # A form the server rewrites on save: the write is marked restore_failed.
        stamp = outcomes["POST /account/stamp"]
        self.assertEqual(stamp["restore"], "restore_failed")
        self.assertIn("label", stamp["detail"])
        posted = [p for p, _f in _Handler.posts]
        self.assertEqual(sorted(posted), ["/account/profile", "/account/stamp"])
        changes = {c["path"]: c for c in out["changes"]}
        self.assertEqual(changes["/account/profile"]["restore_status"], "restored")
        self.assertEqual(changes["/account/stamp"]["restore_status"], "restore_failed")
        self.assertEqual(changes["/account/profile"]["capability"], form_capture.BASELINE_CAPABILITY)
        self.assertIn("RESTORE FAILED", out["log"])
        self.assertNotIn(TOKEN, out["log"])
        self.assertNotIn(TOKEN, json.dumps(result.form_templates))


if __name__ == "__main__":
    unittest.main()
