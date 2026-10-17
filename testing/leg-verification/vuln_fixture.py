"""
Disposable leg-verification fixture -- Phase 2.

A deliberately-vulnerable local Flask app used ONLY to LIVE-verify the harness's
confirmation legs against real true-positives (and matched negative controls),
so a leg is proven to actually bite on a real target rather than only pass a
stubbed smoke test. It is never deployed and binds to localhost only.

Each vuln class has a PAIR of endpoints differing in exactly one property:
  - a TRUE-POSITIVE endpoint that has the bug, and
  - a CONTROL endpoint that is structurally similar but safe,
so a leg must confirm the first and stay silent on the second.

Covered: SSTI (Jinja render vs escaped echo), open redirect (blind vs fixed),
path traversal (raw join vs basename), reflected XSS (raw vs escaped -- for the
browser_xss leg the operator runner drives). Build/run via run_leg_verification.py
or the hermetic test_leg_live_verification.
"""
from __future__ import annotations

import base64
import hashlib as _hashlib
import hmac as _hmac
import html
import json as _json
import os
import pickle
import re
import secrets as _secrets
import subprocess
import urllib.request
from urllib.parse import urlsplit

from flask import Flask, request, redirect, Response, jsonify, make_response
from jinja2 import Template


def make_app(file_base: str | None = None) -> Flask:
    app = Flask(__name__)
    base = file_base or os.path.dirname(os.path.abspath(__file__))

    @app.get("/health")
    def health():
        return {"status": "ok"}

    # --- SSTI: TP renders the param as a template; control escapes it ---------
    @app.get("/ssti/render")
    def ssti_render():
        q = request.args.get("q", "")
        return Response(Template(q).render(), mimetype="text/html")  # nosec B701 - INTENTIONAL SSTI sink; disposable fixture that live-verifies the ssti leg

    @app.get("/ssti/echo")
    def ssti_echo():
        q = request.args.get("q", "")
        return Response(f"you said: {html.escape(q)}", mimetype="text/html")  # safe

    # --- Open redirect: TP redirects to the param; control ignores it ---------
    @app.get("/redirect/open")
    def redirect_open():
        return redirect(request.args.get("url", "/"), code=302)  # VULNERABLE

    @app.get("/redirect/safe")
    def redirect_safe():
        return redirect("/home", code=302)  # ignores the param -- fixed target

    # --- Path traversal: TP joins the raw param; control takes the basename ---
    @app.get("/files/read")
    def files_read():
        name = request.args.get("file", "")
        try:
            with open(os.path.join(base, name), "r", errors="ignore") as f:  # nosec - INTENTIONAL path-traversal sink; disposable fixture for the path_traversal leg
                return Response(f.read(), mimetype="text/plain")
        except OSError:
            return Response("not found", status=404, mimetype="text/plain")

    @app.get("/files/safe")
    def files_safe():
        name = os.path.basename(request.args.get("file", ""))  # strips traversal
        try:
            with open(os.path.join(base, name), "r", errors="ignore") as f:
                return Response(f.read(), mimetype="text/plain")
        except OSError:
            return Response("not found", status=404, mimetype="text/plain")

    # --- Reflected XSS: TP reflects raw; control escapes (for browser_xss) ----
    @app.get("/xss/reflect")
    def xss_reflect():
        q = request.args.get("q", "")
        return Response(f"<html><body>hello {q}</body></html>", mimetype="text/html")  # VULNERABLE

    @app.get("/xss/safe")
    def xss_safe():
        q = request.args.get("q", "")
        return Response(f"<html><body>hello {html.escape(q)}</body></html>", mimetype="text/html")

    # --- DOM-based XSS (dom_xss leg): a client-side sink reads location.hash and
    #     writes it to innerHTML. The payload lives in the FRAGMENT, so the server
    #     never sees it -- only a real browser executing the DOM sink can trigger it.
    #     TP writes hash to innerHTML raw; control uses textContent. For the
    #     operator's real-browser run (run_leg_verification.py), not the auto-suite.
    @app.get("/xss/dom-hash")
    def xss_dom_hash():
        return Response(
            "<html><body><div id=out></div><script>"
            "document.getElementById('out').innerHTML = "
            "decodeURIComponent(location.hash.slice(1));"  # VULNERABLE: hash -> innerHTML
            "</script></body></html>", mimetype="text/html")

    @app.get("/xss/dom-safe")
    def xss_dom_safe():
        return Response(
            "<html><body><div id=out></div><script>"
            "document.getElementById('out').textContent = "
            "decodeURIComponent(location.hash.slice(1));"  # safe: textContent, no HTML parse
            "</script></body></html>", mimetype="text/html")

    # --- SSRF: TP fetches the url param server-side; control never fetches -----
    @app.get("/ssrf/fetch")
    def ssrf_fetch():
        url = request.args.get("url", "")
        try:
            with urllib.request.urlopen(url, timeout=2) as r:  # nosec B310 - INTENTIONAL SSRF sink; disposable fixture for the ssrf leg
                r.read(64)
            return Response("fetched", mimetype="text/plain")
        except Exception:
            return Response("fetch failed", mimetype="text/plain")

    @app.get("/ssrf/safe")
    def ssrf_safe():
        return Response(f"url noted: {html.escape(request.args.get('url', ''))}",  # never fetched
                        mimetype="text/plain")

    # --- XXE via a JS-built XML body (LB-2 driver-capture fixture) ------------
    #     The source page's inline JS POSTs an XML document via fetch() -- there
    #     is no <form> and no server-rendered link to /xxe/parse, so a passive/
    #     HTML-only crawl never sees this request's real shape (nothing to
    #     synthesize a body from, let alone an XML one -- role_crawl's
    #     _synthesize_body only ever guesses application/json). Only a real
    #     browser executing the page's JS observes the actual POST. TP resolves
    #     a SYSTEM external entity by fetching its URL server-side (mirrors
    #     ssrf_fetch below -- OOB-provable via the in-process collaborator,
    #     OS-independent); control reads the body but never resolves entities.
    _XXE_SYSTEM_RE = re.compile(r'<!ENTITY\s+\w+\s+SYSTEM\s+"([^"]+)"', re.IGNORECASE)

    @app.get("/xxe/js-form")
    def xxe_js_form():
        return Response(
            "<html><body><div id=out>loading</div><script>"
            "fetch('/xxe/parse', {method: 'POST', "
            "headers: {'Content-Type': 'application/xml'}, "
            "body: '<?xml version=\"1.0\"?><request><item>probe</item></request>'})"
            ".then(function(r){return r.text();})"
            ".then(function(t){document.getElementById('out').textContent = t;});"
            "</script></body></html>", mimetype="text/html")

    @app.post("/xxe/parse")
    def xxe_parse():
        body = request.get_data(as_text=True) or ""
        m = _XXE_SYSTEM_RE.search(body)
        if m:
            try:
                with urllib.request.urlopen(m.group(1), timeout=2) as r:  # nosec B310 - INTENTIONAL XXE sink (simulates a vulnerable XML parser resolving a SYSTEM external entity by fetching it server-side); disposable fixture for the xxe leg
                    r.read(64)
            except Exception:
                pass
        return Response("parsed", mimetype="text/plain")

    @app.get("/xxe/js-form-safe")
    def xxe_js_form_safe():
        return Response(
            "<html><body><div id=out>loading</div><script>"
            "fetch('/xxe/parse-safe', {method: 'POST', "
            "headers: {'Content-Type': 'application/xml'}, "
            "body: '<?xml version=\"1.0\"?><request><item>probe</item></request>'})"
            ".then(function(r){return r.text();})"
            ".then(function(t){document.getElementById('out').textContent = t;});"
            "</script></body></html>", mimetype="text/html")

    @app.post("/xxe/parse-safe")
    def xxe_parse_safe():
        # CONTROL: the body is read but external entities are never resolved
        # (no SYSTEM-URL fetch) -- a safely-configured parser.
        request.get_data(as_text=True)
        return Response("parsed", mimetype="text/plain")

    # --- Command injection: TP passes the param to a shell; control does not ---
    @app.get("/cmdi/ping")
    def cmdi_ping():
        host = request.args.get("host", "")
        try:
            out = subprocess.run(f"echo {host}", shell=True, capture_output=True,  # nosec B602 - INTENTIONAL shell-injection sink; disposable fixture for the command_injection leg
                                 timeout=5, text=True)
            return Response(out.stdout, mimetype="text/plain")
        except Exception:
            return Response("cmd failed", mimetype="text/plain")

    @app.get("/cmdi/safe")
    def cmdi_safe():
        return Response(f"host noted: {html.escape(request.args.get('host', ''))}",  # no shell
                        mimetype="text/plain")

    # --- Mass assignment (sequence leg): TP binds ALL body fields to the object,
    #     readable back via GET; control binds only an allowlist. state resets. --
    def _fresh():
        return {"id": 1, "name": "alice", "role": "user"}

    # nested-response + non-canonical authority field: the write binds all body
    # fields, but the response NESTS the object under wrapper keys and the
    # escalation field (`is_premium`) is NOT in the canonical priv-field list. The
    # original leg (top-level lookup, fixed field set) misses both; the generalised
    # leg (recursive detection + authority-named schema-derived candidates) catches it.
    def _fresh_tier():
        return {"id": 1, "name": "bob", "is_premium": False, "plan": "free"}
    state = {"profile": _fresh(), "profile_safe": _fresh(),
             "tier": _fresh_tier(), "tier_safe": _fresh_tier()}

    @app.post("/account/reset")
    def account_reset():
        state["profile"], state["profile_safe"] = _fresh(), _fresh()
        state["tier"], state["tier_safe"] = _fresh_tier(), _fresh_tier()
        return jsonify(state["profile"])

    @app.route("/account/tier", methods=["GET", "PATCH", "POST", "PUT"])
    def account_tier():
        if request.method != "GET":
            body = request.get_json(silent=True) or {}
            if isinstance(body, dict):
                state["tier"].update(body)  # VULNERABLE: binds every body field
        return jsonify({"ok": True, "user": {"account": dict(state["tier"])}})  # NESTED

    @app.route("/account/tier-safe", methods=["GET", "PATCH", "POST", "PUT"])
    def account_tier_safe():
        if request.method != "GET":
            body = request.get_json(silent=True) or {}
            if isinstance(body, dict):
                for k in ("name",):  # allowlist -- is_premium/plan ignored
                    if k in body:
                        state["tier_safe"][k] = body[k]
        return jsonify({"ok": True, "user": {"account": dict(state["tier_safe"])}})

    @app.route("/account/profile", methods=["GET", "PATCH", "POST", "PUT"])
    def account_profile():
        if request.method != "GET":
            # accept BOTH JSON and urlencoded form bodies (a realistic app does),
            # so the sequence leg's form-encoded path is exercised too (V14 fix).
            body = request.get_json(silent=True)
            if not isinstance(body, dict):
                body = request.form.to_dict() if request.form else {}
            if isinstance(body, dict):
                state["profile"].update(body)  # VULNERABLE: no settable-field allowlist
        return jsonify(state["profile"])

    @app.route("/account/profile-safe", methods=["GET", "PATCH", "POST", "PUT"])
    def account_profile_safe():
        if request.method != "GET":
            body = request.get_json(silent=True) or {}
            if isinstance(body, dict):
                for k in ("name", "bio"):  # allowlist -- privileged fields ignored
                    if k in body:
                        state["profile_safe"][k] = body[k]
        return jsonify(state["profile_safe"])

    # --- Insecure deserialization: TP pickle.loads a client cookie; control json --
    @app.get("/deser/load")
    def deser_load():
        c = request.cookies.get("session", "")
        try:
            obj = pickle.loads(base64.b64decode(c + "==="))  # nosec B301 - INTENTIONAL insecure-deserialization sink; disposable fixture for the deserialization_oob leg
            return jsonify({"ok": True, "who": str(obj)[:40]})
        except Exception:
            return jsonify({"ok": False}), 200

    @app.get("/deser/safe")
    def deser_safe():
        c = request.cookies.get("session", "")
        try:
            _json.loads(base64.b64decode(c + "===").decode("utf-8", "ignore"))  # safe: json, not pickle
            return jsonify({"ok": True})
        except Exception:
            return jsonify({"ok": False}), 200

    # --- Auth family (auth_sequence leg) --------------------------------------
    # root issues a session cookie so the fixation leg has a pre-auth id to fix.
    @app.get("/")
    def _root():
        resp = make_response(jsonify({"ok": True}))
        resp.set_cookie("sid", request.cookies.get("sid") or _secrets.token_hex(8))
        return resp

    # session fixation: TP reuses the presented sid across login; control rotates it.
    @app.route("/auth/login-fixation", methods=["POST"])
    def login_fixation():
        resp = make_response(jsonify({"ok": True}))
        sid = request.cookies.get("sid")
        if sid:
            resp.set_cookie("sid", sid)  # VULNERABLE: no rotation on auth
        return resp

    @app.route("/auth/login-rotate", methods=["POST"])
    def login_rotate():
        resp = make_response(jsonify({"ok": True}))
        resp.set_cookie("sid", _secrets.token_hex(8))  # rotates -> safe
        return resp

    # weak password policy: TP accepts anything; control enforces a minimum.
    @app.route("/auth/register-weak", methods=["POST"])
    def register_weak():
        body = request.get_json(silent=True) or {}
        return jsonify({"ok": True, "user": body.get("username")}), 200  # VULNERABLE: no policy

    @app.route("/auth/register-strong", methods=["POST"])
    def register_strong():
        body = request.get_json(silent=True) or {}
        if len(str(body.get("password", ""))) < 8:
            return jsonify({"error": "password too weak: minimum 8 characters"}), 400
        return jsonify({"ok": True}), 200

    # username enumeration: TP distinguishes existing vs missing account; control uniform.
    _known = {"alice", "alice@example.com"}

    @app.route("/auth/login-enum", methods=["POST"])
    def login_enum():
        body = request.get_json(silent=True) or {}
        if str(body.get("username", "")) in _known:
            return jsonify({"error": "invalid password"}), 401  # VULNERABLE: reveals existence
        return jsonify({"error": "user not found"}), 404

    @app.route("/auth/login-uniform", methods=["POST"])
    def login_uniform():
        return jsonify({"error": "invalid credentials"}), 401  # uniform -> safe

    # --- Stored XSS (stored_xss leg): POST stores; GET renders all as HTML. TP
    #     renders raw (stored XSS); control escapes on render. ---------------------
    stored = {"comments": [], "comments_safe": []}

    @app.post("/stored/reset")
    def stored_reset():
        stored["comments"].clear(); stored["comments_safe"].clear()
        return jsonify({"ok": True})

    @app.route("/stored/comments", methods=["GET", "POST"])
    def stored_comments():
        if request.method == "POST":
            b = request.get_json(silent=True) or {}
            stored["comments"].append(str(b.get("text", "")))
            return jsonify({"ok": True}), 201
        body = "<html><body>" + "".join(f"<div>{c}</div>" for c in stored["comments"]) + "</body></html>"
        return Response(body, mimetype="text/html")  # VULNERABLE: stored text rendered raw

    @app.route("/stored/comments-safe", methods=["GET", "POST"])
    def stored_comments_safe():
        if request.method == "POST":
            b = request.get_json(silent=True) or {}
            stored["comments_safe"].append(str(b.get("text", "")))
            return jsonify({"ok": True}), 201
        body = ("<html><body>"
                + "".join(f"<div>{html.escape(c)}</div>" for c in stored["comments_safe"])
                + "</body></html>")
        return Response(body, mimetype="text/html")  # escaped on render -> safe

    # --- Stored XSS via a CSRF-token-bound comment FORM (PortSwigger-shaped) ---
    #     The write is a urlencoded form guarded by a per-session CSRF token: the
    #     source page mints the token bound to a session cookie, and a POST whose
    #     token does not match that session is rejected. This is the shape the
    #     stored_xss leg must handle by minting a FRESH token in its own session
    #     (reusing a captured/stale token yields 400 and stores nothing). The
    #     source page lives at the PARENT path of the write action, exactly as the
    #     leg derives it (POST /blog/comment -> GET /blog?postId=1).
    csrf_sessions: dict[str, str] = {}
    blog = {"comments": [], "comments_safe": []}

    @app.post("/blog/reset")
    def blog_reset():
        blog["comments"].clear(); blog["comments_safe"].clear(); csrf_sessions.clear()
        return jsonify({"ok": True})

    def _blog_page(store_key, escape, action, post_id):
        sid = request.cookies.get("session")
        set_cookie = False
        if not sid or sid not in csrf_sessions:
            sid = _secrets.token_hex(8); set_cookie = True
        token = _secrets.token_hex(16)
        csrf_sessions[sid] = token  # freshly minted, bound to THIS session
        rendered = "".join(
            f"<div>{html.escape(c) if escape else c}</div>" for c in blog[store_key])
        page = (f"<html><body><h1>post {html.escape(str(post_id))}</h1>{rendered}"
                f"<form action='{action}' method='POST'>"
                f"<input type='hidden' name='csrf' value='{token}'>"
                f"<input type='hidden' name='postId' value='{html.escape(str(post_id))}'>"
                f"<textarea name='comment'></textarea>"
                f"<input type='text' name='name'>"
                f"<input type='email' name='email'>"
                f"<input type='text' name='website'>"
                f"</form></body></html>")
        resp = make_response(Response(page, mimetype="text/html"))
        if set_cookie:
            resp.set_cookie("session", sid)
        return resp

    def _blog_comment(store_key, escape):
        sid = request.cookies.get("session", "")
        token = request.form.get("csrf", "")
        if not sid or csrf_sessions.get(sid) != token:
            return Response("Invalid CSRF token", status=400, mimetype="text/plain")
        website = request.form.get("website", "")
        if website and not website.startswith(("http://", "https://")):
            return Response("Invalid website.", status=400, mimetype="text/plain")
        blog[store_key].append(str(request.form.get("comment", "")))
        return redirect("/blog?postId=1" if not escape else "/blog-safe?postId=1", code=302)

    @app.get("/blog")
    def blog_page():
        return _blog_page("comments", False, "/blog/comment", request.args.get("postId", "1"))

    @app.post("/blog/comment")
    def blog_comment():
        return _blog_comment("comments", False)  # VULNERABLE: rendered raw

    @app.get("/blog-safe")
    def blog_page_safe():
        return _blog_page("comments_safe", True, "/blog-safe/comment", request.args.get("postId", "1"))

    @app.post("/blog-safe/comment")
    def blog_comment_safe():
        return _blog_comment("comments_safe", True)  # escaped on render -> safe

    # --- JWT kid key-confusion (jwt_forge kid variant) ------------------------
    def _b64url(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    def _verify_hs256(token, key):
        try:
            h, p, s = token.split(".")
            expected = _b64url(_hmac.new(key, f"{h}.{p}".encode(), _hashlib.sha256).digest())
            return s == expected
        except Exception:
            return False

    def _bearer():
        a = request.headers.get("Authorization", "")
        return a.split(" ", 1)[-1] if " " in a else a

    @app.get("/jwt/kid")
    def jwt_kid():
        tok = _bearer()
        try:
            hdr = _json.loads(base64.urlsafe_b64decode(tok.split(".")[0] + "==="))
            key = str(hdr.get("kid", "")).encode()  # VULNERABLE: key derived from attacker kid
            if key and _verify_hs256(tok, key):
                payload = _json.loads(base64.urlsafe_b64decode(tok.split(".")[1] + "==="))
                return jsonify({"ok": True, "role": payload.get("role")})
        except Exception:
            pass
        return jsonify({"error": "unauthorized"}), 401

    @app.get("/jwt/kid-safe")
    def jwt_kid_safe():
        if _verify_hs256(_bearer(), b"fixed-server-secret-value"):  # ignores kid -> safe
            return jsonify({"ok": True})
        return jsonify({"error": "unauthorized"}), 401

    # --- JWT unverified signature (accepts ANY signature; denies tokenless) ----
    @app.get("/jwt/unverified")
    def jwt_unverified():
        # VULNERABLE: trusts a structurally-valid token WITHOUT verifying its
        # signature, but a tokenless request is denied. The confirmation is the
        # differential invalid-signature-accepted vs tokenless-denied.
        tok = _bearer()
        if not tok:
            return jsonify({"error": "unauthorized"}), 401
        try:
            payload = _json.loads(base64.urlsafe_b64decode(tok.split(".")[1] + "==="))
            return jsonify({"ok": True, "sub": payload.get("sub"),
                            "secret": "protected-account-data"})
        except Exception:
            return jsonify({"error": "unauthorized"}), 401

    @app.get("/jwt/public")
    def jwt_public():
        # CONTROL: protected-looking content returned regardless of token -- a truly
        # public endpoint accepts garbage AND tokenless, so the leg must SKIP (the
        # token does not gate access; that is not a signature-verification bug).
        return jsonify({"ok": True, "data": "public-listing"})

    # --- File upload via a CSRF-bound multipart form (PortSwigger-shaped) ------
    #     The upload uses a specific file-field name (`avatar`) alongside hidden
    #     csrf/user fields; a bare `file` part with no token is rejected. The leg
    #     must read the real form from the source page (fresh token) to succeed.
    upl = {"csrf": {}, "files": {}}

    def _upload_form_page(action):
        sid = request.cookies.get("session")
        setc = False
        if not sid or sid not in upl["csrf"]:
            sid = _secrets.token_hex(8); setc = True
        token = _secrets.token_hex(16); upl["csrf"][sid] = token
        page = (f"<html><body><form action='{action}' method='POST' "
                f"enctype='multipart/form-data'>"
                f"<input type='hidden' name='csrf' value='{token}'>"
                f"<input type='hidden' name='user' value='wiener'>"
                f"<input type='file' name='avatar'></form></body></html>")
        resp = make_response(Response(page, mimetype="text/html"))
        if setc:
            resp.set_cookie("session", sid)
        return resp

    def _store_upload(prefix):
        sid = request.cookies.get("session", "")
        if upl["csrf"].get(sid) != request.form.get("csrf", ""):
            return None, Response("Invalid CSRF token", status=400, mimetype="text/plain")
        fs = request.files.get("avatar")  # REQUIRES the real field name, not `file`
        if fs is None:
            return None, Response("Missing avatar field", status=400, mimetype="text/plain")
        name = prefix + fs.filename
        upl["files"][name] = fs.read()
        return name, None

    @app.get("/upload/account")
    def upload_account():
        return _upload_form_page("/upload/avatar")

    @app.post("/upload/avatar")
    def upload_avatar():
        name, err = _store_upload("")
        if err is not None:
            return err
        return Response(f"<html><img src='/upload/files/{name}'></html>", mimetype="text/html")

    @app.get("/upload/files/<path:name>")
    def upload_files(name):
        data = upl["files"].get(name)
        if data is None:
            return Response("not found", status=404)
        return Response(data, mimetype="text/html")  # VULNERABLE: served as active HTML

    @app.get("/upload/account-safe")
    def upload_account_safe():
        return _upload_form_page("/upload/avatar-safe")

    @app.post("/upload/avatar-safe")
    def upload_avatar_safe():
        name, err = _store_upload("safe-")
        if err is not None:
            return err
        return Response(f"<html><img src='/upload/files-safe/{name}'></html>", mimetype="text/html")

    @app.get("/upload/files-safe/<path:name>")
    def upload_files_safe(name):
        data = upl["files"].get(name)
        if data is None:
            return Response("not found", status=404)
        # CONTROL: forced as an attachment -> not an active execution context.
        return Response(data, mimetype="text/html",
                        headers={"Content-Disposition": f"attachment; filename={name}"})

    # --- 2FA / MFA bypass (step-1 login reaches a protected page pre-2nd-factor) --
    mfa = {"sessions": {}}

    def _mfa_login(mode):
        body = request.get_json(silent=True) or {}
        user = request.form.get("username") or body.get("username") or "alice"
        sid = _secrets.token_hex(8)
        mfa["sessions"][sid] = {"user": user, "verified": False, "mode": mode}
        resp = make_response(redirect("/2fa/verify", code=302))  # lands on the 2nd-factor step
        resp.set_cookie("session", sid)
        return resp

    @app.post("/2fa/login")
    def mfa_login():
        return _mfa_login("vuln")

    @app.post("/2fa/login-safe")
    def mfa_login_safe():
        return _mfa_login("safe")

    @app.get("/2fa/verify")
    def mfa_verify():
        return Response("<html><body>Enter your verification code"
                        "<form method='POST'><input name='mfa-code'></form></body></html>",
                        mimetype="text/html")

    @app.get("/my-account")
    def mfa_account():
        s = mfa["sessions"].get(request.cookies.get("session", ""))
        if not s:
            return redirect("/2fa/verify", code=302)  # no session -> denied
        if s["mode"] == "safe" and not s["verified"]:
            return redirect("/2fa/verify", code=302)  # ENFORCING: 2nd factor required
        # VULNERABLE mode: the partial (step-1-only) session already reaches the account.
        return Response(f"<html><body>My account for {s['user']}. "
                        f"<a href='/logout'>Log out</a></body></html>", mimetype="text/html")

    # --- Excessive trust in client-side controls (client-supplied price) -------
    def _fmt(cents):
        return f"{cents // 100}.{cents % 100:02d}"

    @app.route("/shop/cart", methods=["POST"])
    def shop_cart():
        body = request.get_json(silent=True) or {}
        price = request.form.get("price") or body.get("price") or "0"
        try:
            cents = int(price)  # VULNERABLE: the server trusts the client-supplied price
        except ValueError:
            cents = 0
        return Response(f"<html><body>Cart total: ${_fmt(cents)}</body></html>", mimetype="text/html")

    @app.route("/shop/cart-safe", methods=["POST"])
    def shop_cart_safe():
        # CONTROL: the client price is ignored; the server uses its own authoritative
        # price, so a tampered value is never reflected back.
        return Response(f"<html><body>Cart total: ${_fmt(133700)}</body></html>", mimetype="text/html")

    # --- Cross-site browser PoC for CSRF confirmation (LB-5) -------------------
    #     Each variant pairs a state-changing, cookie-authenticated POST with a
    #     GET-only readback of the SAME state, so the leg's "independent GET-only
    #     verification" is a real differential, not a trust-the-POST's-own-
    #     response shortcut. The ambient session cookie's name/value/SameSite
    #     attribute is supplied by the DRIVER (PlaywrightDriver.cross_site_submit's
    #     own context.add_cookies call), not minted by a login flow here -- these
    #     endpoints only check for the cookie's PRESENCE, mirroring a real app that
    #     trusts whatever ambient cookie rides along on a request. No-defense and
    #     the SameSite=Strict/Lax controls share these SAME /csrf-poc/transfer +
    #     /csrf-poc/state endpoints -- SameSite enforcement is entirely the
    #     BROWSER's job (which sameSite value cross_site_submit seeds the cookie
    #     with), not something this server needs to vary for.
    csrf_poc_state = {"note": "", "note_origin": "", "note_bearer": ""}

    @app.post("/csrf-poc/reset")
    def csrf_poc_reset():
        for k in csrf_poc_state:
            csrf_poc_state[k] = ""
        return jsonify({"ok": True})

    # No defense: cookie-authenticated, no Origin/Referer check, no CSRF
    # token -- the "ambient cookie rides along on a cross-site auto-submit
    # form" case a real-browser PoC must confirm.
    @app.post("/csrf-poc/transfer")
    def csrf_poc_transfer():
        if not request.cookies.get("csrf_sid"):
            return Response("unauthorized", status=401, mimetype="text/plain")
        csrf_poc_state["note"] = request.form.get("note", "")
        return Response("ok", mimetype="text/plain")

    @app.get("/csrf-poc/state")
    def csrf_poc_state_get():
        if not request.cookies.get("csrf_sid"):
            return Response("unauthorized", status=401, mimetype="text/plain")
        return Response(csrf_poc_state["note"], mimetype="text/plain")

    # CONTROL: Origin/Referer enforced -- the ambient cookie still rides along
    # (same cookie check as above), but the handler additionally rejects a
    # cross-origin Origin/Referer, so a real browser's own (unforgeable)
    # Origin header on the cross-site POST is what must defeat this -- not a
    # missing cookie, which IS present.
    def _csrf_poc_same_origin(req) -> bool:
        origin = req.headers.get("Origin", "")
        if origin:
            return urlsplit(origin).hostname == urlsplit(req.url).hostname
        referer = req.headers.get("Referer", "")
        if referer:
            return urlsplit(referer).hostname == urlsplit(req.url).hostname
        return False  # neither header present -- fail closed, treat as cross-site

    @app.post("/csrf-poc/transfer-origin")
    def csrf_poc_transfer_origin():
        if not request.cookies.get("csrf_sid"):
            return Response("unauthorized", status=401, mimetype="text/plain")
        if not _csrf_poc_same_origin(request):
            return Response("forbidden: cross-origin request rejected", status=403,
                            mimetype="text/plain")
        csrf_poc_state["note_origin"] = request.form.get("note", "")
        return Response("ok", mimetype="text/plain")

    @app.get("/csrf-poc/state-origin")
    def csrf_poc_state_origin_get():
        if not request.cookies.get("csrf_sid"):
            return Response("unauthorized", status=401, mimetype="text/plain")
        return Response(csrf_poc_state["note_origin"], mimetype="text/plain")

    # CONTROL: bearer-only (non-ambient) -- requires an Authorization header
    # the browser's cookie jar can never supply on its own, so an
    # ambient-cookie-only PoC must never confirm this one regardless of
    # whether a cookie is also present.
    _CSRF_POC_BEARER_TOKEN = "csrf-poc-fixture-bearer-token"  # fixture-only constant, not a real secret

    @app.post("/csrf-poc/transfer-bearer")
    def csrf_poc_transfer_bearer():
        if request.headers.get("Authorization", "") != f"Bearer {_CSRF_POC_BEARER_TOKEN}":
            return Response("unauthorized", status=401, mimetype="text/plain")
        csrf_poc_state["note_bearer"] = request.form.get("note", "")
        return Response("ok", mimetype="text/plain")

    @app.get("/csrf-poc/state-bearer")
    def csrf_poc_state_bearer_get():
        if request.headers.get("Authorization", "") != f"Bearer {_CSRF_POC_BEARER_TOKEN}":
            return Response("unauthorized", status=401, mimetype="text/plain")
        return Response(csrf_poc_state["note_bearer"], mimetype="text/plain")

    return app


if __name__ == "__main__":
    make_app().run(host="127.0.0.1", port=5099)
