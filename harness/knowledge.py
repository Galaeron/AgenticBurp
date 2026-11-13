from __future__ import annotations
import re

from harness.models import HttpExchange

# A deliberately small, hand-written methodology corpus -- not a copy of
# any external text (OWASP Testing Guide, PortSwigger docs, etc; those
# are copyrighted and paraphrasing them closely enough to be useful would
# still risk reproducing their structure). This is the "Memory Retriever"
# module VulnBot's five-module architecture names explicitly: a
# retrieval step separate from planning/generation, so agents ground
# their reasoning in something written down instead of only what's in
# the model's weights. Keeping this file-based and keyword-scored (no
# embeddings, no vector DB) is a deliberate choice: it's inspectable,
# has zero extra runtime dependencies, and its failure mode when it
# misses is "no context added" rather than "silently wrong context from
# a bad embedding match."
#
# Extend this corpus freely -- each entry needs "tags" (matched against
# agent name + a few keywords pulled from the exchange) and "note" (the
# actual grounding text, kept short and operational).
_CORPUS: list[dict] = [
    {
        "tags": ["sqli", "sql", "injection", "database"],
        "note": "Differential testing beats single-request pattern matching for SQLi: "
                "compare a baseline request against one with a single quote appended, "
                "then against one with the quote escaped/doubled -- a genuine injection "
                "point usually shows a response difference on the first and not the "
                "second. Time-based confirmation (a sleep expression vs a no-op of "
                "matching syntax) is the fallback when the response body gives no signal.",
    },
    {
        "tags": ["xss", "cross-site", "script"],
        "note": "Where a reflection lands changes what breaks out of it: inside an HTML "
                "attribute you need to close the attribute and possibly the tag; inside a "
                "<script> block you don't need HTML-breaking characters at all, just "
                "JS-breaking ones; inside a JSON response that's later parsed by JS, the "
                "risk is downstream (does something eval or innerHTML it), not the "
                "response itself.",
    },
    {
        "tags": ["idor", "access_control", "business_logic", "business_logic_enhanced"],
        "note": "IDOR is only proven by a differential test across two identities: same "
                "object ID, two different session tokens, compare responses -- or same "
                "token, two different IDs. A single request showing a plausible-looking "
                "numeric ID is a candidate, not a finding, until that second request "
                "exists.",
    },
    {
        "tags": ["ssrf"],
        "note": "Blind SSRF (no reflected response, no visible fetch) is usually "
                "confirmed out-of-band: point the candidate parameter at an "
                "analyst-controlled listener and check for an inbound connection, "
                "since the application's own response may never show anything. "
                "Cloud metadata endpoints (link-local addresses reachable from inside "
                "the app's network) are a common high-value target once SSRF is "
                "confirmed at all.",
    },
    {
        "tags": ["business_logic", "race", "workflow", "race_condition", "business_logic_enhanced"],
        "note": "Race-condition-shaped findings (redemption, balance transfer, "
                "limited-quantity purchase) need concurrent requests, not sequential "
                "ones -- firing the same request twice one after another rarely "
                "reproduces a TOCTOU window; it needs to be genuinely simultaneous.",
    },
    {
        "tags": ["misconfig", "headers", "cors"],
        "note": "The dangerous CORS misconfiguration is the *pairing* of "
                "Access-Control-Allow-Origin reflecting an arbitrary origin together "
                "with Access-Control-Allow-Credentials: true -- either alone is much "
                "lower risk than the combination, which lets a malicious origin read "
                "authenticated responses.",
    },
    {
        "tags": ["auth", "jwt", "session"],
        "note": "For JWT-bearing apps, check the algorithm field before anything else: "
                "an app that accepts 'none' as an algorithm, or that can be tricked into "
                "verifying an RS256 token with the public key as an HMAC secret, breaks "
                "signature verification entirely regardless of how strong the actual "
                "signing key is.",
    },
    {
        "tags": ["ai_llm", "prompt", "injection", "ai_security"],
        "note": "Prompt injection testing separates two different risks that get "
                "conflated: direct injection (the user's own message tries to override "
                "instructions) and indirect injection (untrusted third-party content -- "
                "a fetched URL, an uploaded document -- contains instructions the model "
                "follows as if they were trusted). Indirect injection is generally the "
                "higher-severity, easier-to-miss case, since the attacker never talks to "
                "the app directly.",
    },
    {
        "tags": ["supply_chain", "dependency", "lockfile", "github", "actions"],
        "note": "An exposed lockfile is a reconnaissance gift, not a vulnerability by "
                "itself -- the actual risk is whichever named version turns out to have "
                "a disclosed advisory, which is exactly what the deterministic "
                "known-vulnerability lookup step (not agent reasoning) is for. "
                "Separately: a GitHub Actions workflow using pull_request_target while "
                "checking out and running code from the PR head is a well-documented "
                "'pwn request' pattern -- untrusted fork code runs with the base repo's "
                "token and secrets.",
    },
    {
        "tags": ["known", "advisory", "cve", "rediscover"],
        "note": "When a component's exact version and a matching disclosed advisory "
                "both exist, the useful next step is confirming the deployed version "
                "falls in the affected range and checking remediation status -- not "
                "spending further effort trying to independently redemonstrate that the "
                "underlying bug exists. Effort is better spent on components where no "
                "advisory was found, since that's the only case where independent "
                "analysis is actually adding information.",
    },
    # SKL-2: one note per specialist agent whose own name matched no tag above.
    # Each tag set leads with the exact agent-name token and adds only
    # distinctive words, so a neutral exchange never drags in another class.
    # Every note states the PROOF rule the matching validator applies.
    {
        "tags": ["command_injection", "os-command", "rce"],
        "note": "Command injection is proven out-of-band: the injected value should do "
                "nothing except make the host fetch a unique, single-use listener URL, and "
                "the inbound callback is the evidence. Output that merely looks like a "
                "command result, or an error mentioning a shell, stays a candidate; a "
                "timing difference counts only against a no-op control of the same shape.",
    },
    {
        "tags": ["xxe", "xml-entity", "dtd"],
        "note": "XXE is confirmed when the XML parser itself reaches out: declare an "
                "external entity that points at a unique listener URL and wait for the "
                "fetch. That works for blind parsers too, so whether entity content is "
                "echoed back does not matter. An endpoint that merely accepts XML, or "
                "returns a parser error on a DOCTYPE, is a candidate only.",
    },
    {
        "tags": ["deserialization", "serialized", "pickle", "viewstate"],
        "note": "Recognising a serialized-object format (by its leading byte signature) "
                "establishes a candidate, not a vulnerability. Execution is proven only by "
                "a benign beacon -- a crafted object whose sole effect is an out-of-band "
                "fetch of a unique URL. Never build or send a destructive gadget chain; "
                "when the format is not one the harness can beacon, name the finding and "
                "leave exploitability to an analyst.",
    },
    {
        "tags": ["ssti", "template-injection"],
        "note": "Template injection is told apart from plain reflection by evaluation: "
                "submit an arithmetic expression between unique nonce markers and look for "
                "the computed result between those markers. Seeing the literal expression "
                "back means reflection (perhaps XSS), not SSTI. The arithmetic result is the "
                "whole proof; no OS-level payload is needed or wanted.",
    },
    {
        "tags": ["nosql", "mongodb", "operator-injection"],
        "note": "NoSQL operator injection on a login is proven with a paired test in two "
                "fresh sessions: an operator expression that cannot match any user must "
                "leave you at the login page (negative control), while the same shape "
                "aimed at a known identity must land on that identity's authenticated "
                "page. A changed error message or status alone is not proof.",
    },
    {
        "tags": ["csrf", "xsrf", "samesite"],
        "note": "A CSRF claim needs an observed state change, not a 200: show that a request "
                "lacking the anti-forgery token changed something, then read the new value "
                "back independently. Check the session cookie's SameSite attribute first -- "
                "Strict blocks cross-site submission, Lax still allows top-level GET "
                "navigation. A token-stripped replay that returns success is an observation.",
    },
    {
        "tags": ["file_upload", "upload", "multipart"],
        "note": "Upload filter bypass is proven by retrieval, not by the upload response: "
                "send a harmless file with a disallowed extension or content type, then "
                "fetch the stored URL and confirm the same content is served back. "
                "Acceptance messages alone prove nothing. Do not upload anything that "
                "executes; stored-and-served is the claim, server-side execution is not.",
    },
    {
        "tags": ["header_injection", "crlf"],
        "note": "Response header injection is proven when a line break in a parameter "
                "produces a separate, harness-chosen marker header in the raw response. A "
                "value that is only reflected inside an existing header is a candidate. "
                "Mail-header injection through a form cannot be seen from the HTTP "
                "response, so it stays unconfirmed unless the resulting message is observed.",
    },
    {
        "tags": ["http_request_smuggling", "smuggling", "desync"],
        "note": "A smuggling probe that times out or returns an odd status is a candidate, "
                "never a confirmation: a single connection cannot show that a front end and "
                "back end disagreed. Confirmation needs a paired effect -- a smuggled prefix "
                "that visibly changes the response to a separate follow-up request -- and "
                "should run only against an owned or test pair of servers.",
    },
    {
        "tags": ["web_cache_poisoning", "cache-poisoning", "cache-deception"],
        "note": "Cache poisoning needs two observations: an unkeyed input (such as a "
                "forwarding header) changes the response, AND a later clean request without "
                "that input still gets the altered response. Use a unique cache-buster so "
                "real users never receive the poisoned copy. For cache deception, show an "
                "authenticated page served from cache under a static-looking suffix.",
    },
    {
        "tags": ["open_redirect", "redirect", "returnurl"],
        "note": "An open redirect is proven by the Location header, not the body: set the "
                "redirect parameter to a unique off-origin host, do not follow redirects, "
                "and confirm a 3xx whose Location host is that host. The value appearing in "
                "page text or a same-origin redirect is not the finding.",
    },
    {
        "tags": ["websocket", "cswsh"],
        "note": "Cross-site WebSocket hijacking is proven when the handshake completes "
                "(101) despite a foreign Origin header while the session rides on cookies. "
                "A server that rejects the foreign Origin is the negative result. Issues "
                "inside messages, like missing per-message authorization, need a live "
                "session and a second identity, so report them as unconfirmed.",
    },
    {
        "tags": ["oauth", "oidc", "pkce", "redirect_uri"],
        "note": "Missing state or PKCE on an authorization request, or a token in the URL, "
                "can be read off one exchange and is a configuration observation. "
                "redirect_uri enforcement is tested with one probe that changes the "
                "redirect_uri: acceptance of a foreign value is the finding, rejection is "
                "the negative control. Full flow abuse needs a real consenting user.",
    },
    {
        "tags": ["csp", "clickjacking", "frame-ancestors"],
        "note": "Judge the policy the browser actually enforces: re-fetch the page and "
                "parse its directives, and remember a report-only header enforces nothing. "
                "Framing protection exists if either X-Frame-Options or frame-ancestors "
                "restricts it. A weak directive is a hardening gap; calling it exploitable "
                "needs a separate injection sink.",
    },
    {
        "tags": ["crypto", "tls", "hsts", "cipher"],
        "note": "Transport claims should come from an independent TLS handshake (negotiated "
                "protocol, cipher, certificate expiry and hostname), not from what the "
                "proxy displays. HSTS and cookie Secure flags are read from the captured "
                "headers. A weak-hash or weak-key claim needs the algorithm shown in the "
                "evidence, not inferred from a field name.",
    },
    {
        "tags": ["info_disclosure", "stacktrace", "verbose-error"],
        "note": "Quote exactly what leaked and rank it: a credential or key outranks a file "
                "path or internal hostname, which outranks a library version. A generic "
                "error page naming nothing is not a finding. Repeat with a well-formed "
                "control request: detail that only appears on malformed input is the real "
                "signal; detail on every page is a configuration issue.",
    },
    {
        "tags": ["graphql", "introspection"],
        "note": "Reachable introspection is a directly observable over-exposure finding. "
                "Missing per-field or per-object authorization is proven like IDOR: the "
                "same query under two identities, compared. Keep query depth, aliasing and "
                "batching findings (cost and rate-limit bypass) separate from data-exposure "
                "findings, since they need different evidence.",
    },
    {
        "tags": ["api_security", "mass-assignment", "bola"],
        "note": "Mass assignment is confirmed only by a controlled change: read the object "
                "first (field absent or different), send the write with the extra field, "
                "then read it back independently and see the new value. An echo in the "
                "write response is not proof. An oversized page or limit value proves "
                "missing bounds only if the server returns more than its usual cap.",
    },
    {
        "tags": ["rate_limit", "lockout", "brute-force"],
        "note": "Missing rate limiting is shown by a bounded burst of identical replays "
                "that all reach the application with no 429, no Retry-After and no "
                "lockout after a sensible threshold. Stay within the configured burst "
                "ceiling; a reduced burst gives lower confidence, not a skip. Never vary "
                "credentials to guess real passwords -- the replay is the test.",
    },
    {
        "tags": ["recon", "attack-surface"],
        "note": "Reconnaissance expands what to test; it does not prove a vulnerability. "
                "Record each new path, host or API base with where it was seen (link, "
                "script, comment, header), and rank it by what it unlocks next. A framework "
                "banner with no follow-on test is low value; a referenced internal host or "
                "exposed source map is high.",
    },
    {
        "tags": ["subdomain_takeover", "dangling", "cname"],
        "note": "A takeover candidate is a hostname pointing at a third-party service whose "
                "response matches that provider's known unclaimed-resource fingerprint. "
                "Do not register or claim the resource to prove it. No fingerprint match "
                "means only that the known signatures did not match, not that the host is "
                "safe.",
    },
    {
        "tags": ["anomaly", "outlier"],
        "note": "An anomaly is a deviation from a stated baseline, not a bug in itself: say "
                "what normal looks like for this route (status, header set, size, content "
                "type) and how this exchange differs. Repeat the request once to rule out "
                "flakiness. Hand a reproducible deviation to the matching specialist rather "
                "than assigning it severity.",
    },
]


def _tokenize(text: str) -> set[str]:
    return set(re.findall(r"[a-z][a-z0-9_-]{2,}", text.lower()))


def _external_notes(engagement_id: str = "") -> list[dict]:
    """Tester-authored writeups + auto-remembered confirmed findings, loaded from
    the store at decision time (VulnBot's Memory Retriever role -- grounding on
    accumulated experience, not just the model's weights). Best-effort: a store
    hiccup degrades to the built-in corpus alone, never an error.

    `engagement_id` (P2.3, optional): "" (default) keeps the prior global-only
    behaviour; a non-empty value additionally surfaces THAT engagement's own
    private notes, never another engagement's -- see store.list_knowledge_notes."""
    try:
        from harness import store
        rows = store.list_knowledge_notes(engagement_id=(engagement_id or None))
    except Exception:
        return []
    out = []
    for r in rows:
        # An external note is matched on its tags PLUS its own tokenized text, so
        # a free-text writeup still scores against the query.
        tag_tokens = {t.lower() for t in (r.get("tags") or [])} | _tokenize(r.get("note", ""))
        out.append({"tags": tag_tokens, "note": r.get("note", ""), "source": r.get("source", "manual")})
    return out


def remember_finding(vulnerability_class: str, url: str, evidence: str = "",
                     engagement_id: str = "") -> bool:
    """Persist a confirmed finding as a retrievable note -- the harness's own
    'past task' memory. Stores only the class + a path shape (no bodies/values),
    so future analyses of similar surface get grounded in what already worked
    here. `engagement_id` (P2.3, optional): "" (default) saves a globally-
    shared note, matching prior behaviour; a non-empty value saves it PRIVATE
    to that engagement (see store.save_knowledge_note). Returns whether a new
    note was stored."""
    try:
        from harness import store
        from urllib.parse import urlsplit
        path = urlsplit(url).path or "/"
        note = (f"On this engagement, {vulnerability_class} was CONFIRMED at a "
                f"{path}-shaped endpoint. Prioritize the same check on similar endpoints.")
        tags = list(_tokenize(vulnerability_class) | _tokenize(path))
        return store.save_knowledge_note(tags, note, source="finding", engagement_id=engagement_id)
    except Exception:
        return False


def retrieve(agent_name: str, exchange: HttpExchange, top_k: int = 2, engagement_id: str = "",
             *, include_external: bool = True) -> str:
    """
    Keyword-overlap retrieval (no embeddings): score the built-in corpus AND the
    tester's stored notes / remembered findings by how many of their tags/words
    appear in the agent's own name plus a slice of the exchange (URL + first part
    of the body), return the top_k notes as a single prompt-ready block.
    Deterministic and cheap enough to run on every call.

    `engagement_id` (P2.3, optional): "" (default) keeps the prior global-only
    behaviour for external notes; a non-empty value also surfaces that
    engagement's own PRIVATE notes -- never another engagement's (see
    _external_notes/store.list_knowledge_notes). The built-in corpus is always
    shared -- it carries no engagement-specific data at all.
    `include_external=False` keeps only that built-in corpus. Passive analysis
    uses this because stored notes lack captured-principal ownership.
    """
    query_tokens = _tokenize(agent_name) | _tokenize(exchange.url) | _tokenize(exchange.request_body[:500])

    scored: list[tuple[int, int, str]] = []
    # Built-in corpus first (tie-break priority 1), external notes second (0) so a
    # curated methodology entry edges out an incidental writeup on an equal score.
    for entry in _CORPUS:
        overlap = len(query_tokens & set(entry["tags"]))
        if overlap > 0:
            scored.append((overlap, 1, entry["note"]))
    for entry in (_external_notes(engagement_id=engagement_id) if include_external else []):
        overlap = len(query_tokens & entry["tags"])
        if overlap > 0:
            scored.append((overlap, 0, entry["note"]))

    if not scored:
        return ""

    scored.sort(key=lambda t: (t[0], t[1]), reverse=True)
    seen: set[str] = set()
    top: list[str] = []
    for _, _, note in scored:
        if note in seen:
            continue
        seen.add(note)
        top.append(note)
        if len(top) >= top_k:
            break
    return "\n".join(f"- {note}" for note in top)
