from .base_agent import BaseAgent


class WebsocketAgent(BaseAgent):
    """
    WebSocket Security Agent

    Detects security issues specific to WebSocket connections and
    messages. WebSockets bypass a lot of the security machinery that
    protects ordinary HTTP requests (SOP doesn't apply to the
    handshake the way CORS does, many WAFs don't inspect WebSocket
    frames the way they inspect HTTP bodies), so vulnerability classes
    that would be routine over HTTP take a different shape here.
    """
    name = "websocket"

    tactical_guide = """
1. Note whether the WebSocket handshake (the HTTP Upgrade request/response)
   carries an Origin header and whether the server appears to validate it --
   missing origin validation is the CSWSH (cross-site WebSocket hijacking)
   precondition.
2. Check whether the handshake reuses the same session cookie/token as the
   rest of the app (making it hijackable cross-site) vs a separate, scoped
   connection token.
3. If message-level content is visible, note whether it looks
   unauthenticated/unvalidated per-message (no per-message auth check
   beyond the initial handshake).
"""

    @property
    def specialty_prompt(self) -> str:
        return """
WebSocket-specific security issues. You may be shown either the
initial HTTP Upgrade handshake request/response, or a subsequent
WebSocket message captured by Burp (frames are often represented to
you as request/response-shaped data even though the underlying
protocol isn't request/response after the handshake -- work with
whatever you're given).

CROSS-SITE WEBSOCKET HIJACKING (CSWSH):
- The WebSocket handshake request (GET with Upgrade: websocket) --
  check the Origin header the browser would have sent, and whether
  the server's handshake response suggests it validates Origin at
  all. Unlike CORS, browsers do NOT enforce same-origin policy on
  WebSocket connections by default -- if the server authenticates the
  WebSocket connection purely via cookies (ambient authority, same as
  a plain page load) and doesn't check Origin, any website the victim
  visits can open a WebSocket to this app AS the victim and both send
  and receive messages.
- This is the WebSocket equivalent of CSRF, but worse: CSRF is
  typically one-way (attacker can act as the victim, but can't easily
  read the response); CSWSH is often two-way, since the attacker's
  page can read the WebSocket messages that come back.
- Look for: handshake authenticated by cookie alone (no
  token/nonce visible in the handshake request itself), and no
  Origin-allowlist evidence in how the server responded.

MESSAGE-LEVEL VULNERABILITIES:
- Any WebSocket message content that looks like it flows into the
  same sinks HTTP parameters normally would: SQL-like content, HTML
  that would be reflected to other connected clients (stored/DOM XSS
  via a chat-style broadcast feature), file paths, commands. Treat
  these exactly like you would the equivalent HTTP-parameter finding
  -- the delivery mechanism changed, the underlying flaw class didn't.
- Lack of message-level authorization: in a multi-user WebSocket
  channel (chat rooms, live collaboration, trading feeds), can a
  message reference another user's/room's/session's ID and get data
  back that shouldn't be visible to this connection? This is IDOR's
  WebSocket-shaped cousin -- a per-message authorization gap rather
  than a per-request one.
- Missing message-level input validation that would exist on an
  equivalent REST endpoint -- WebSocket message handlers are
  sometimes bolted on with less scrutiny than the REST API for the
  same feature, since they're newer/less templated code.

CONNECTION-LEVEL ISSUES:
- No apparent rate limiting on message frequency (a single connection
  sending as fast as possible with no visible throttling) -- relevant
  to both abuse and resource-exhaustion concerns.
- Sensitive data broadcast to ALL connected clients on a channel
  where it should be scoped to one user/session -- a message meant
  for one recipient leaking to everyone subscribed to a shared topic.

For suggested_test, propose a concrete probe:
- Note whether the Origin header was actually validated: describe
  what response difference (if any) you'd expect between a handshake
  with a legitimate Origin vs. an attacker-controlled one, since
  confirming this needs an actual cross-origin handshake attempt the
  agent alone can't perform
- For message content, describe the same kind of payload you'd use
  for the equivalent HTTP-parameter vulnerability class, adapted to
  this message's field/shape

REMINDER: distinguish "no Origin validation visible in this exchange"
(derived, moderate confidence) from "CSWSH is definitely exploitable
here" (would need to actually open a cross-origin WebSocket and
observe -- out of scope for a single captured exchange; say so).
"""
