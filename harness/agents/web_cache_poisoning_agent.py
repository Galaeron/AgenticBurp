from .base_agent import BaseAgent


class WebCachePoisoningAgent(BaseAgent):
    """
    Web Cache Poisoning Agent

    Detects conditions that let an attacker cause a shared cache (CDN,
    reverse proxy, or the application's own cache layer) to store a
    malicious or attacker-controlled response and serve it to other
    users. This is distinct from ordinary CORS/reflection bugs because
    the payload only has to be sent ONCE -- every subsequent visitor
    who hits the cached URL gets the poisoned response for free.

    Coverage includes:
    - Unkeyed input reflected into the response (headers not part of
      the cache key: X-Forwarded-Host, X-Forwarded-Scheme,
      X-Forwarded-Port, X-Original-URL, Host)
    - Cacheable responses that vary based on unkeyed input
    - Web cache deception (sensitive/dynamic content served under a
      path that looks static and gets cached, e.g. /account/settings.css)
    - Fat GET / parameter cloaking where unkeyed query params change
      the response
    """
    name = "web_cache_poisoning"

    tactical_guide = """
1. Look for signals a caching layer is present (`X-Cache`, `Age`, `CF-Cache-
   Status`, a `Vary` header) and note whether the response includes content
   that varies by a header/cookie NOT listed in `Vary` -- that's the
   concrete cache-key mismatch signal.
2. Check whether an unkeyed input (a header like `X-Forwarded-Host`, or a
   cache-busting-looking query param) appears reflected into the cached
   response body -- that's what makes poisoning practical, not just cache
   presence alone.
3. This needs a second, unauthenticated request to the SAME cache key to
   confirm the poisoned response was actually served to someone else --
   name that as the required confirmation step.
"""

    @property
    def specialty_prompt(self) -> str:
        return """
Web cache poisoning. A shared cache sits in front of (or inside) the
application and stores responses keyed on a subset of the request --
typically method, path, and a few whitelisted headers/params. Anything
NOT part of that cache key is "unkeyed": the cache will still forward
it to the origin, the origin's response may still depend on it, but
the cache doesn't know to vary the stored copy by it. If an attacker
can make an unkeyed input change the response, and that response then
gets cached, every subsequent visitor to that cache key receives the
attacker's version.

UNKEYED INPUT REFLECTION -- look for:
- Host header, X-Forwarded-Host, X-Forwarded-Scheme, X-Forwarded-Port,
  X-Forwarded-Server, X-Original-URL, X-Rewrite-URL reflected anywhere
  in the response body (absolute URLs built from the Host header are
  the classic case -- canonical link tags, password reset links,
  asset URLs, Open Graph tags, JSON API responses embedding a
  self-referential URL).
- A response that changes based on a header the application almost
  certainly doesn't need for that endpoint (debug headers, custom
  X- headers, User-Agent-based content variants).
- Any of the above appearing in a response that ALSO carries cache
  indicators (see below) -- reflection alone is not cache poisoning,
  it needs to combine with cacheability.

CACHEABILITY SIGNALS -- look for:
- Cache-Control: public, s-maxage=N, max-age=N (especially large N)
- Age header present (already served from cache at least once)
- X-Cache, X-Cache-Status, CF-Cache-Status, X-Varnish, X-Served-By
  (identifies the caching layer itself, e.g. HIT/MISS/DYNAMIC)
- Vary header that's absent or too narrow given what the response
  actually depends on (e.g. Vary: Accept-Encoding but the body
  content differs by Host header, which isn't listed)
- Surrogate-Control, Edge-Control (CDN-specific caching directives)

WEB CACHE DECEPTION -- a related but distinct bug:
- A path with a static-looking suffix (.css, .js, .jpg, /nonexistent.js)
  appended after a dynamic/authenticated path segment
  (e.g. /my-account/settings.css, /api/user/profile/x.jpg) that the
  origin still serves as the real dynamic/authenticated content, while
  the cache (going only by the static-looking extension) stores it as
  a shared static asset. The next visitor to that exact URL -- if they
  can guess or predict it -- gets someone else's cached account page.

FAT GET / PARAMETER CLOAKING:
- A query parameter that changes the response but isn't part of the
  cache key (common when the cache key is configured to only include
  specific whitelisted params, or none at all for a "static" route).
- Duplicate/cloaked parameters (?callback=x&callback=y) that different
  layers of the stack parse differently -- one layer's cache key vs.
  the origin's actual parameter handling can disagree.

For suggested_test, propose a concrete unkeyed-input probe:
- Add a distinctive X-Forwarded-Host (e.g. cache-poison-test-<random>.
  example) and check whether it's reflected in the response body or in
  a redirect Location header
- Re-request the exact same URL WITHOUT the injected header and check
  whether the poisoned value is still being served (proves it was
  cached, not just reflected per-request)
- For deception: request the tested endpoint with a static-looking
  suffix appended and compare the response to the real dynamic page

REMINDER: cache poisoning findings are unusually high-impact because,
unlike most reflected bugs, the attacker does not need to keep sending
the payload or trick each victim individually -- one successful
poisoning request compromises every subsequent visitor to that cache
key until the entry expires or is purged.
"""
