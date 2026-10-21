# Protected routes (`authz.protected_paths`)

The engagement chain confirms missing authentication only on a route the operator has declared
protected. An undeclared route that serves data anonymously stays an unconfirmed
`unauthenticated_access` candidate: a model label or a privileged-looking path is never a
declaration. Owner decision of 2026-10-21; implemented by batch RV-S
(`harness/protected_routes.py`, handoff `.test-work/rv-s-protectedroutes-20261021/HANDOFF.md`).

## Where the list comes from

- `authz.protected_paths` in the git-ignored `harness/config.local.yaml`: a mapping from the
  target to a list of patterns. The shipped `harness/config.yaml` has only a commented example,
  so the effective default is empty.
- The target key is the host, or `host:port` when the port is not the scheme's default. The host
  compares case-insensitively and exactly: no wildcards and no URL.
- A bare host means the default port only (80 for http, 443 for https), so `127.0.0.1` does not
  cover `127.0.0.1:8080`. IPv6 is written `[::1]:8443`.
- The engagement's own list (`EngagementState.protected_paths`) applies to that engagement's
  target and combines with the config list. Nothing sets it from the Burp UI or the API yet
  (I16 follow-up).

```yaml
authz:
  protected_paths:
    "app.example.test": ["/admin/**", "GET /api/account/*"]
    "127.0.0.1:8080": ["/reports/*"]
```

## Pattern syntax

- An optional HTTP method (letters), then a path starting with `/`. A pattern with no method
  matches every method, but only safe methods are probed.
- The pattern is anchored to the whole request path. Both the path and the pattern are
  normalized as `engagement.normalize_path` does: the query and fragment are dropped, and numeric
  and long-hex segments become `{id}`. So `/orders/42`, `/orders/{id}` and `/orders/*` all match
  `/orders/7`.
- `*` matches within one segment. `**`, which must be a whole segment, matches zero or more
  segments: `/admin/**` matches `/admin`, `/admin/x` and `/admin/x/y`.
- Paths compare case-sensitively; the method compares case-insensitively.
- Globs, not regular expressions, so a pattern cannot cause a ReDoS blow-up.
- Ignored with a logged warning (and reported by `config_schema.validate_config`), never making a
  route protected: a non-string or empty entry; more than 1024 characters; no leading `/`; a `?`
  or `#`; `**` inside a segment; a method that is not letters, or more than one method; a host
  key that is a URL, a wildcard, empty or has an invalid port; a section of the wrong type.

## What confirms

All of these must hold:

- the route (method and normalized path) matches a pattern for this target;
- the anonymous replay, with every known credential header and every other header a supplied
  identity sets removed, returns a substantive response;
- an authenticated baseline returns the same substantive payload. The baseline uses the
  exchange's own credentials, or else the highest-trust supplied identity's.

The finding's evidence then ends with `Route declared protected by pattern '<p>' from the
<config|engagement> (<where>).`, and the finding carries `protected_route: {pattern, source,
where}`.

## What does not confirm

- An unlisted route, even one that serves data anonymously (a candidate).
- On a listed route: an anonymous replay that is refused (no finding); an anonymous answer that
  differs from the baseline, such as a public help page; a baseline with no payload; no identity
  supplying a known credential header; a malformed entry.
- An app that authenticates only through a custom header (for example `X-Tenant-Session`)
  cannot confirm yet: the baseline carries only known credential headers (fail closed).
