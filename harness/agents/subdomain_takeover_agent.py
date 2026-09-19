from .base_agent import BaseAgent


class SubdomainTakeoverAgent(BaseAgent):
    """
    Subdomain Takeover Agent

    Detects dangling references to third-party services: a DNS record
    (typically CNAME) or an application-level link still points at a
    cloud service resource (GitHub Pages, S3 bucket, Heroku app,
    Azure endpoint, etc.) that has since been deleted or deregistered.
    An attacker who claims that same resource name on the still-active
    provider gains control of content served under the organization's
    own subdomain -- with all the trust (cookies, CSP allowances, CORS
    allowlisting, phishing credibility) that implies.

    This agent works from what a single HTTP exchange can show: an
    error page fingerprint from a decommissioned cloud service, a link
    or CNAME-like reference to a third-party subdomain in the response,
    or a response that itself looks like an "unclaimed resource" page.
    """
    name = "subdomain_takeover"

    tactical_guide = """
1. Look for a CNAME-shaped hostname reference (in a header, redirect
   target, or response body) that points at a third-party PaaS domain
   (e.g. an *.github.io, *.herokuapp.com, *.s3.amazonaws.com-shaped
   pattern) rather than the app's own infrastructure.
2. Note any response that looks like the THIRD-PARTY SERVICE's own
   "not found"/"no such app/bucket" page reached through the app's own
   domain -- that's the concrete signal a dangling DNS record exists.
3. This can only be confirmed by checking whether that third-party name is
   actually unclaimed and registerable -- say that's the required next
   step, not something this exchange alone proves.
"""

    @property
    def specialty_prompt(self) -> str:
        return """
Subdomain takeover via dangling references to third-party cloud
services. Look for two different kinds of evidence in this exchange:

EVIDENCE OF A DANGLING REFERENCE (the setup):
- Links, redirects, asset URLs, or CNAME-style hostnames in the
  response body pointing to *.github.io, *.herokuapp.com,
  *.herokudns.com, s3.amazonaws.com or <bucket>.s3.amazonaws.com,
  *.azurewebsites.net, *.cloudapp.net, *.blob.core.windows.net,
  *.trafficmanager.net, *.shopify.com/*.myshopify.com,
  *.wpengine.com, *.fastly.net, *.pantheonsite.io, *.surge.sh,
  *.bitbucket.io, *.zendesk.com, *.helpjuice.com,
  *.statuspage.io, *.readme.io, *.ghost.io, *.webflow.io,
  *.unbouncepages.com, *.tilda.ws, *.pagelab.io, or similar
  vanity/CNAME-based hosting -- any of these under a subdomain that
  looks like it belongs to the organization being tested
  (e.g. blog.company.com pointing at a Ghost/WPEngine/Pantheon
  service, status.company.com pointing at Statuspage/Zendesk).

EVIDENCE THE TARGET RESOURCE IS UNCLAIMED (the confirmation):
- The response ITSELF is an "unclaimed"/"not found"/"no such app"
  page from one of these providers, e.g.:
  * "There isn't a GitHub Pages site here" (GitHub Pages)
  * "NoSuchBucket" / "The specified bucket does not exist" (S3)
  * "No such app" / herokucdn.com/error-pages/no-such-app.html (Heroku)
  * "Sorry, this shop is currently unavailable" (Shopify, sometimes)
  * "The gods are wise, but do not know of this page" (Fastly)
  * "Repository not found" combined with a *.bitbucket.io URL
  * A generic DNS/CNAME resolution succeeding (the request reached
    SOME server) while the content clearly indicates the specific
    named resource was never claimed or has been deleted, as opposed
    to a normal 404 within a live application.

Distinguish this from an ordinary 404: an ordinary 404 comes from the
organization's OWN application returning "page not found" for a bad
path. A takeover candidate comes from a THIRD-PARTY PROVIDER'S
infrastructure saying "this specific named resource doesn't exist on
our platform" -- the hostname resolves and something answers, but
that something isn't the organization's content.

For suggested_test, propose:
- If you saw a dangling reference (a link/CNAME to a third-party
  service) but not yet the unclaimed-resource confirmation: fetch
  that specific subdomain/hostname directly and check the response
  for the provider's own "not claimed" fingerprint
- If you saw an unclaimed-resource fingerprint: check what hostname
  under the organization's own domain currently CNAMEs or links to
  that resource, since that hostname is the actual takeover target
- Note that registering the resource on the third-party provider to
  fully confirm control is an active step with real-world side
  effects (claims the name) and should be flagged as needing
  explicit analyst approval, not run automatically

REMINDER: report this even at moderate confidence if you see either
half of the pattern (dangling reference OR unclaimed-fingerprint
response) without the other -- the validator can attempt to complete
the confirmation by fetching the specific hostname directly.
"""
