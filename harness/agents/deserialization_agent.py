from .base_agent import BaseAgent


class DeserializationAgent(BaseAgent):
    """
    Insecure Deserialization Agent

    Detects evidence that a request or response carries a serialized
    object (as opposed to plain data formats like JSON/XML) that the
    server might deserialize back into a live object -- the classic
    setup for remote code execution via a gadget chain if the
    deserializer isn't restricted to safe types.

    Like race_condition, this was not named in either prior backlog
    for this project -- it's a finding from the later WSTG/PortSwigger
    coverage review, cross-checked against PortSwigger's own topic
    list.
    """
    name = "deserialization"

    tactical_guide = """
1. Look for a serialized-object shape, not just "JSON": Java-serialized
   (`rO0AB` / `\xac\xed`), Python pickle (`\x80\x04` / crafted
   `c__main__`), PHP `O:8:"ClassName"`, or a .NET `TypeObject` marker in a
   request body, cookie, or hidden field.
2. Note the exact sink (a cookie value, a "state" hidden field, a cache
   payload) and whether the app appears to deserialize it BEFORE any
   integrity check (no HMAC/signature covering the blob).
3. This class is unsafe to actively exploit blind -- report the candidate
   shape/sink precisely and let the deterministic OOB-beacon leg confirm it,
   rather than proposing a payload yourself.
"""

    @property
    def specialty_prompt(self) -> str:
        return """
Insecure deserialization. Look for evidence that DATA in this
exchange is actually a SERIALIZED OBJECT (language-specific binary or
structured format carrying type information), not just structured
data like JSON/XML/YAML -- the distinction matters because
deserializing untrusted structured data (JSON.parse, XML parsing) is
usually safe, while deserializing untrusted OBJECT-CARRYING formats
can construct arbitrary objects and, via a gadget chain, execute code.

FORMAT FINGERPRINTS -- look for:
- Java serialized objects: base64-decoded content starting with the
  bytes 0xACED (magic number), or a raw (non-base64) blob starting
  with \\xac\\xed. Base64 text frequently starting with "rO0" is the
  telltale sign of a base64-encoded Java serialized object (rO0
  decodes to 0xAC 0xED 0x00).
- PHP serialized data: values matching PHP's serialization syntax,
  e.g. O:8:"ClassName":N:{...}, a:N:{...} (array), s:N:"string"
  -- especially inside a cookie, hidden form field, or query parameter
  that otherwise looks like an opaque token.
- Python pickle: base64 content that looks like pickle's opcodes
  (often starts with "gAN" or similar for protocol 3+ when
  base64-encoded), or any parameter/cookie whose name/context
  suggests server-side session data stored client-side.
- .NET (BinaryFormatter, ViewState): ASP.NET __VIEWSTATE hidden form
  fields are the classic instance -- especially interesting if
  __VIEWSTATEMAC / EnableViewStateMac evidence is absent or a
  MAC-validation error appears when the value is tampered with.
- Generic tell regardless of language: a parameter/cookie whose value
  is clearly opaque (high-entropy-looking, base64 or hex, no visible
  structure) AND whose presence/absence changes application behavior
  in a way that suggests it carries STATE, not just an identifier --
  a session token is usually just an identifier looked up server-side;
  a serialized object carries the actual state inline.

CONTEXT THAT RAISES CONFIDENCE:
- An error message (even partial, even in a stack trace fragment)
  naming a deserialization-related class/function: readObject,
  ObjectInputStream, unserialize(), pickle.loads, BinaryFormatter,
  Marshal.load (Ruby), yaml.load (specifically the unsafe variant,
  as opposed to yaml.safe_load).
- The application is built on a stack/framework with well-known
  deserialization gadget chains in its dependency tree (this overlaps
  with the supply_chain agent's territory -- if you see a version
  banner AND a serialized-object fingerprint together, that
  combination is worth flagging even if you can't independently
  confirm a gadget chain exists for that exact version).

For suggested_test, propose a concrete probe:
- Note the exact byte/text pattern that identified the format (magic
  bytes, base64 prefix, PHP serialization syntax) as the evidence a
  human or the validator should look for structurally
- Propose sending a minimally-modified version of the same serialized
  blob (flip a byte, truncate it, or -- if a public gadget-chain
  generation tool is relevant to the identified format/framework --
  name the class of tool, e.g. "a Java deserialization gadget chain
  generator," without providing exploit payload bytes yourself) and
  observing whether the server's error response changes in a way
  that confirms it actually attempted to deserialize the content
  (a deserialization-specific exception/stack trace, vs. a generic
  "bad request")

REMINDER: identifying the FORMAT is squarely in scope and should be
high-confidence when the magic bytes/syntax match. Claiming a gadget
chain is EXploitable is a much stronger claim needing much more
evidence (a matching known-vulnerable library version, ideally) --
keep these two confidence levels visibly distinct in the finding.
"""
