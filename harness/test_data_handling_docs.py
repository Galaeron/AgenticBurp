"""DOC-4: the data-handling statements in docs/USER_MANUAL.md section 5 and docs/LIMITATIONS.md are
the behaviour of harness/security.py, and the stale notes are gone.

Section 5 of the manual carries a table of nine classes, each marked *withheld* or *sent*. This module
holds one probe per class: a sample run through the real sanitiser that must come out withheld or
unchanged as the table says. The class ids in the table and in `PROBES` must be the same set, so a
statement without a probe, or a probe without a statement, fails. A caller-level test then sends the
samples through `OllamaClient` and reads what reaches the wire; its control replaces the provider-boundary
sanitiser with the identity (the pre-DOC-4 claim "sent unredacted") and shows the samples would go out.
"""
import json
import re
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

from harness import ollama_client, security
from harness.ollama_client import OllamaClient
from harness.testing_fixtures.model_pacer import fresh_model_pacer

ROOT = Path(__file__).resolve().parent.parent
MANUAL = (ROOT / "docs/USER_MANUAL.md").read_text(encoding="utf-8")
LIMITATIONS = (ROOT / "docs/LIMITATIONS.md").read_text(encoding="utf-8")
SECRET = "S3cr3tValue-9f2c"
PLACEHOLDER = security.SECRET_VALUE_PLACEHOLDER
_REAL_ASYNC_CLIENT = httpx.AsyncClient


def manual_classes(text: str) -> dict[str, str]:
    """class id -> 'withheld' | 'sent', from the table in section 5."""
    section = text[text.index("## 5. Data handling"):text.index("## 6. Building")]
    return {m[1]: ("sent" if "sent" in m[2] else "withheld")
            for m in re.finditer(r"^\| `([a-z-]+)` \| (\*\*sent\*\*|withheld) \|", section, flags=re.M)}


def _header_values():
    names = ("Authorization", "Cookie", "Set-Cookie", "X-API-Key", "X-Auth-Token", "Proxy-Authorization")
    redacted = security.redact_headers({name: SECRET for name in names})
    return all(SECRET not in value for value in redacted.values()) and len(redacted) == len(names)


def _jwt_header_only():
    token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhbGljZSJ9.sig"          # {"alg":"none"} . {"sub":"alice"}
    shown = security.redact_headers({"Authorization": "Bearer " + token})["Authorization"]
    return '"alg": "none"' in shown and "alice" not in shown and "sig" not in shown.split("JWT header only")[1]


def _secret_named_fields():
    body = json.dumps({"password": SECRET, "user": {"api_key": SECRET, "session": SECRET}, "csrf": SECRET})
    form = f"token={SECRET}&q=1"
    kv = f"secret: {SECRET}"
    clean = [security.sanitize_text(text) for text in (body, form, kv)]
    return all(SECRET not in text for text in clean) and "q=1" in clean[1]


def _url_secrets():
    clean = security.sanitize_text(f"see https://alice:{SECRET}@host/p?token={SECRET}&q=1#access_token={SECRET}")
    return SECRET not in clean and "q=1" in clean


def _inline_assignments():
    clean = security.sanitize_text(f'accessToken={SECRET} and "api_key": "{SECRET}"\nAuthorization: Bearer {SECRET}')
    return SECRET not in clean


def _known_values():
    value = "opaque-value-1234"
    return value not in security.sanitize_text(f"x {value} y", known_values=(value,)) and \
        value in security.sanitize_text(f"x {value} y")


def _pii():
    sample = ("Jo Smith", "jo.smith@example.com", "+1 555 0100", "1 Main St", "1990-01-01",
              "4111111111111111", "123-45-6789")
    body = json.dumps({"name": sample[0], "email": sample[1], "phone": sample[2], "address": sample[3],
                       "dob": sample[4], "card": sample[5], "ssn": sample[6]})
    clean = security.sanitize_text(body)
    return all(value in clean for value in sample)


def _unlisted_names():
    return SECRET in security.sanitize_text(json.dumps({"jwt": SECRET}))


def _unlabelled_values():
    prose = f"the recovery code is {SECRET} please keep it"
    note = json.dumps({"note": f"Bearer {SECRET}"})
    return SECRET in security.sanitize_text(prose) and SECRET in security.sanitize_text(note)


def _injection_payloads():
    payload = "<script>alert(1)</script> ' OR '1'='1"
    body = json.dumps({"search": payload})
    url = f"http://host/s?q={payload}"
    return payload in security.sanitize_text(body) and security.redact_secrets_in_url(url) == url


# class id -> (documented treatment, probe that is true when the sanitiser behaves that way)
PROBES = {
    "header-values": ("withheld", lambda: _header_values() and _jwt_header_only()),
    "secret-named-fields": ("withheld", _secret_named_fields),
    "url-secrets": ("withheld", _url_secrets),
    "inline-assignments": ("withheld", _inline_assignments),
    "known-values": ("withheld", _known_values),
    "pii": ("sent", _pii),
    "unlisted-names": ("sent", _unlisted_names),
    "unlabelled-values": ("sent", _unlabelled_values),
    "injection-payloads": ("sent", _injection_payloads),
}

# Wording the audit found stale, per document. A phrase listed here must not come back.
STALE = {
    "USER_MANUAL.md": ("sent to the model unredacted", "Only auth\n  *headers* are masked"),
    "LIMITATIONS.md": ("Bodies sent to the model unredacted", "Redaction before cloud is not implemented",
                       "is why\n  some active-gate unit tests are red", "in-flight in the working tree"),
}


def stale_phrases(name: str, text: str) -> list[str]:
    return [phrase for phrase in STALE[name] if phrase in text]


class DocumentedClassesTests(unittest.TestCase):
    def test_every_documented_class_has_a_probe_and_every_probe_a_statement(self):
        self.assertEqual(manual_classes(MANUAL), {name: treatment for name, (treatment, _) in PROBES.items()})

    def test_each_class_behaves_as_the_manual_says(self):
        for name, (treatment, probe) in PROBES.items():
            with self.subTest(cls=name, documented=treatment):
                self.assertTrue(probe(), f"{name}: security.py does not {treatment} this class")

    def test_the_documented_header_names_are_exactly_the_redacted_set(self):
        section = MANUAL[MANUAL.index("`header-values`"):MANUAL.index("`secret-named-fields`")]
        documented = {"authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token", "proxy-authorization"}
        for name in documented:
            self.assertIn(name, section.lower())
        self.assertEqual(documented, set(security.SECRET_HEADER_NAMES))

    def test_the_example_secret_names_are_on_the_list(self):
        section = MANUAL[MANUAL.index("`secret-named-fields`"):MANUAL.index("`url-secrets`")]
        names = re.findall(r"`([a-z_]+)`", section.split("|")[2])
        self.assertGreaterEqual(len(names), 5, "the row should name example secret names")
        for name in names:
            self.assertIn(name, security.SECRET_FIELD_NAMES, name)

    def test_the_guard_notices_a_class_the_sanitiser_does_not_withhold(self):
        # `jwt` is documented as sent; a policy that also withheld it would make the probe false.
        with patch.object(security, "SECRET_FIELD_NAMES", security.SECRET_FIELD_NAMES | {"jwt"}):
            self.assertFalse(_unlisted_names())

    def test_the_guard_notices_pii_redaction_being_added(self):
        real = security.sanitize_text

        def over_redacting(text, **kw):
            return real(text, **kw).replace("jo.smith@example.com", PLACEHOLDER)

        with patch.object(security, "sanitize_text", over_redacting):
            self.assertFalse(_pii())


class StalePhraseTests(unittest.TestCase):
    def test_the_stale_notes_are_gone(self):
        self.assertEqual(stale_phrases("USER_MANUAL.md", MANUAL), [])
        self.assertEqual(stale_phrases("LIMITATIONS.md", LIMITATIONS), [])

    def test_the_guard_reports_the_pre_fix_statements(self):
        old_manual = "- Request/response **bodies are sent to the model unredacted.** Only auth\n  *headers* are masked."
        old_limits = ("- **[open] Bodies sent to the model unredacted; cloud egress needs a policy.**\n"
                      "  See USER_MANUAL §5. Redaction before cloud is not implemented.\n"
                      "(This migration is in-flight in the working tree and is why\n  some active-gate unit tests are red.)")
        self.assertEqual(len(stale_phrases("USER_MANUAL.md", old_manual)), 2)
        self.assertEqual(len(stale_phrases("LIMITATIONS.md", old_limits)), 4)

    def test_the_two_documents_agree_on_the_egress_gate(self):
        for text in (MANUAL, LIMITATIONS):
            self.assertIn("allow_cloud_models", text)
        self.assertIn("409", MANUAL)
        self.assertIn("model_egress", MANUAL)


class ModelBoundaryTests(unittest.IsolatedAsyncioTestCase):
    """A caller-level check of the first sentence of section 5: what reaches the wire."""

    def _client(self, captured):
        fresh_model_pacer(self)
        client = OllamaClient(base_url="http://fake-ollama:11434")

        def handler(request: httpx.Request) -> httpx.Response:
            captured.append(request.content.decode("utf-8"))
            return httpx.Response(200, json={"message": {"content": json.dumps({"ok": True})}, "done": True})

        class PatchedAsyncClient(_REAL_ASYNC_CLIENT):
            def __init__(self, *args, **kwargs):
                kwargs["transport"] = httpx.MockTransport(handler)
                super().__init__(*args, **kwargs)

        ollama_client.httpx.AsyncClient = PatchedAsyncClient
        self.addCleanup(setattr, ollama_client.httpx, "AsyncClient", _REAL_ASYNC_CLIENT)
        return client

    PROMPT = json.dumps({"password": SECRET, "email": "jo.smith@example.com", "q": "<script>alert(1)</script>"})

    async def test_a_secret_named_field_is_withheld_and_pii_is_sent(self):
        captured = []
        await self._client(captured).chat_json(model="m", system_prompt="s", user_prompt=self.PROMPT)
        wire = captured[0]
        self.assertNotIn(SECRET, wire)
        self.assertIn(PLACEHOLDER, wire)
        self.assertIn("jo.smith@example.com", wire)
        self.assertIn("alert(1)", wire)

    async def test_control_without_the_boundary_sanitiser_the_secret_would_go_out(self):
        captured = []
        with patch("harness.security.sanitize_for_inference", lambda system, user: (system, user)):
            await self._client(captured).chat_json(model="m", system_prompt="s", user_prompt=self.PROMPT)
        self.assertIn(SECRET, captured[0])


class SafetyLedgerDocsTests(unittest.TestCase):
    """The HS-* paragraph of TESTING.md and the coverage bullet of LIMITATIONS.md describe the ledger
    d3 built (GAP-4, GAP-2); they must name what coverage_manifest declares."""

    def test_testing_md_names_the_declared_safety_ledger(self):
        from harness import coverage_manifest as cm
        testing = (ROOT / "docs/TESTING.md").read_text(encoding="utf-8")
        for needle in ("SAFETY_PROPERTIES", "_SAFETY_EVIDENCE", "harness/test_live_safety_loopback.py"):
            self.assertIn(needle, testing)
        self.assertTrue(hasattr(cm, "SAFETY_PROPERTIES") and hasattr(cm, "_SAFETY_EVIDENCE"))
        self.assertTrue((ROOT / "harness/test_live_safety_loopback.py").is_file())
        self.assertTrue(cm.SAFETY_PROPERTIES and all(p.id.startswith("HS-") for p in cm.SAFETY_PROPERTIES))

    def test_limitations_keeps_the_ledger_bullet_and_separates_hs_from_wstg(self):
        flat = " ".join(LIMITATIONS.split())
        self.assertIn("The `HS-*` harness safety properties are reported in their own section "
                      "and are not WSTG coverage.", flat)
        self.assertIn("**blocks** when a registered test fails, is skipped, or left no fresh evidence", flat)


if __name__ == "__main__":
    unittest.main()
