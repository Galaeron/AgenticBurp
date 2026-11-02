"""P3-2 supply-chain hardening: digest-pinned image references (tool_runner), the
offline CycloneDX SBOM and image-pin report (supply_chain), and the CI audit job.
The docker seam is mocked -- nothing is pulled or run."""
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import harness.ffuf_runner as ffuf_runner
import harness.supply_chain as sc
import harness.tool_runner as tr

ROOT = Path(__file__).resolve().parent.parent
DIGEST = "sha256:" + "ab" * 32
OTHER = "sha256:" + "cd" * 32


def _result(rc, out, err, args=()):
    return tr.ProcessResult(list(args), rc, out, err, "exit", "not_needed", "job")


class ParseImageRefTests(unittest.TestCase):
    def test_tag_only_is_unpinned(self):
        ref = tr.parse_image_ref("harness/sqlmap:1.10.9")
        self.assertEqual((ref.name, ref.tag, ref.digest), ("harness/sqlmap", "1.10.9", None))
        self.assertFalse(ref.pinned)

    def test_registry_port_is_not_a_tag(self):
        ref = tr.parse_image_ref("registry.local:5000/team/sqlmap")
        self.assertEqual((ref.name, ref.tag), ("registry.local:5000/team/sqlmap", None))

    def test_name_tag_and_digest(self):
        ref = tr.parse_image_ref(f"harness/sqlmap:1.10.9@{DIGEST}")
        self.assertEqual((ref.name, ref.tag, ref.digest), ("harness/sqlmap", "1.10.9", DIGEST))
        self.assertTrue(ref.pinned)
        self.assertFalse(ref.is_image_id)

    def test_bare_image_id_is_pinned(self):
        ref = tr.parse_image_ref(DIGEST)
        self.assertTrue(ref.pinned and ref.is_image_id)

    def test_malformed_digests_are_refused(self):
        for bad in ("img@sha256:abc", "img@sha256:" + "AB" * 32, "img@sha512:" + "ab" * 64,
                    "img@", f"@{DIGEST}", "sha256:abc", "", "img:"):
            with self.subTest(ref=bad), self.assertRaises(tr.ImageReferenceError):
                tr.parse_image_ref(bad)

    def test_require_digest(self):
        with self.assertRaises(tr.ImageReferenceError):
            tr.validate_image_ref("harness/sqlmap:1.10.9", require_digest=True)
        self.assertEqual(tr.validate_image_ref(f"x@{DIGEST}", require_digest=True).digest, DIGEST)


class RunHonoursDigestTests(unittest.TestCase):
    def setUp(self):
        tr._reset_available_cache()
        self.addCleanup(tr._reset_available_cache)

    def test_pinned_reference_reaches_docker_unchanged_and_is_receipted(self):
        seen, receipt = [], {}
        image = f"harness/sqlmap:1.10.9@{DIGEST}"
        with patch.object(tr, "run_process",
                          lambda cmd, **kw: seen.append(cmd) or _result(0, "", "", cmd)):
            tr.run(image, ["--version"], receipt=receipt, require_digest=True)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0][seen[0].index(image) + 1:], ["--version"])
        self.assertEqual(receipt["tool_image_digest"], DIGEST)

    def test_unpinned_reference_still_runs_by_default(self):
        receipt = {}
        with patch.object(tr, "run_process", lambda cmd, **kw: _result(0, "", "", cmd)):
            tr.run("harness/sqlmap:1.10.9", ["--version"], receipt=receipt)
        self.assertIsNone(receipt["tool_image_digest"])

    def test_malformed_digest_is_refused_before_launch(self):
        with patch.object(tr, "run_process") as launch, patch.object(tr, "_force_remove") as rm:
            with self.assertRaises(tr.ImageReferenceError):
                tr.run("harness/sqlmap@sha256:deadbeef", ["--version"])
        launch.assert_not_called()
        rm.assert_not_called()

    def test_require_digest_refuses_unpinned_before_launch(self):
        with patch.object(tr, "run_process") as launch:
            with self.assertRaises(tr.ImageReferenceError):
                tr.run("harness/sqlmap:1.10.9", ["--version"], require_digest=True)
        launch.assert_not_called()


class CallerLevelFfufTests(unittest.TestCase):
    """The ffuf runner passes its configured image straight to tool_runner.run."""

    def test_pinned_image_is_launched_by_the_caller(self):
        seen = []
        image = f"harness/ffuf:2.1.0@{DIGEST}"
        with patch.object(tr, "run_process",
                          lambda cmd, **kw: seen.append(cmd) or _result(0, "", "", cmd)):
            result = ffuf_runner.run_sync("http://127.0.0.1:3002/", image=image)
        self.assertIsNone(result.error)
        self.assertIn(image, seen[0])

    def test_malformed_digest_never_launches_from_the_caller(self):
        with patch.object(tr, "run_process") as launch:
            result = ffuf_runner.run_sync("http://127.0.0.1:3002/",
                                          image="harness/ffuf@sha256:short")
        launch.assert_not_called()
        self.assertIn("malformed digest", result.error)


class VerifyPinnedDigestTests(unittest.TestCase):
    def _inspect(self, image_id, repo_digests, rc=0):
        out = f"{json.dumps(image_id)} {json.dumps(repo_digests)}\n"
        return patch("subprocess.run", return_value=subprocess.CompletedProcess([], rc, out, ""))

    def test_repo_digest_match(self):
        with self._inspect(OTHER, [f"harness/sqlmap@{DIGEST}"]) as m:
            self.assertEqual(tr.verify_pinned_digest(f"harness/sqlmap:1.10.9@{DIGEST}"),
                             (True, "digest matches"))
        self.assertNotIn("pull", m.call_args.args[0])

    def test_repo_digest_mismatch_and_wrong_repo(self):
        with self._inspect(OTHER, [f"harness/sqlmap@{OTHER}", f"evil/sqlmap@{DIGEST}"]):
            ok, reason = tr.verify_pinned_digest(f"harness/sqlmap@{DIGEST}")
        self.assertFalse(ok)
        self.assertIn(DIGEST, reason)

    def test_local_image_id(self):
        with self._inspect(DIGEST, []):
            self.assertTrue(tr.verify_pinned_digest(DIGEST)[0])
        with self._inspect(OTHER, []):
            self.assertFalse(tr.verify_pinned_digest(DIGEST)[0])

    def test_absent_or_unpinned(self):
        with self._inspect("", [], rc=1):
            self.assertIn("not present", tr.verify_pinned_digest(f"x@{DIGEST}")[1])
        with patch("subprocess.run") as m:
            self.assertFalse(tr.verify_pinned_digest("harness/sqlmap:1.10.9")[0])
        m.assert_not_called()


class _Tmp(unittest.TestCase):
    def setUp(self):
        # inside the repo tree, never %TEMP% (Defender, AGENTS.md)
        self._td = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self._td.cleanup)
        self.dir = Path(self._td.name)

    def write(self, name, text):
        path = self.dir / name
        path.write_text(text, encoding="utf-8")
        return path


class RequirementParsingTests(_Tmp):
    def test_pins_ranges_extras_markers_and_comments(self):
        path = self.write("r.txt", "# comment\n-r other.txt\n\nFoo_Bar==1.0  # pinned\n"
                                   "uvicorn[standard]==0.52.4\nmitmproxy>=12.3.1\n"
                                   'backports.zstd==1.7.0; python_version < "3.14"\nbare\n')
        reqs = sc.parse_requirements(path, root=self.dir)
        self.assertEqual([(r.name, r.spec, r.version, r.marker) for r in reqs], [
            ("Foo_Bar", "==1.0", "1.0", ""), ("uvicorn", "==0.52.4", "0.52.4", ""),
            ("mitmproxy", ">=12.3.1", None, ""),
            ("backports.zstd", "==1.7.0", "1.7.0", 'python_version < "3.14"'),
            ("bare", "", None, "")])
        self.assertEqual({r.source for r in reqs}, {"r.txt"})

    def test_unparseable_line_raises(self):
        with self.assertRaises(ValueError):
            sc.parse_requirements(self.write("r.txt", "not a requirement!\n"), root=self.dir)

    def test_dockerfile_from_lines_skip_build_stages(self):
        path = self.write("x.Dockerfile", "FROM golang:1.22 AS build\nRUN true\n"
                                          f"FROM --platform=linux/amd64 debian@{DIGEST}\n"
                                          "COPY --from=build /a /a\nFROM build\n")
        self.assertEqual(sc.dockerfile_base_images(path), ["golang:1.22", f"debian@{DIGEST}"])


class SbomTests(_Tmp):
    def test_components_purls_and_merged_sources(self):
        lock = self.write("requirements.lock", "Foo_Bar==1.0\nbrotli==1.2.1\n")
        proxy = self.write("requirements-proxy.txt", "brotli==1.2.1\nmitmproxy>=12.3.1\n")
        docker = self.write("t.Dockerfile", f"FROM python:3.12-slim@{DIGEST}\n")
        doc = sc.build_sbom([lock, proxy], [docker], root=self.dir)
        self.assertEqual((doc["bomFormat"], doc["specVersion"]), ("CycloneDX", "1.5"))
        by_name = {c["name"]: c for c in doc["components"]}
        self.assertEqual(by_name["foo-bar"]["purl"], "pkg:pypi/foo-bar@1.0")
        self.assertEqual([p["value"] for p in by_name["brotli"]["properties"]],
                         ["requirements.lock", "requirements-proxy.txt"])
        self.assertNotIn("purl", by_name["mitmproxy"])
        self.assertIn({"name": "harness:constraint", "value": ">=12.3.1"},
                      by_name["mitmproxy"]["properties"])
        image = by_name["python"]
        self.assertEqual((image["type"], image["version"]), ("container", "3.12-slim"))
        self.assertEqual(image["hashes"], [{"alg": "SHA-256", "content": "ab" * 32}])
        self.assertEqual(len({c["bom-ref"] for c in doc["components"]}), len(doc["components"]))

    def test_deterministic_and_content_bound(self):
        lock = self.write("requirements.lock", "a==1\n")
        first, second = sc.build_sbom([lock], root=self.dir), sc.build_sbom([lock], root=self.dir)
        self.assertEqual(first, second)
        self.assertNotIn("timestamp", first["metadata"])
        lock.write_text("a==2\n", encoding="utf-8")
        self.assertNotEqual(sc.build_sbom([lock], root=self.dir)["serialNumber"],
                            first["serialNumber"])

    def test_cli_writes_sbom_with_source_date_epoch(self):
        lock = self.write("requirements.lock", "a==1\n")
        out = self.dir / "sbom.json"
        with patch.dict(os.environ, {"SOURCE_DATE_EPOCH": "0"}):
            rc = sc.main(["sbom", "--requirements", str(lock), "--dockerfiles", "--out", str(out)])
        self.assertEqual(rc, 0)
        doc = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(doc["metadata"]["timestamp"], "1970-01-01T00:00:00Z")
        self.assertEqual([c["purl"] for c in doc["components"]], ["pkg:pypi/a@1"])

    def test_real_lock_every_pin_becomes_a_purl(self):
        lock = ROOT / "harness" / "requirements.lock"
        reqs = sc.parse_requirements(lock)
        self.assertTrue(reqs and all(r.version for r in reqs), "the lock must be exact-pinned")
        doc = sc.build_sbom([lock])
        purls = {c.get("purl") for c in doc["components"]}
        for req in reqs:
            self.assertIn(f"pkg:pypi/{sc.normalize_name(req.name)}@{req.version}", purls)


class ImagePinCliTests(_Tmp):
    def test_require_digest_exit_codes(self):
        unpinned = self.write("a.Dockerfile", "FROM python:3.12-slim\n")
        pinned = self.write("b.Dockerfile", f"FROM python:3.12-slim@{DIGEST}\n")
        bad = self.write("c.Dockerfile", "FROM python@sha256:short\n")
        with patch("builtins.print"):
            self.assertEqual(sc.main(["images", "--dockerfiles", str(unpinned)]), 0)
            self.assertEqual(sc.main(["images", "--require-digest", "--dockerfiles",
                                      str(unpinned), str(pinned)]), 1)
            self.assertEqual(sc.main(["images", "--require-digest", "--dockerfiles",
                                      str(pinned)]), 0)
            self.assertEqual(sc.main(["images", "--dockerfiles", str(bad)]), 2)

    def test_repo_dockerfiles_parse(self):
        rows = sc.image_pin_report([ROOT / p for p in sc.DEFAULT_DOCKERFILES])
        self.assertTrue(rows)
        self.assertFalse([r for r in rows if r["error"]])


class CiAuditJobTests(unittest.TestCase):
    def test_dependency_audit_job_audits_the_lock_and_emits_the_sbom(self):
        import yaml
        jobs = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))["jobs"]
        job = jobs["dependency-audit"]
        scripts = " ".join(step.get("run", "") for step in job["steps"])
        self.assertIn("pip-audit -r harness/requirements.lock", scripts)
        self.assertIn("python -m harness.supply_chain sbom", scripts)
        self.assertIn("python -m harness.supply_chain images", scripts)
        self.assertRegex(scripts, r"pip-audit==\d+\.\d+\.\d+")


if __name__ == "__main__":
    unittest.main()
