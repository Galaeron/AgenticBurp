"""DOC-3: the operator first-run step list in README.md and docs/USER_MANUAL.md agrees with the code.

Six steps (Python, install from the lock, model and context settings, the Burp build, pairing,
a first /analyze). Each statement the steps make about a version, a default, a file, a route or a
request shape is checked here against the file or module that owns it, so a change to the lock,
the config defaults, the Gradle pins or the token path fails this test until the docs follow.

Not covered, and not claimed: the clean-machine walk-through (a new operator reaching a first
/analyze result in 30 minutes). That is an owner step; the docs mark it unverified.
"""
import ast
import json
import re
import tomllib
import unittest
from pathlib import Path

import yaml

from harness import ollama_client
from harness.models import AnalysisRequest, AnalysisResponse

ROOT = Path(__file__).resolve().parent.parent
README = (ROOT / "README.md").read_text(encoding="utf-8")
MANUAL = (ROOT / "docs/USER_MANUAL.md").read_text(encoding="utf-8")
CONFIG = yaml.safe_load((ROOT / "harness/config.yaml").read_text(encoding="utf-8"))
STEPS = ["Python", "Install from the lock", "Model and context settings",
         "Build the Burp extension", "Start the server and pair", "A first `/analyze`"]


def readme_steps(text: str) -> list[str]:
    """`**N. Title.**` step markers in the README's Quick Start."""
    quick = text[text.index("## Quick Start"):text.index("## Testing")]
    return [m[2].rstrip(".") for m in re.finditer(r"^\*\*(\d)\. (.+?)\*\*", quick, flags=re.M)]


def manual_steps(text: str) -> list[str]:
    """`### N. Title` step headings in USER_MANUAL section 1, without a parenthetical."""
    first = text[text.index("## 1. First run"):text.index("## 2. Scope")]
    return [re.sub(r"\s*\(.*\)$", "", m[1]) for m in re.finditer(r"^### \d\. (.+)$", first, flags=re.M)]


def fenced_blocks(text: str, language: str) -> list[str]:
    return re.findall(rf"```{language}\n(.*?)```", text, flags=re.S)


SERVER_SOURCES = [ROOT / "harness/server.py", *sorted((ROOT / "harness").glob("server_routes_*.py"))]


def server_routes() -> set[tuple[str, str]]:
    """(METHOD, path) for every @app.<method>("...") or @router.<method>("...")
    decorator in harness/server.py and its router modules (ARC-9)."""
    found = set()
    for source in SERVER_SOURCES:
        for node in ast.walk(ast.parse(source.read_text(encoding="utf-8"))):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for dec in node.decorator_list:
                    if (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
                            and isinstance(dec.func.value, ast.Name)
                            and dec.func.value.id in ("app", "router")
                            and dec.args and isinstance(dec.args[0], ast.Constant)):
                        found.add((dec.func.attr.upper(), dec.args[0].value))
    return found


class StepListTests(unittest.TestCase):
    def test_the_readme_and_the_manual_list_the_same_six_steps_in_order(self):
        self.assertEqual(readme_steps(README), STEPS)
        self.assertEqual(manual_steps(MANUAL), STEPS)

    def test_the_guard_notices_a_missing_step(self):
        self.assertNotEqual(readme_steps(README.replace("**2. Install from the lock**", "Install")), STEPS)

    def test_both_docs_mark_the_clean_machine_walk_through_unverified(self):
        for name, text in (("README.md", README), ("USER_MANUAL.md", MANUAL)):
            with self.subTest(doc=name):
                self.assertIn("unverified", text.lower())
                self.assertIn("30-minute", text)


def python_range_problems(text: str) -> list[str]:
    problems = [f"does not say {needle!r}" for needle in ("Python 3.11 or newer", "3.14") if needle not in text]
    if "Python 3.12+" in text:
        problems.append("still says 'Python 3.12+'")
    return problems


class PythonAndInstallTests(unittest.TestCase):
    def test_the_guard_catches_the_pre_fix_prerequisite(self):
        stale = "- **Python 3.12+** with dependencies (FastAPI, httpx, PyYAML, pydantic)"
        self.assertEqual(python_range_problems(stale),
                         ["does not say 'Python 3.11 or newer'", "does not say '3.14'", "still says 'Python 3.12+'"])

    def test_the_python_range_is_the_one_pyproject_and_ci_declare(self):
        floor = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["requires-python"]
        self.assertEqual(floor, ">=3.11")
        ci = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))["jobs"]
        versions = {str(step["with"]["python-version"]) for job in ci.values() for step in job.get("steps", [])
                    if isinstance(step, dict) and "python-version" in (step.get("with") or {})}
        self.assertEqual(versions, {"3.14"})
        for name, text in (("README.md", README), ("USER_MANUAL.md", MANUAL)):
            with self.subTest(doc=name):
                self.assertEqual(python_range_problems(text), [])

    def test_the_install_commands_use_files_that_exist(self):
        for name, text in (("README.md", README), ("USER_MANUAL.md", MANUAL)):
            with self.subTest(doc=name):
                for command in ("pip install -r harness/requirements.lock", "pip install -e . --no-deps",
                                "python -m harness.lock_preflight"):
                    self.assertIn(command, text)
        self.assertTrue((ROOT / "harness/requirements.lock").is_file())
        self.assertTrue((ROOT / "harness/lock_preflight.py").is_file())


def model_setting_problems(text: str) -> list[str]:
    """Statements in step 3 that disagree with the shipped config or the code."""
    problems = []
    recommended = ollama_client.recommended_num_ctx(ollama_client.ESTIMATED_LARGEST_PROMPT_TOKENS)
    if f"num_ctx: {recommended}" not in text:
        problems.append(f"num_ctx: {recommended} (the value ollama_client recommends) is not documented")
    fallback = CONFIG["prompt_budget"]["unknown_context_tokens"]
    if f"`prompt_budget.unknown_context_tokens` ({fallback})" not in text:
        problems.append(f"the unknown-window fallback ({fallback}) is not documented")
    for needle in ("allow_cloud_models", "409", "model_rate_limit"):
        if needle not in text:
            problems.append(f"does not mention {needle}")
    for key, value in CONFIG["ollama"]["rate_limit"].items():
        if f"`{key}: {str(value).lower()}`" not in text:
            problems.append(f"the shipped rate_limit.{key} ({value}) is not documented")
    return problems


class ModelSettingsTests(unittest.TestCase):
    def test_step_3_agrees_with_the_shipped_config_and_the_code(self):
        for name, text in (("README.md", README), ("USER_MANUAL.md", MANUAL)):
            with self.subTest(doc=name):
                self.assertEqual(model_setting_problems(text), [])

    def test_the_shipped_defaults_the_docs_rely_on(self):
        self.assertNotIn("num_ctx", CONFIG["ollama"], "the shipped config must leave num_ctx unset")
        self.assertIs(CONFIG["ollama"]["allow_cloud_models"], False)
        self.assertEqual(set(CONFIG["ollama"]["rate_limit"]),
                         {"enabled", "burst_calls", "calls_per_minute", "max_wait_seconds"})

    def test_the_guard_notices_each_drifted_statement(self):
        shipped = CONFIG["ollama"]["rate_limit"]
        recommended = ollama_client.recommended_num_ctx(ollama_client.ESTIMATED_LARGEST_PROMPT_TOKENS)
        drifts = {
            "num_ctx": (f"num_ctx: {recommended}", "num_ctx: 8192"),
            "fallback": ("unknown_context_tokens` (", "unknown_context_tokens` (1"),
            "pacer": (f"`calls_per_minute: {shipped['calls_per_minute']}`", "`calls_per_minute: 60`"),
            "cloud": ("allow_cloud_models", "allow_models"),
        }
        for label, (old, new) in drifts.items():
            with self.subTest(drift=label):
                stale = MANUAL.replace(old, new)
                self.assertNotEqual(stale, MANUAL)
                self.assertTrue(model_setting_problems(stale), f"the guard misses a drifted {label}")


class BuildTests(unittest.TestCase):
    def test_the_documented_toolchain_is_the_pinned_one(self):
        props = (ROOT / "burp-extension/gradle/wrapper/gradle-wrapper.properties").read_text(encoding="utf-8")
        self.assertIn("gradle-8.7-bin.zip", props)
        self.assertIn("distributionSha256Sum=", props)
        build = (ROOT / "burp-extension/build.gradle").read_text(encoding="utf-8")
        self.assertIn("JavaLanguageVersion.of(17)", build)
        for name, text in (("README.md", README), ("USER_MANUAL.md", MANUAL)):
            with self.subTest(doc=name):
                self.assertIn("./gradlew shadowJar", text)
                self.assertIn("gradlew.bat shadowJar", text)
                self.assertIn("JDK 17", text)
        self.assertIn("Gradle 8.7", README)
        self.assertIn("Gradle 8.7", MANUAL)
        self.assertTrue((ROOT / "burp-extension/gradlew").is_file())


class PairingAndAnalyzeTests(unittest.TestCase):
    def test_the_documented_token_file_and_routes_exist(self):
        server = (ROOT / "harness/server.py").read_text(encoding="utf-8")
        self.assertIn('TOKEN_LOCKFILE_PATH = Path(__file__).parent / ".harness_token.lock"', server)
        routes = server_routes()
        for route in (("GET", "/pairing/check"), ("GET", "/health"), ("GET", "/health/details"),
                      ("POST", "/analyze")):
            self.assertIn(route, routes)
        for name, text in (("README.md", README), ("USER_MANUAL.md", MANUAL)):
            with self.subTest(doc=name):
                self.assertIn("harness/.harness_token.lock", text)
                self.assertIn("/pairing/check", text)
                self.assertIn("**Pairing token**", text)

    def test_the_burp_side_of_pairing_is_what_the_docs_say(self):
        panel = (ROOT / "burp-extension/src/main/java/com/harness/llm/ui/HarnessPanel.java").read_text(encoding="utf-8")
        client = (ROOT / "burp-extension/src/main/java/com/harness/llm/HarnessClient.java").read_text(encoding="utf-8")
        self.assertIn('new JLabel("Pairing token:")', panel)
        self.assertIn('System.getenv("HARNESS_BEARER_TOKEN")', client)
        for text in (README, MANUAL):
            self.assertIn("HARNESS_BEARER_TOKEN", text)

    def test_the_example_exchange_is_a_valid_analysis_request(self):
        for name, text in (("README.md", README), ("USER_MANUAL.md", MANUAL)):
            with self.subTest(doc=name):
                blocks = fenced_blocks(text, "json")
                self.assertEqual(len(blocks), 1, "exactly one example exchange")
                request = AnalysisRequest.model_validate(json.loads(blocks[0]))
                self.assertEqual(request.exchange.method, "POST")
        self.assertEqual(json.loads(fenced_blocks(README, "json")[0]), json.loads(fenced_blocks(MANUAL, "json")[0]))

    def test_the_example_is_rejected_when_it_is_not_an_exchange(self):
        with self.assertRaises(ValueError):
            AnalysisRequest.model_validate({"exchange": {"method": "GET"}})  # no url

    def test_the_response_fields_the_docs_name_exist(self):
        fields = set(AnalysisResponse.model_fields)
        for field in ("dispatched_agents", "agent_reports", "summary", "degraded", "agent_errors"):
            self.assertIn(field, fields)
            self.assertIn(field, MANUAL)


if __name__ == "__main__":
    unittest.main()
