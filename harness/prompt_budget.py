"""Fit specialist-agent and critique prompts to the model's context window.

Measured motivation (r3, job 0574e29a0799, gemma4:latest at `ollama.num_ctx` 4096):
capture review sent 2,391 prompts whose system part was 6-10.6k characters and
whose user part reached 10.9k, about three times the other phases' prompts. The
run logged 88 context truncations and 151 empty model responses. Ollama truncates
an oversized prompt from the start, where the agent's instructions are, and a
prompt that only just fits leaves no room for the answer.

`from_config` derives a budget from the configured context: `ollama.num_ctx` when
set, else `prompt_budget.model_context_tokens`, minus `prompt_budget.answer_tokens`
for the answer. With neither set (a cloud model with a large window) there is no
budget and every prompt is sent unchanged.

`fit_agent_prompts` leaves a prompt that fits unchanged. Otherwise it applies the
steps below in order, re-measuring after each, and stops as soon as it fits:

1. drop the retrieved methodology notes (general guidance, not exchange evidence);
2. drop shared rules that do not apply to this agent and exchange;
3. drop specialty sections that nothing in this exchange matches;
4. drop the prior-findings context;
5. shorten the request/response bodies, down to `_MIN_BODY_CHARS`;
6. shorten the specialty text;
7. shorten the bodies further, down to nothing.

Every cut is marked in the prompt itself and listed in the returned record, which
`BaseAgent.run` stores as `AgentReport.prompt_fit`. A prompt still over budget after
step 7 is sent with `fits: False` in that record, never cut further.

Token counts are estimated, not tokenized: the model's tokenizer is not available
offline. `estimate_tokens` was calibrated against gemma4's prompt_eval_count on
fixture prompts (agent system prompts, JSON/HTML capture-review user prompts,
minified JS, base64, hex, prose). It came out at 0.96-1.32 times the real count,
whereas a characters/4 rule undercounts JSON by 40%. Prompts are measured as sent
(after security.sanitize_for_inference), with the fence nonce at its worst case.
"""
from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from harness.agents.base_agent import BaseAgent
    from harness.models import HttpExchange

log = logging.getLogger("harness.prompt_budget")

_TOKEN_RE = re.compile(r"[A-Z]?[a-z]{2,6}|[A-Za-z]|\d|[^\sA-Za-z\d]")
# Chat-template tokens around the two messages (measured: 16 for gemma4).
_TEMPLATE_TOKENS = 32
DEFAULT_ANSWER_TOKENS = 1024
# Body characters kept before the specialty text itself is shortened (step 5 -> 6).
_MIN_BODY_CHARS = 800
# Specialty characters always kept when step 6 shortens it.
_MIN_SPECIALTY_CHARS = 400


# The user prompt's fence carries a fresh random hex nonce (base_agent), whose
# estimate would otherwise vary from one build to the next and let a fitted
# prompt land over budget on the build actually sent. Each nonce is counted at
# its worst case instead: one token per hex digit.
_NONCE_RE = re.compile(r"(?<=UNTRUSTED-DATA-)[0-9a-fA-F]+")


def estimate_tokens(text: str) -> int:
    """Approximate model tokens in `text`, leaning high (see module docstring)."""
    text = _NONCE_RE.sub(lambda m: "0" * len(m.group()), text or "")
    return len(_TOKEN_RE.findall(text))


def _sent_tokens(system: str, user: str) -> int:
    """Estimated tokens of a system + user prompt as sent: after the provider-
    boundary sanitizer (security.sanitize_for_inference), which may rewrite them."""
    from harness.security import sanitize_for_inference
    system, user = sanitize_for_inference(system, user)
    return estimate_tokens(system) + estimate_tokens(user)


@dataclass(frozen=True)
class PromptBudget:
    context_tokens: int
    answer_tokens: int
    source: str

    @property
    def prompt_tokens(self) -> int:
        """Estimated tokens the system and user prompts may use together."""
        return max(0, self.context_tokens - self.answer_tokens - _TEMPLATE_TOKENS)

    def record(self, original_tokens: int) -> dict:
        return {"context_tokens": self.context_tokens, "source": self.source,
                "budget_tokens": self.prompt_tokens, "original_tokens": original_tokens}


def from_config(config: dict | None) -> PromptBudget | None:
    """The prompt budget the config implies, or None when no context is configured."""
    config = config or {}
    pb = config.get("prompt_budget") or {}
    num_ctx = (config.get("ollama") or {}).get("num_ctx")
    if num_ctx:
        context, source = int(num_ctx), "ollama.num_ctx"
    elif pb.get("model_context_tokens"):
        context, source = int(pb["model_context_tokens"]), "prompt_budget.model_context_tokens"
    else:
        return None
    answer = pb.get("answer_tokens")
    answer = DEFAULT_ANSWER_TOKENS if answer is None else max(0, int(answer))
    return PromptBudget(context_tokens=context, answer_tokens=answer, source=source)


# --- relevance -------------------------------------------------------------

_WORD_RE = re.compile(r"[a-z][a-z0-9]{3,}")
_STOPWORDS = frozenset("""
about above after again against also always another anything appear appears based
because before being below between both cannot could does doing during each either
else even every example field fields from have here however into itself just like
look looks many might more most must never none only other otherwise over same
should show shown since some such than that their them then there these they this
those through under until upon very what when where whether which while will with
within without would your yours
request requests response responses header headers value values parameter parameters
endpoint endpoints application server user users http https test tests testing check
checks vulnerability vulnerabilities security attack attacker attackers potential
possible finding findings report evidence confidence
""".split())

# A software name directly followed by a version ("nginx/1.18.0", "jquery@3.5.1",
# "Express 4.17"): the shared CVE/components rule applies to such an exchange.
_VERSION_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9_.+-]*[/@ ]v?\d+\.\d+")
# Agents whose specialty is reporting components keep that rule regardless.
_COMPONENT_AGENTS = frozenset({"supply_chain", "recon", "info_disclosure", "misconfig"})
_RELEVANCE_BODY_CHARS = 20000

# Shared-rule bullets that only apply to some agents/exchanges, by their opening
# words in base_agent._COMMON_RULES. A bullet not listed here is always kept, so
# a rule added later is never dropped by this module.
_RULE_COMPONENTS = "- Do NOT claim that a specific software version"
_RULE_PARAMETER = "- parameter_name is the exact name"
_RULE_NAMES = {"components_cve": "the rule on CVE claims and component versions",
               "parameter": "the parameter_name/parameter_location rule"}
_HEADING_RE = re.compile(r"^[A-Z][A-Z0-9 /&()\-.,']{3,}:\s*$", re.M)


def _exchange_text(exchange: "HttpExchange") -> str:
    parts = [exchange.method or "", exchange.url or ""]
    for headers in (exchange.request_headers, exchange.response_headers):
        parts.extend(f"{k}: {v}" for k, v in (headers or {}).items())
    parts.append((exchange.request_body or "")[:_RELEVANCE_BODY_CHARS])
    parts.append((exchange.response_body or "")[:_RELEVANCE_BODY_CHARS])
    return "\n".join(parts)


def _words(text: str) -> set[str]:
    return set(_WORD_RE.findall(text.lower())) - _STOPWORDS


def _has_inputs(exchange: "HttpExchange") -> bool:
    from urllib.parse import urlsplit
    parts = urlsplit(exchange.url or "")
    cookie = any(k.lower() == "cookie" for k in (exchange.request_headers or {}))
    return bool(parts.query or exchange.request_body or cookie or re.search(r"\d", parts.path))


def _shows_version(exchange: "HttpExchange") -> bool:
    text = "\n".join(f"{k}: {v}" for k, v in (exchange.response_headers or {}).items())
    text += "\n" + (exchange.response_body or "")[:_RELEVANCE_BODY_CHARS]
    return bool(_VERSION_RE.search(text))


def relevant_rules(rules: str, agent: "BaseAgent", exchange: "HttpExchange") -> tuple[str, list[str]]:
    """`rules` without the bullets that do not apply here, and the dropped bullets' keys.

    - the CVE/components rule needs a version banner in the response, unless the
      agent's own specialty is reporting components;
    - the parameter rule needs an input in the request (query, body, cookie or an
      id-like path segment), and never applies to a header-only agent."""
    head, sep, body = rules.partition("\nRules:\n")
    if not sep:
        return rules, []
    bullets = re.split(r"\n(?=- )", body)
    kept, dropped = [], []
    for bullet in bullets:
        if bullet.startswith(_RULE_COMPONENTS) and agent.name not in _COMPONENT_AGENTS \
                and not _shows_version(exchange):
            dropped.append("components_cve")
        elif bullet.startswith(_RULE_PARAMETER) and (
                agent.input_body_chars is not None or not _has_inputs(exchange)):
            dropped.append("parameter")
        else:
            kept.append(bullet)
    if not dropped:
        return rules, []
    names = "; ".join(_RULE_NAMES[key] for key in dropped)
    kept[-1] = kept[-1].rstrip("\n")
    kept.append(f"- [Omitted as not applicable to this exchange, to fit the model context "
                f"window: {names}.]\n")
    return head + sep + "\n".join(kept), dropped


def relevant_specialty(specialty: str, exchange: "HttpExchange") -> tuple[str, list[str]]:
    """`specialty` without its headed sections that share no keyword with the
    exchange, and the omitted headings (see omitted_sections_note).

    Only prompts written as `HEADING:` sections are filtered; the text before the
    first heading is always kept, and a prose-only specialty is returned as is."""
    heads = list(_HEADING_RE.finditer(specialty))
    if not heads:
        return specialty, []
    exchange_words = None
    kept = [specialty[:heads[0].start()]]
    omitted = []
    for i, head in enumerate(heads):
        end = heads[i + 1].start() if i + 1 < len(heads) else len(specialty)
        section = specialty[head.start():end]
        if exchange_words is None:
            exchange_words = _words(_exchange_text(exchange))
        if _words(section) & exchange_words:
            kept.append(section)
        else:
            omitted.append(head.group(0).strip().rstrip(":"))
    if not omitted:
        return specialty, []
    return "".join(kept).rstrip("\n") + "\n", omitted


def omitted_sections_note(omitted: list[str]) -> str:
    if not omitted:
        return ""
    return ("\n[Sections omitted to fit the model context window, because nothing in this "
            "exchange matched them: " + "; ".join(omitted) + ".]\n")


def _shorten(text: str, keep: int) -> str:
    if len(text) <= keep:
        return text
    return (text[:keep].rstrip() + f"\n...[{len(text) - keep} more characters of this "
            "guidance omitted to fit the model context window]\n")


# --- agent prompts ---------------------------------------------------------

# Character resolution of the length searches below: a cut keeps within this many
# characters of the most that fits, for about half the rebuilds of an exact search.
_SEARCH_STEP = 64


def _largest_fitting(lo: int, hi: int, fits_at) -> int:
    """The largest n in [lo, hi], to within _SEARCH_STEP, for which `fits_at(n)`;
    `fits_at(lo)` is known to hold."""
    while hi - lo > _SEARCH_STEP:
        mid = (lo + hi + 1) // 2
        if fits_at(mid):
            lo = mid
        else:
            hi = mid - 1
    return lo

def _prompt_body_lengths(view) -> dict[str, int]:
    """Body lengths as base_agent._user_prompt cuts them: those of its _prompt_view
    (sanitized, secrets redacted), so a record's original_chars matches the
    "N more characters" marker in the prompt."""
    return {"request_body": len(view.request_body or ""),
            "response_body": len(view.response_body or "")}


def fit_agent_prompts(agent: "BaseAgent", exchange: "HttpExchange", body_chars: int,
                      prior_context: str, budget: PromptBudget) -> tuple[str, str, dict | None]:
    """(system_prompt, user_prompt, record) for `agent` on `exchange`, within
    `budget`. `record` is None when the full prompts already fit."""
    from harness.agents.base_agent import _COMMON_RULES

    # One sanitized view for every rebuild below: sanitizing a large body is
    # most of the cost of building a user prompt.
    view = agent._prompt_view(exchange)
    system = agent._system_prompt()
    user = agent._user_prompt(view, body_chars, prior_context)
    original = _sent_tokens(system, user)
    if original <= budget.prompt_tokens:
        return system, user, None

    elided: list[dict] = []
    state = {"rules": _COMMON_RULES, "specialty": agent.specialty_prompt,
             "sections": [], "knowledge": True, "prior": prior_context, "body": body_chars,
             "omitted": []}

    def build() -> tuple[str, str, int]:
        s = agent._compose_system_prompt(
            state["rules"], state["specialty"] + omitted_sections_note(state["sections"]))
        u = agent._user_prompt(view, state["body"], state["prior"],
                               include_knowledge=state["knowledge"], context_fit=state["body"] < body_chars,
                               omitted=state["omitted"])
        return s, u, _sent_tokens(s, u)

    def fits() -> bool:
        nonlocal system, user
        system, user, total = build()
        return total <= budget.prompt_tokens

    def done() -> tuple[str, str, dict]:
        total = _sent_tokens(system, user)
        record = budget.record(original)
        record.update(fitted_tokens=total, fits=total <= budget.prompt_tokens, elided=elided,
                      system_prompt_version=hashlib.sha256(system.encode()).hexdigest()[:12])
        if not record["fits"]:
            log.warning("%s prompt is still %d estimated tokens over the %d-token budget "
                        "after fitting; sending it anyway", agent.name,
                        total - budget.prompt_tokens, budget.prompt_tokens)
        return system, user, record

    # 1. methodology notes
    knowledge_tokens = estimate_tokens(user) - estimate_tokens(
        agent._user_prompt(view, body_chars, prior_context, include_knowledge=False))
    if knowledge_tokens > 0:
        state["knowledge"] = False
        state["omitted"] = ["methodology notes"]
        elided.append({"part": "methodology_notes", "tokens": knowledge_tokens})
        if fits():
            return done()

    # 2. shared rules that do not apply
    rules, dropped = relevant_rules(_COMMON_RULES, agent, exchange)
    if dropped:
        state["rules"] = rules
        elided.append({"part": "shared_rules", "omitted": dropped})
        if fits():
            return done()

    # 3. specialty sections nothing in the exchange matches
    specialty, omitted = relevant_specialty(agent.specialty_prompt, exchange)
    if omitted:
        state["specialty"], state["sections"] = specialty, omitted
        elided.append({"part": "specialty_sections", "omitted": omitted})
        if fits():
            return done()

    # 4. prior findings
    if prior_context:
        state["prior"] = ""
        state["omitted"] = state["omitted"] + ["prior findings on this host"]
        elided.append({"part": "prior_findings",
                       "lines": len([l for l in prior_context.splitlines() if l.strip()])})
        if fits():
            return done()

    bodies = _prompt_body_lengths(view)
    longest = min(body_chars, max(bodies.values()))

    def cut_bodies(floor: int) -> bool:
        """Largest body budget in [floor, longest) that fits; True when found."""
        if longest <= floor:
            return False
        state["body"] = floor
        if not fits():
            return False
        def fits_at(n: int) -> bool:
            state["body"] = n
            return fits()
        state["body"] = _largest_fitting(floor, longest - 1, fits_at)
        fits()
        return True

    def body_record() -> None:
        elided[:] = [e for e in elided if e["part"] not in bodies]
        elided.extend({"part": part, "original_chars": n, "kept_chars": state["body"]}
                      for part, n in bodies.items() if n > state["body"])

    # 5. bodies, down to _MIN_BODY_CHARS
    floor = min(_MIN_BODY_CHARS, longest)
    if cut_bodies(floor):
        body_record()
        return done()
    if longest > floor:
        state["body"] = floor
        body_record()

    # 6. specialty text
    if len(state["specialty"]) > _MIN_SPECIALTY_CHARS:
        full = state["specialty"]

        def fits_at(n: int) -> bool:
            state["specialty"] = _shorten(full, n)
            return fits()
        lo = _MIN_SPECIALTY_CHARS
        if fits_at(lo):
            lo = _largest_fitting(lo, len(full) - 1, fits_at)
        state["specialty"] = _shorten(full, lo)
        elided.append({"part": "specialty_text", "original_chars": len(full), "kept_chars": lo})
        if fits():
            return done()

    # 7. bodies, down to nothing
    if state["body"] > 0 and any(n > 0 for n in bodies.values()):
        cut_bodies(0) or fits()
        body_record()
    else:
        fits()
    return done()


# --- critique prompt -------------------------------------------------------

def fit_critique_prompt(system_prompt: str, render, evidence_lengths: list[int],
                        budget: PromptBudget) -> tuple[str, dict | None]:
    """The critique user prompt within `budget`.

    `render(cap)` builds the user prompt with each finding's evidence cut to `cap`
    characters (None = uncut) and marked when cut. The largest cap that fits is
    used; None record when the uncut prompt fits."""
    user = render(None)
    original = _sent_tokens(system_prompt, user)
    if original <= budget.prompt_tokens:
        return user, None
    longest = max(evidence_lengths or [0])

    def fits_at(cap: int) -> bool:
        return _sent_tokens(system_prompt, render(cap)) <= budget.prompt_tokens
    lo = 0
    if fits_at(0):
        lo = _largest_fitting(0, max(0, longest - 1), fits_at)
    user = render(lo)
    total = _sent_tokens(system_prompt, user)
    record = budget.record(original)
    record.update(fitted_tokens=total, fits=total <= budget.prompt_tokens, elided=[{
        "part": "finding_evidence", "kept_chars": lo,
        "findings": sum(1 for n in evidence_lengths if n > lo)}])
    if not record["fits"]:
        log.warning("critique prompt is still %d estimated tokens over the %d-token budget "
                    "after fitting; sending it anyway", total - budget.prompt_tokens,
                    budget.prompt_tokens)
    return user, record
