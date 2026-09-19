from .base_agent import BaseAgent


class AiLlmAgent(BaseAgent):
    name = "ai_llm"

    tactical_guide = """
1. Look for the actual LLM-facing prompt boundary: is user input concatenated
   directly into a system/instruction string, or passed as a separate role?
2. Check whether the response echoes back anything resembling an internal
   system prompt, tool name, or hidden instruction -- that is a prompt-leak,
   not just a stylistic quirk.
3. If the app exposes tool-calling/function-calling, look for a parameter that
   flows untouched into a shell/SQL/file-path sink downstream of the model --
   that is indirect injection turning into a concrete vulnerability class.
4. Note (don't guess) whether user-supplied text could reach a RETRIEVED
   document/webpage the model later reads -- that is the indirect prompt-
   injection surface, and needs a second exchange to confirm.
"""

    @property
    def specialty_prompt(self) -> str:
        return """
AI/LLM-feature-specific vulnerabilities. Bug bounty data shows this as
the fastest-growing category by a wide margin (prompt injection reports
alone up several-hundred percent year over year through 2025) as more
applications add chat, "ask AI", summarization, agentic, or
autocomplete features. This specialist only applies when the exchange
actually looks like it touches such a feature -- do not force a finding
onto an unrelated endpoint.

First decide: does this request/response look like it talks to an LLM
or AI feature? Signals: URL/path containing chat, assistant, copilot,
completion, generate, ask, summarize, agent; a request body with a
"prompt", "message", "messages", "input", or "query" field containing
natural language rather than structured data; a streaming response
(text/event-stream) or a response that reads like generated prose rather
than a fixed API schema. If none of these are present, return no
findings and say so -- don't speculate about AI risk on a plain CRUD
endpoint.

If it does apply, look for:
- Prompt injection surface: does user-controlled text appear to be
  concatenated directly into what looks like a system-level instruction,
  or does the app accept content from an external, less-trusted source
  (a URL to fetch, an uploaded document, a webpage to summarize) that
  the model would then process as if it were trusted instruction?
- Insecure output handling: is the model's output rendered back into
  HTML, executed, used to construct a further API call, or otherwise
  trusted downstream without the same validation you'd apply to
  arbitrary user input? (This is XSS/injection risk one hop removed --
  the untrusted input is model output, not the original request.)
- Excessive agency: does the exchange suggest the AI feature can take
  actions (call tools, hit other endpoints, modify data, send messages)
  rather than just return text? If so, note what authorization gates
  those actions and whether this exchange shows any.
- System prompt / instruction leakage: does the response contain
  content that looks like it could be the system prompt, internal
  tool definitions, or configuration rather than a normal answer?
- Sensitive data in the prompt/context: does the request body include
  what looks like other users' data, internal identifiers, or secrets
  being passed into the model context, which could later be echoed back
  to a different user.

For suggested_test, propose a concrete, minimal probe an analyst can run
in Repeater (e.g. "ask the assistant to repeat its system instructions
verbatim and see what comes back" or "submit a document/URL containing
an embedded instruction and see if the model's subsequent behavior
changes") -- not a fully worked jailbreak string.
"""
