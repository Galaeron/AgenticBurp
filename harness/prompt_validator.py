"""
Input validation for LLM prompts.

This module provides comprehensive validation for all LLM prompts to prevent:
1. Prompt injection attacks
2. Excessive token usage
3. Sensitive data leakage
4. Malicious content patterns
5. Input size limits

Security Principles:
- Validate, don't sanitize: we reject bad input rather than trying to fix it
- Defense in depth: multiple layers of validation (length, content, structure)
- Fail securely: reject when in doubt
- Log violations: track rejected inputs for security monitoring
"""
from __future__ import annotations
import re
import logging
from typing import Optional
from dataclasses import dataclass, field

log = logging.getLogger("harness.prompt_validator")


# =============================================================================
# Configuration
# =============================================================================

@dataclass
class ValidationConfig:
    """Configuration for prompt validation."""
    
    # Length limits
    max_system_prompt_chars: int = 32000
    max_user_prompt_chars: int = 32000
    max_total_prompt_chars: int = 64000
    # Split per prompt type, matching the char-limit fields above --
    # found live, against a real Juice Shop run: a single shared
    # max_prompt_lines=200 rejected 2 of this project's 36 real agents'
    # system prompts outright (http_request_smuggling at 306 lines,
    # recon at 221) purely for being verbosely formatted, developer-
    # authored, code-reviewed prose -- not for any actual malformation.
    # System prompts get a generous ceiling (500 -- comfortable headroom
    # above the current real maximum of 306, so a normal future edit to
    # an agent's specialty_prompt doesn't immediately retrip this);
    # excess line count for TRUSTED, reviewed content is a "something
    # is probably a bug" signal at a much higher threshold than for user
    # content, not a security boundary. User prompts (derived from
    # captured exchange data, which can legitimately be attacker-
    # influenced) keep the original, tighter 200 -- unrelated to this
    # fix and not re-examined here, since that wasn't the observed
    # failure and changing it without the same live-verification this
    # fix had would be exactly the kind of unverified guess this
    # project's own standards call out.
    max_system_prompt_lines: int = 500
    max_user_prompt_lines: int = 200
    
    # Token limits (approximate, based on characters)
    max_system_prompt_tokens: int = 8000
    max_user_prompt_tokens: int = 8000
    max_total_prompt_tokens: int = 16000
    
    # Content patterns to reject
    blocked_patterns: list[str] = field(default_factory=lambda: [
        # Prompt injection attempts - be specific to actual injection patterns
        r'\b(ignore|forget|disregard)\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?|guidelines?|system\s+prompt)\b',
        r'\b(your\s+)?system\s+prompt\s+(is|was|are|were)\s+(ignored|irrelevant|wrong|false)\b',
        r'\b(act\s+as|behave\s+as|pretend\s+to\s+be)\s+[if\s+]+.*\b(user|assistant|system|model)\b',
        r'\b(you\s+are\s+now\s+ignoring|from\s+now\s+on\s+ignore)\s+.*\b',
        
        # Jailbreak attempts - more specific patterns
        r'\b(DAN|d\.?a\.?n\.?)\b',
        r'\b(developer|admin|root|superuser)\s+mode\b',
        r'\b(bypass|disable|ignore|skip)\s+(safety|security|content|filter|moderation)\s+(checks?|mechanisms?|systems?)\b',
        r'\b(enable|activate|turn\s+on)\s+(debug|dev|developer|test)\s+mode\b',
        
        # Code execution attempts
        r'\b(exec|execute|run|spawn|fork|system|popen|os\.|subprocess\.)\s*[("\']',
        #
        # Found live, during this project's first real (non-substituted)
        # Ollama run: this pattern used to also list "import"/"from" as
        # trigger verbs. "import os" / "from subprocess import ..." are
        # the single most ubiquitous opening lines of real Python source
        # code -- and disclosing real source code (via a path-traversal
        # or misconfigured-debug-endpoint bug) is exactly the kind of
        # finding this harness needs to analyze, not treat as an
        # injection attempt. Confirmed live: a genuine path-traversal
        # exchange whose response body was the target app's own app.py
        # failed prompt validation for the literal text "import os" in
        # that disclosed source, silently producing zero findings for a
        # real vulnerability across every dispatched agent. Unlike the
        # shell-chaining/data-exfiltration false positives fixed
        # earlier, this is not a "words too far apart" bug fixable by
        # bounding a gap -- "import os" is a real, zero-distance,
        # completely ordinary phrase with no injection intent. The line
        # above already covers the actually-dangerous form (a real call:
        # `os.system(`, `subprocess.Popen(`, `exec(`) -- a bare import
        # statement doesn't itself execute anything, so dropping
        # import/from here trades a heuristic with little real signal
        # for eliminating a false positive that broke the harness's core
        # purpose. "require"/"eval"/"exec"/"compile" are kept: none of
        # them are common bare-word prefixes in ordinary disclosed source
        # the way "import os" is.
        r'\b(require|eval|exec|compile)\s+.*\b(os|sys|subprocess|shutil|ctypes)\b',
        r'\b(__import__|__builtins__|__code__|__class__|__mro__)\b',
        
        # File system access
        r'\b(open|read|write|delete|remove|unlink|rm|cat|less|more|head|tail)\s+["\']\s*/\s*',
        r'\b(file://|/etc/passwd|/etc/shadow|/etc/group|/etc/sudoers|\.ssh/|\.bashrc|\.bash_profile)\b',
        
        # Network access
        #
        # Found live, against a real testfire.net run: the "requests.|
        # httpx.|urllib." half of this pattern required trailing
        # whitespace (`\s+`) after the library name and dot -- which
        # means it matched the END of an ordinary English sentence
        # ("Too many requests. Please try again") exactly as readily as
        # a real code invocation, since both have a dot followed by a
        # space. Real Python attribute access never has a space between
        # the dot and the method name (`requests.get(`, never
        # `requests. get(`), so requiring a word character immediately
        # after the dot -- no whitespace -- distinguishes "this is a
        # sentence ending" from "this is a library call" precisely.
        # wget/curl are unaffected: those are bare shell command names,
        # legitimately followed by a space then an argument (`curl
        # http://evil.com`), not dotted attribute access.
        #
        # fetch/axios used to be lumped in with wget/curl here, on the
        # same "bare shell command name" assumption -- which is wrong
        # for these two specifically. Found live: the target app's own
        # disclosed source code (a real path-traversal finding) failed
        # validation on the literal docstring text "...fetch for the
        # avatar feature (real SSRF, not simulated)" -- ordinary English
        # prose, not code, tripped purely because "fetch" was followed
        # by a space then another word, which is true of nearly every
        # real sentence using the word "fetch". Unlike wget/curl (real
        # shell commands, essentially never appearing as an ordinary
        # English word), fetch/axios are JS APIs invoked as CALLS --
        # `fetch(url)`, `axios.get(url)` -- never bare-word-then-space
        # shell-style. Moved to the call-syntax pattern below, matching
        # how requests/httpx/urllib are already (correctly) handled.
        r'\b(wget|curl)\s+',
        #
        # "urllib" was dropped from this list. Found live: the same
        # disclosed-source-code exchange above also failed validation on
        # `urllib.request.urlopen(...)` -- the app's OWN real (vulnerable)
        # SSRF implementation, disclosed via the same path-traversal bug.
        # Unlike "requests"/"httpx" (third-party libraries an app may not
        # even use), urllib is Python's STANDARD LIBRARY -- "import
        # urllib.request" / "urllib.parse..." is ordinary, ubiquitous code
        # in any real disclosed Python source, not a signal of injection
        # intent. requests/httpx are kept: an app not using them at all is
        # common, so their appearance carries more signal.
        r'\b(requests|httpx)\.\w',
        r'\bfetch\s*\(',
        r'\baxios\.\w',
        #
        # "connect" was dropped from this list. Found live, same real
        # disclosed-source exchange as above: the app's own ordinary
        # `sqlite3.connect(DB_PATH)` -- opening a database connection is
        # about as common as Python code gets -- tripped this. Unlike
        # socket/bind/listen/accept (low-level networking calls that
        # rarely appear in ordinary application-level source), "connect("
        # alone carries almost no signal: DB connections, HTTP clients,
        # and countless other ordinary APIs all spell it this way.
        r'\b(socket|bind|listen|accept)\s*[("\']',
        
        # Dangerous patterns
        r'\b(rm\s+-rf\s+/|chmod\s+777|chown\s+0:0|mv\s+.*\s+/tmp/)\b',
        # Shell command-chaining operators (;, &&, ||, backtick command
        # substitution) followed by a recognized dangerous command name.
        #
        # Found live, against a real Juice Shop run: the PREVIOUS version
        # of this pattern (`\b(;\s*\w+|&&\s*\w+|\|\|\s*\w+|`\s*\w+)\b`)
        # was broken in two directions at once, both confirmed by direct
        # testing, not assumed:
        #   1. Over-broad: `\b` only fires at a word/non-word character
        #      transition, and ;/&&/||/backtick are all non-word
        #      characters -- so the pattern only matched when the
        #      operator was DIRECTLY preceded by a word character with
        #      no space (e.g. "json; charset" matches because "n" abuts
        #      ";", but "value; charset" also matches for the same
        #      reason). Since a semicolon directly following a word is
        #      exactly how ordinary HTTP header syntax reads --
        #      `Content-Type: application/json; charset=utf-8`, `Accept:
        #      text/html; q=0.9`, `multipart/form-data; boundary=...` --
        #      this fired on nearly every real HTTP exchange, not just
        #      injection attempts. Confirmed: "; charset", "; q", ";
        #      boundary" all matched on real captured Juice Shop traffic.
        #   2. Simultaneously under-broad: the same `\b` mechanics meant
        #      a real injection attempt with a SPACE before the operator
        #      (e.g. "x=1 && curl evil.com", arguably the more natural
        #      way to write one) did NOT match, because a space is also
        #      a non-word character and no boundary transition occurs.
        # The fix: drop the leading `\b` (it was the source of both
        # failure modes, not a useful constraint) and instead require
        # the operator to be followed by a specific, known dangerous
        # command name -- what actually distinguishes a shell-chaining
        # attempt from ubiquitous, benign punctuation. Verified against
        # 13 cases (7 benign incl. real HTTP header syntax, 6 malicious
        # incl. both spaced and unspaced operator forms, and a path-
        # prefixed command) before landing this -- see
        # test_prompt_validator.py's TestShellChainingPatternPrecision.
        # Backtick detection is kept broad (any backtick-enclosed span,
        # not command-name-gated) since backticks are rare enough in
        # real HTTP exchange data that the false-positive cost is low,
        # and command substitution doesn't require a "recognizable"
        # command name the way ;/&&/|| chaining does.
        r'(?:;|&&|\|\|)\s*(?:/[\w./-]*/)?(?:rm|cat|curl|wget|nc|ncat|bash|sh|zsh|python[23]?|perl|ruby|php|'
        r'chmod|chown|chgrp|kill|pkill|dd|mkfs|reboot|shutdown|useradd|userdel|passwd|sudo|su|eval|exec|'
        r'base64|nslookup|dig|ping|telnet|ssh|scp|ftp|whoami|id|uname|nmap|netcat)\b',
        r'`[^`\n]{1,200}`',
        
        # Data exfiltration patterns.
        #
        # Found live, during the first real (non-substituted) Ollama run
        # this project ever executed: the PREVIOUS version of this
        # pattern used an unbounded `.*` between the verb and the
        # sensitive noun, so it matched the two words appearing ANYWHERE
        # on the same line regardless of relationship. A real auth
        # agent's own honest finding evidence -- "The login request is a
        # POST to /api/login with no token/nonce field visible in the
        # request body" -- tripped it purely because "POST" (the HTTP
        # method, also a verb in this list) and "token" (an ordinary word
        # for describing a missing-auth-token finding) both occur in the
        # same sentence, four unrelated words apart. That finding text
        # then feeds into the critique pass's own user prompt (see
        # orchestrator.py's _critique), so this silently failed critique
        # -- shipping every finding on the exchange unreviewed -- for
        # exactly the finding category (missing/absent tokens) this
        # harness exists to produce. Same failure shape as the
        # shell-chaining fix above: unbounded intervening text can't
        # distinguish an instruction ("send the token to evil.com") from
        # incidental co-occurrence in unrelated prose.
        # The fix has two parts, both needed (confirmed by testing each
        # alone against the real evidence text above -- neither is
        # sufficient by itself):
        #   1. Cap the gap at 3 filler words (matching `\S+` so a
        #      URL/path counts as one token same as a plain word), which
        #      keeps "send the user's token", "post credentials to
        #      evil.com", "write my api_key" all bounded within cap
        #      while excluding the 4+-word gap ordinary descriptive prose
        #      needs.
        #   2. "post"/"put" specifically also collide with the HTTP
        #      method names themselves -- the bounded-gap fix ALONE still
        #      let a benign 3-word gap like "POST ... with an auth
        #      token" match, because that's a plausible, real way to
        #      describe an authenticated POST request. What actually
        #      distinguishes an HTTP-method mention from the exfiltration
        #      verb "post" is what immediately follows it: a method
        #      mention reads "POST to X", "POST /path", or "POST
        #      request", while the exfiltration sense takes a direct
        #      object immediately ("post the credential"). A negative
        #      lookahead excludes exactly that HTTP-method-mention shape
        #      for post/put only -- print/echo/write/log/send/upload
        #      don't share this collision and don't need it.
        # Verified against the real evidence text above (now passes),
        # five other realistic benign HTTP-method descriptions (now
        # pass), and eight realistic attack phrasings incl. "put ... in
        # the response body and email it" (still blocked) -- see
        # test_prompt_validator.py's TestDataExfiltrationPatternPrecision.
        r'\b(print|echo|write|log|send|upload)\b(?:\s+\S+){0,3}?\s+\b(password|secret|token|key|credential|api_key)\b'
        r'|\b(post|put)\b(?!\s+(?:to\b|request\b|/))(?:\s+\S+){0,3}?\s+\b(password|secret|token|key|credential|api_key)\b',
    ])
    
    # Allowed patterns (whitelist for certain contexts)
    allowed_patterns: list[str] = field(default_factory=lambda: [
        # Safe import patterns
        r'^\s*(import|from)\s+[a-zA-Z0-9_]+\s+(import|as)\s+[a-zA-Z0-9_]+',
        # Safe function calls
        r'\b(def|class|return|if|else|for|while|try|except|finally)\b',
    ])
    
    # Character restrictions
    max_consecutive_newlines: int = 10
    max_consecutive_spaces: int = 50
    
    # Enabled validation checks
    check_length: bool = True
    check_patterns: bool = True
    check_lines: bool = True
    check_characters: bool = True
    check_encoding: bool = True
    # Weakness #1: the USER prompt in this harness carries the CAPTURED EXCHANGE --
    # the very evidence a scanner exists to analyze (SQLi payloads, shell strings,
    # malicious prompts). RAISING on a "dangerous" pattern there silently SKIPS the
    # analysis of exactly the content that matters (the saved-run "Blocked pattern
    # detected in user prompt" errors). So by default an injection-shaped user
    # prompt is DETECTED + counted (observable) but NOT blocked -- the real defense
    # is the action boundary (validators are code-built; the model executes
    # nothing). Set True to restore hard-blocking of user prompts.
    block_user_patterns: bool = False


# Default configuration
_DEFAULT_CONFIG = ValidationConfig()


# =============================================================================
# Validation Errors
# =============================================================================

class ValidationError(Exception):
    """Base class for validation errors."""
    
    def __init__(self, message: str, code: str = "VALIDATION_ERROR", details: dict = None):
        super().__init__(message)
        self.code = code
        self.details = details or {}


class LengthValidationError(ValidationError):
    """Raised when input exceeds length limits."""
    
    def __init__(self, message: str, actual: int, limit: int):
        super().__init__(message, code="LENGTH_EXCEEDED", details={"actual": actual, "limit": limit})
        self.actual = actual
        self.limit = limit


class PatternValidationError(ValidationError):
    """Raised when blocked patterns are detected."""
    
    def __init__(self, message: str, pattern: str, matched_text: str = None):
        super().__init__(message, code="BLOCKED_PATTERN", 
                        details={"pattern": pattern, "matched_text": matched_text})
        self.pattern = pattern
        self.matched_text = matched_text


class EncodingValidationError(ValidationError):
    """Raised when encoding issues are detected."""
    pass


# =============================================================================
# Validator Class
# =============================================================================

class PromptValidator:
    """
    Validates LLM prompts for security and stability.
    
    This validator performs multiple checks on prompts before they're
    sent to the LLM to prevent injection attacks, excessive resource usage,
    and other security issues.
    """
    
    def __init__(self, config: ValidationConfig = None):
        self.config = config or _DEFAULT_CONFIG
        self._compiled_patterns = None
        self._stats = {
            'total_checks': 0,
            'passed': 0,
            'failed': 0,
            'blocked_patterns': 0,
            'length_violations': 0,
            'whitespace_collapsed': 0,
        }

    def _compile_patterns(self):
        """Compile regex patterns for efficiency."""
        if self._compiled_patterns is None:
            self._compiled_patterns = [
                (re.compile(p, re.IGNORECASE), p) 
                for p in self.config.blocked_patterns
            ]
        return self._compiled_patterns
    
    def validate_system_prompt(self, prompt: str) -> str:
        """Validate a system prompt."""
        return self._validate_prompt(prompt, "system")
    
    def validate_user_prompt(self, prompt: str) -> str:
        """Validate a user prompt."""
        return self._validate_prompt(prompt, "user")
    
    def validate_prompts(self, system_prompt: str, user_prompt: str) -> tuple[str, str]:
        """Validate both system and user prompts together."""
        system_validated = self.validate_system_prompt(system_prompt)
        user_validated = self.validate_user_prompt(user_prompt)
        
        # Check combined length
        if self.config.check_length:
            total_chars = len(system_validated) + len(user_validated)
            if total_chars > self.config.max_total_prompt_chars:
                self._stats['failed'] += 1
                self._stats['length_violations'] += 1
                raise LengthValidationError(
                    f"Combined prompt length ({total_chars}) exceeds maximum ({self.config.max_total_prompt_chars})",
                    total_chars, self.config.max_total_prompt_chars
                )
        
        return system_validated, user_validated
    
    def _collapse_whitespace_runs(self, prompt: str) -> str:
        """Bound runs of consecutive spaces/newlines to the configured ceiling
        instead of rejecting the prompt. Returns the (possibly) collapsed text;
        leaves the prompt untouched when no run exceeds its limit. See the
        call site for why this is a collapse, not a reject."""
        collapsed = prompt
        max_newlines = self.config.max_consecutive_newlines
        if max_newlines and max_newlines > 0:
            collapsed = re.sub(r'\n{%d,}' % (max_newlines + 1),
                               '\n' * max_newlines, collapsed)
        max_spaces = self.config.max_consecutive_spaces
        if max_spaces and max_spaces > 0:
            collapsed = re.sub(r' {%d,}' % (max_spaces + 1),
                               ' ' * max_spaces, collapsed)
        if collapsed != prompt:
            self._stats['whitespace_collapsed'] += 1
            log.debug(
                "Collapsed excessive whitespace run(s) in prompt (bounded to "
                "newlines<=%s, spaces<=%s); content preserved, exchange not dropped.",
                max_newlines, max_spaces,
            )
        return collapsed

    def _validate_prompt(self, prompt: str, prompt_type: str) -> str:
        """Internal validation method."""
        self._stats['total_checks'] += 1
        
        if prompt is None:
            self._stats['failed'] += 1
            raise ValidationError(f"{prompt_type.capitalize()} prompt cannot be None")
        
        # Check type
        if not isinstance(prompt, str):
            self._stats['failed'] += 1
            raise ValidationError(f"{prompt_type.capitalize()} prompt must be a string, got {type(prompt).__name__}")
        
        # Check encoding
        if self.config.check_encoding:
            try:
                prompt.encode('utf-8')
            except UnicodeEncodeError as e:
                self._stats['failed'] += 1
                raise EncodingValidationError(
                    f"{prompt_type.capitalize()} prompt contains invalid UTF-8: {e}"
                )
        
        # Check length
        if self.config.check_length:
            max_chars = getattr(self.config, f'max_{prompt_type}_prompt_chars', self.config.max_user_prompt_chars)
            if len(prompt) > max_chars:
                self._stats['failed'] += 1
                self._stats['length_violations'] += 1
                raise LengthValidationError(
                    f"{prompt_type.capitalize()} prompt length ({len(prompt)}) exceeds maximum ({max_chars})",
                    len(prompt), max_chars
                )
        
        # Check lines
        if self.config.check_lines:
            lines = prompt.split('\n')
            max_lines = getattr(self.config, f'max_{prompt_type}_prompt_lines', self.config.max_user_prompt_lines)
            if len(lines) > max_lines:
                self._stats['failed'] += 1
                self._stats['length_violations'] += 1
                raise LengthValidationError(
                    f"{prompt_type.capitalize()} prompt has too many lines ({len(lines)} > {max_lines})",
                    len(lines), max_lines
                )
        
        # Consecutive-whitespace handling: COLLAPSE, never reject.
        #
        # Found live, and re-confirmed by the 2026-10 review (pt 4): long runs
        # of consecutive spaces or newlines are an ordinary FORMATTING quirk of
        # real captured content -- deeply-indented HTML (13+ nesting levels
        # easily exceeds 50 leading spaces), minified/pretty-printed bodies,
        # and templates with blank-line runs -- not an attack and not a
        # security boundary. The old behavior RAISED a ValidationError here,
        # which propagated out of ollama_client as an OllamaError and made
        # EVERY dispatched agent return zero findings for that exchange, with
        # the reason buried in an error field. That is exactly the "silently
        # produced zero findings on a real vulnerability" failure class this
        # module already fixed for the blocked-pattern check (weakness #1):
        # the captured exchange is the evidence under test, so a cosmetic quirk
        # in it must never discard the analysis.
        #
        # The limit's real purpose -- bounding degenerate token usage -- is
        # preserved by collapsing any run down to the configured ceiling
        # instead of rejecting the whole prompt. Applied to both prompt types:
        # collapsing is lossless for analysis and harmless for the trusted
        # system prompt.
        if self.config.check_characters:
            prompt = self._collapse_whitespace_runs(prompt)
        
        # Check blocked patterns -- USER prompts only, never system prompts.
        #
        # Found live, against a real Juice Shop run: this check used to
        # apply identically to both prompt types, and the shared
        # _COMMON_RULES boilerplate every one of this project's 36
        # specialist agents includes in its system prompt contains the
        # literal text "; so" -- which trips the shell-command-chaining
        # pattern (`\b(;\s*\w+|...)\b`) below. That pattern (and most of
        # this checklist -- code execution, file access, network access,
        # exfiltration) exists to catch an ATTACKER'S content arriving
        # via untrusted exchange/user data and attempting to steer the
        # model into unsafe behavior. It has no legitimate purpose
        # against the system prompt: that text is developer-authored and
        # trusted, not attacker-influenced, and a defensive system prompt
        # instructing the model on what NOT to do will routinely contain
        # exactly the words and punctuation these patterns look for
        # (mentioning "execute", "rm -rf", or an ordinary semicolon in
        # ordinary prose) without being any kind of injection attempt.
        #
        # Applying this check to the system prompt didn't add security --
        # threat-model-wise, there is no "attacker" for a hardcoded
        # string -- it only produced a 100%-reproducible false positive
        # that silently failed EVERY agent dispatch in this project
        # before any Ollama call was ever attempted. This was invisible
        # to this project's own test suite because
        # test_prompt_validator.py's coverage of validate_system_prompt()
        # only used a short hand-written example ("You are a helpful
        # assistant"), never the actual, full _COMMON_RULES text -- the
        # gap this project's own tests couldn't see is exactly the gap a
        # live run against a real target exists to close.
        #
        # The other structural checks above (length, encoding, line
        # count, consecutive whitespace) remain applied to BOTH prompt
        # types -- those guard against a system prompt becoming
        # malformed or absurdly long (e.g. from a bad config value), which
        # is a real, symmetric concern regardless of trust level.
        if self.config.check_patterns and prompt_type == "user":
            for compiled_pattern, original_pattern in self._compile_patterns():
                match = compiled_pattern.search(prompt)
                if match:
                    matched_text = match.group(0)[:100]  # Truncate for logging
                    self._stats['blocked_patterns'] += 1
                    # Weakness #1: DETECT + count for observability, but do NOT skip
                    # the analysis of captured evidence unless hard-blocking is
                    # explicitly enabled. The captured exchange IS the thing under
                    # test; a malicious-looking string in it is a finding to analyze,
                    # not permission to silently drop the exchange.
                    if self.config.block_user_patterns:
                        self._stats['failed'] += 1
                        log.warning(
                            "Blocked pattern detected in %s prompt: %s (matched: %s)",
                            prompt_type, original_pattern[:50], matched_text
                        )
                        raise PatternValidationError(
                            f"Blocked pattern detected in {prompt_type} prompt",
                            original_pattern,
                            matched_text
                        )
                    log.info(
                        "Injection-shaped pattern OBSERVED in user prompt (analyzed as evidence, "
                        "not blocked): %s (matched: %s)", original_pattern[:50], matched_text
                    )
                    break  # one observation is enough; keep analyzing the evidence

        self._stats['passed'] += 1
        return prompt
    
    def sanitize_for_logging(self, prompt: str, max_length: int = 200) -> str:
        """Sanitize a prompt for safe logging."""
        if not isinstance(prompt, str):
            return f"<{type(prompt).__name__}>"
        
        # Truncate
        if len(prompt) > max_length:
            prompt = prompt[:max_length] + "..."
        
        # Remove potentially sensitive patterns
        sensitive_patterns = [
            r'\b(password|secret|token|key|credential|api_key|auth|bearer)\s*[=:]\s*[^\s]+',
            r'[0-9]{16,}',  # Credit card-like numbers
            r'\b(http|https)://[^\s]+',  # URLs
        ]
        
        for pattern in sensitive_patterns:
            prompt = re.sub(pattern, "[REDACTED]", prompt, flags=re.IGNORECASE)
        
        return prompt
    
    def get_stats(self) -> dict:
        """Get validation statistics."""
        return self._stats.copy()
    
    def reset_stats(self) -> None:
        """Reset validation statistics."""
        self._stats = {
            'total_checks': 0,
            'passed': 0,
            'failed': 0,
            'blocked_patterns': 0,
            'length_violations': 0,
            'whitespace_collapsed': 0,
        }


# =============================================================================
# Global Validator Instance
# =============================================================================

# Default validator instance
_default_validator: Optional[PromptValidator] = None


def get_validator() -> PromptValidator:
    """Get the default prompt validator instance."""
    global _default_validator
    if _default_validator is None:
        _default_validator = PromptValidator()
    return _default_validator


def set_default_validator(validator: PromptValidator) -> None:
    """Set the default prompt validator instance."""
    global _default_validator
    _default_validator = validator


# =============================================================================
# Convenience Functions
# =============================================================================

def validate_system_prompt(prompt: str) -> str:
    """Validate a system prompt using the default validator."""
    return get_validator().validate_system_prompt(prompt)


def validate_user_prompt(prompt: str) -> str:
    """Validate a user prompt using the default validator."""
    return get_validator().validate_user_prompt(prompt)


def validate_prompts(system_prompt: str, user_prompt: str) -> tuple[str, str]:
    """Validate both prompts using the default validator."""
    return get_validator().validate_prompts(system_prompt, user_prompt)


# =============================================================================
# HTTP-Specific Validation
# =============================================================================

class HttpPromptValidator:
    """
    Specialized validator for HTTP request/response data.
    
    This validator handles the specific patterns found in HTTP exchanges
    and provides additional validation for headers, URLs, and body content.
    """
    
    def __init__(self, config: ValidationConfig = None):
        self.validator = PromptValidator(config)
        self._http_patterns = [
            # Block dangerous HTTP methods
            (re.compile(r'\b(TRACE|TRACK|CONNECT|DEBUG)\b', re.IGNORECASE), "dangerous_http_method"),
            
            # Block internal/private IPs in URLs
            (re.compile(r'\b(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)\d+\.\d+\b'), "private_ip"),
            (re.compile(r'\b169\.254\.\d+\.\d+\b'), "link_local"),
            (re.compile(r'\b127\.\d+\.\d+\.\d+\b'), "loopback"),
            (re.compile(r'\b(localhost|localhost\.localdomain|\.local|\.internal|\.private)\b', re.IGNORECASE), "localhost"),
            
            # Block sensitive headers
            (re.compile(r'\b(Authorization|Cookie|Set-Cookie|Proxy-Authorization|WWW-Authenticate)\s*[::]\s*[^\s]+', re.IGNORECASE), "sensitive_header"),
            
            # Block sensitive header values
            (re.compile(r'\b(Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)\b'), "bearer_token"),
            (re.compile(r'\b(Basic\s+[A-Za-z0-9+/=]+)\b'), "basic_auth"),
        ]
    
    def validate_exchange(self, url: str, method: str, headers: dict, body: str) -> tuple[str, str, dict, str]:
        """Validate HTTP exchange data before including in prompts."""
        # Validate URL
        validated_url = self._validate_url(url)
        
        # Validate method
        validated_method = self._validate_method(method)
        
        # Validate headers
        validated_headers = self._validate_headers(headers)
        
        # Validate body
        validated_body = self._validate_body(body)
        
        return validated_url, validated_method, validated_headers, validated_body
    
    def _validate_url(self, url: str) -> str:
        """Validate URL for inclusion in prompts."""
        if not url:
            return url
        
        for pattern, name in self._http_patterns:
            if pattern.search(url):
                log.warning("Blocked pattern in URL: %s", name)
                raise PatternValidationError(
                    f"Blocked pattern in URL: {name}",
                    pattern.pattern,
                    url[:100]
                )
        
        return url
    
    def _validate_method(self, method: str) -> str:
        """Validate HTTP method."""
        if not method:
            return method
        
        # Check for dangerous methods
        dangerous_methods = {'TRACE', 'TRACK', 'CONNECT', 'DEBUG'}
        if method.upper() in dangerous_methods:
            raise PatternValidationError(
                f"Dangerous HTTP method: {method}",
                method,
                method
            )
        
        return method
    
    def _validate_headers(self, headers: dict) -> dict:
        """Validate HTTP headers."""
        if not headers:
            return headers
        
        validated = {}
        sensitive_headers = {
            'authorization', 'cookie', 'set-cookie', 'proxy-authorization',
            'www-authenticate', 'x-api-key', 'x-auth-token', 'x-access-token'
        }
        
        for key, value in headers.items():
            # Check header name
            for pattern, name in self._http_patterns:
                if pattern.search(key):
                    log.warning("Blocked pattern in header name: %s", name)
                    raise PatternValidationError(
                        f"Blocked pattern in header name: {name}",
                        pattern.pattern,
                        key
                    )
            
            # Redact sensitive header values
            if key.lower() in sensitive_headers:
                validated[key] = "[REDACTED]"
            else:
                validated[key] = value
        
        return validated
    
    def _validate_body(self, body: str) -> str:
        """Validate HTTP body."""
        if not body:
            return body
        
        # Check body length
        if len(body) > self.validator.config.max_user_prompt_chars:
            # Truncate body for inclusion in prompts
            body = body[:self.validator.config.max_user_prompt_chars] + "...[TRUNCATED]"
        
        # Check for sensitive data in body
        sensitive_patterns = [
            r'\b(password|secret|token|key|credential|api_key)\s*["\']?\s*[=:]\s*["\']?[^\s"\'<>]+',
            r'\b(access_token|refresh_token|id_token|session_id|csrf_token)\s*[=:]\s*[^\s]+',
        ]
        
        for pattern in sensitive_patterns:
            body = re.sub(pattern, lambda m: f"{m.group(1)}: [REDACTED]", body, flags=re.IGNORECASE)
        
        return body
