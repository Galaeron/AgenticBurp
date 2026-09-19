from .base_agent import BaseAgent


class CommandInjectionAgent(BaseAgent):
    """Agent for detecting command injection and RCE vulnerabilities."""
    name = "command_injection"

    tactical_guide = """
1. Find any parameter whose value plausibly reaches a shell/subprocess call
   server-side (filenames, hostnames for a ping/traceroute/DNS-lookup
   feature, image/PDF conversion tools, git/archive operations).
2. Note the delimiter set that would matter (semicolon, pipe, &, $(), backtick,
   newline) for the SPECIFIC OS/shell this looks like, based on response
   headers/error text -- don't propose a payload blind to the platform.
3. Blind command injection (no output reflected) needs an out-of-band
   callback to confirm -- say that explicitly as the suggested_test rather
   than implying the response alone would show it.
"""

    @property
    def specialty_prompt(self) -> str:
        return """
Command injection and Remote Code Execution (RCE) vulnerabilities. Look for:

COMMAND INJECTION INDICATORS:
- Parameters that appear to be passed to shell commands
- Input fields used in system(), exec(), spawn(), or similar functions
- Backtick (`) or dollar sign ($) characters in parameters
- Pipe (|), semicolon (;), ampersand (&), backslash (\\), or other shell metacharacters in input
- Command substitution patterns ($(command), `command`)
- File path parameters that might be used in shell commands

RCE PATTERNS:
- Input reflected in command execution context
- Error messages indicating command execution
- Output from executed commands in responses
- File system operations based on user input
- Code evaluation functions (eval(), exec(), Function())

COMMON VULNERABLE PARAMETERS:
- ip, hostname, domain (ping, nslookup, dig commands)
- url, file, path (wget, curl, file operations)
- cmd, command, exec, action (direct command execution)
- query, search, input (user input passed to commands)
- filename, document, template (file operations)

ERROR MESSAGE INDICATORS:
- Shell error messages (sh: 1: not found, /bin/sh: bad interpreter)
- Command not found errors
- Permission denied errors from command execution
- Syntax errors from shell parsing
- Stack traces showing command execution

RESPONSE ANALYSIS:
- Command output in response body
- File contents returned from server
- Directory listings
- System information disclosure
- Time delays indicating command execution

PAYLOAD PATTERNS TO LOOK FOR:
- Simple command injection: ; ls, | cat /etc/passwd
- Blind command injection: && sleep 5, || sleep 5
- Time-based: $(sleep 5)
- File read: `cat /etc/passwd`
- File write: > file.txt, >> file.txt

For suggested_test, propose:
- Test with semicolon: parameter=value; ls
- Test with pipe: parameter=value|cat /etc/passwd
- Test with backtick: parameter=`ls`
- Test with dollar: parameter=$(ls)
- Test with sleep: parameter=value&&sleep 5&&
- Test with command substitution: parameter=$(id)

suggested_test MUST be concrete and testable in Burp Repeater:
- "Append ; ls to parameter value"
- "Replace parameter with | cat /etc/passwd"
- "Test with && sleep 5 && to detect time delay"
- "Test command substitution with $(id)"

CONTEXT MATTERS:
- Different operating systems use different shell syntax (Linux vs Windows)
- Some characters may be filtered or encoded
- Time-based detection requires measuring response times
- Blind RCE may not show output but can be detected via time delays
"""
