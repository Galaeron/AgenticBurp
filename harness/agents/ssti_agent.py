from .base_agent import BaseAgent


class SstiAgent(BaseAgent):
    """Agent for detecting Server-Side Template Injection vulnerabilities."""
    name = "ssti"

    tactical_guide = """
1. Look for user input that lands somewhere that could plausibly be
   template-rendered (a "name"/"greeting"/report-title field, an email/PDF
   template preview) rather than just any string field.
2. Note which template engine's syntax would fit the app's apparent stack
   (Jinja2 `{{ }}`, Twig, Freemarker `${}`, Velocity `#set`) based on
   response headers/framework signals, rather than proposing a generic
   payload blind to the engine.
3. Propose a NONCE-WRAPPED ARITHMETIC probe (e.g. a payload that would
   evaluate to a distinctive number if rendered, literal text if not) as
   the differential confirmation, not a payload that merely "looks like"
   template syntax.
"""

    @property
    def specialty_prompt(self) -> str:
        return """
Server-Side Template Injection (SSTI) vulnerabilities. Look for:

TEMPLATE ENGINE INDICATORS:
- File extensions: .tpl, .tmpl, .html, .ejs, .jade, .pug, .erb, .shtml
- Template engine names in responses: Jinja2, Twig, Smarty, Velocity, Freemarker
- Template syntax in responses: {{ variable }}, {{{ variable }}}, <% variable %>, <%= variable %>
- Template error messages in responses
- Template debugging output

VULNERABLE INPUT PATTERNS:
- User input reflected inside template expressions
- User input used in template variable names
- User input used in template filters or modifiers
- User input in include/extend/import statements
- User input in template function calls

COMMON TEMPLATE SYNTAX:
- Jinja2/Twig: {{ variable }}, {{{ variable }}}, {% tag %}
- ERB (Ruby): <% code %>, <%= expression %>
- EJS (JavaScript): <%= code %>, <%- code %>, <% code %>
- Jade/Pug: = variable, - code
- Smarty: {$variable}, {function()}
- Velocity: $variable, #directive()
- Freemarker: ${variable}, <#directive>

SSTI DETECTION PATTERNS:
- Mathematical operations: {{ 7*7 }}, {{ config.__class__ }}
- String operations: {{ 'a'+'b' }}
- Variable access: {{ user.name }}, {{ request.args }}
- Built-in functions: {{ range(10) }}, {{ dump() }}
- Filter chains: {{ value|upper|lower }}
- Object traversal: {{ user.__class__.__base__.__subclasses__() }}

ERROR MESSAGE INDICATORS:
- TemplateSyntaxError
- UndefinedError (undefined variable)
- TypeError in template context
- Template rendering errors
- Stack traces showing template evaluation

RESPONSE ANALYSIS:
- Template syntax in response body
- Variable names from user input in templates
- Error messages from template engine
- Output from template evaluation
- Code execution results

For suggested_test, propose:
- Test with mathematical expression: {{7*7}}
- Test with string concatenation: {{'a'+'b'}}
- Test with built-in function: {{range(10)}}
- Test with object traversal: {{user.__class__}}
- Test with filter: {{value|upper}}

suggested_test MUST be concrete template payloads:
- '{{7*7}}'
- '{{config.__class__}}'
- '{{request.args}}'
- '{{user.__class__.__base__.__subclasses__()}}'

CONTEXT MATTERS:
- Different template engines have different syntax
- SSTI often requires knowing the template engine
- Some engines auto-escape by default (Jinja2 with autoescape=True)
- Sandboxed environments may limit access
- Blind SSTI may require time-based or error-based detection
"""
