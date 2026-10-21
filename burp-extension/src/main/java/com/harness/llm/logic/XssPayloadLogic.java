package com.harness.llm.logic;

import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Payload selection + verdict logic for reflection_context_validation
 * (XSS). Montoya-free for the same reason as the other *Logic classes.
 *
 * Replaces the old single-payload check (plain alnum canary, checked for
 * bare substring presence) which only ever proved text echo, never that
 * HTML/JS-breaking characters survive unescaped -- so it could report
 * "supported, 0.86 confidence" for a response that safely HTML-encodes
 * everything. PAYLOADS below are ordered weakest-signal-last: real
 * breakout attempts first, the plain canary (echo-only, proves nothing
 * about escaping) as the final fallback so it still gives a same result
 * as before when nothing sharper works.
 *
 * Proof is bound to the injected payload (code review 02 R28): a
 * confirmation needs the whole rendered payload, unique canary included,
 * to appear raw in the body at a position where the HTML/JS parser would
 * execute it. A page that merely contains a {@code <script>} tag of its
 * own, or echoes the payload inside a textarea, comment or string
 * literal, is not proof.
 */
public final class XssPayloadLogic {

    public enum Verdict { CONFIRMED, SUPPORTED, REJECTED }

    /** Where a payload has to land for its breakout to execute. */
    public enum Context {
        /** The payload's own {@code <script>} tag must open in HTML text (after closing any quoted attribute and tag). */
        HTML_TAG_BREAKOUT,
        /**
         * The payload's leading quote must close a single-quoted string in script
         * the browser runs: a {@code <script>} block, an event-handler attribute
         * value, or a {@code javascript:} URL in an attribute that navigates to it.
         */
        JS_SINGLE_QUOTED_STRING,
        /** The payload's leading quote must close a double-quoted attribute value inside an opening tag. */
        DOUBLE_QUOTED_ATTRIBUTE,
        /** Plain echo: proves nothing about escaping, never confirmed. */
        ECHO
    }

    public record Payload(String template, String rawMarker, Context context) {
        /** Substitutes the canary into this payload's template. */
        public String render(String canary) { return template.replace("__C__", canary); }
    }

    public static final List<Payload> PAYLOADS = List.of(
            new Payload("\"><script>__C__</script>", "<script>", Context.HTML_TAG_BREAKOUT),        // tag breakout
            new Payload("'-__C__-'", "-'", Context.JS_SINGLE_QUOTED_STRING),                        // JS string breakout
            new Payload("\"onmouseover=\"__C__", "onmouseover=", Context.DOUBLE_QUOTED_ATTRIBUTE), // event-handler injection, no new tag
            new Payload("__C__", "", Context.ECHO)                                                  // plain echo probe -- proves nothing about escaping, kept last
    );

    /** The JavaScript MIME type essences (MIME Sniffing): a script of one of these types runs as a classic script. */
    private static final Set<String> JAVASCRIPT_MIME_TYPES = Set.of(
            "application/ecmascript", "application/javascript", "application/x-ecmascript", "application/x-javascript",
            "text/ecmascript", "text/javascript", "text/javascript1.0", "text/javascript1.1", "text/javascript1.2",
            "text/javascript1.3", "text/javascript1.4", "text/javascript1.5", "text/jscript", "text/livescript",
            "text/x-ecmascript", "text/x-javascript");

    /** Elements whose content the HTML parser reads as text up to the matching end tag. */
    private static final Set<String> RAW_TEXT_ELEMENTS = Set.of(
            "script", "style", "textarea", "title", "xmp", "iframe", "noembed", "noframes", "noscript", "plaintext");

    /**
     * Event-handler content attributes: the browser compiles their value as
     * script. A fixed list rather than any "on*" name, so a custom attribute
     * that merely starts with "on" is not read as script.
     */
    private static final Set<String> EVENT_HANDLER_ATTRIBUTES = Set.of(
            "onabort", "onafterprint", "onanimationend", "onanimationiteration", "onanimationstart",
            "onauxclick", "onbeforeinput", "onbeforeprint", "onbeforeunload", "onblur", "oncancel",
            "oncanplay", "oncanplaythrough", "onchange", "onclick", "onclose", "oncontextmenu", "oncopy",
            "oncuechange", "oncut", "ondblclick", "ondrag", "ondragend", "ondragenter", "ondragleave",
            "ondragover", "ondragstart", "ondrop", "ondurationchange", "onemptied", "onended", "onerror",
            "onfocus", "onfocusin", "onfocusout", "onformdata", "onhashchange", "oninput", "oninvalid",
            "onkeydown", "onkeypress", "onkeyup", "onload", "onloadeddata", "onloadedmetadata",
            "onloadstart", "onmessage", "onmousedown", "onmouseenter", "onmouseleave", "onmousemove",
            "onmouseout", "onmouseover", "onmouseup", "onoffline", "ononline", "onpagehide", "onpageshow",
            "onpaste", "onpause", "onplay", "onplaying", "onpointerdown", "onpointerenter",
            "onpointerleave", "onpointermove", "onpointerout", "onpointerover", "onpointerup",
            "onpopstate", "onprogress", "onratechange", "onreset", "onresize", "onscroll", "onscrollend",
            "onsearch", "onseeked", "onseeking", "onselect", "onselectionchange", "onselectstart",
            "onstalled", "onstorage", "onsubmit", "onsuspend", "ontimeupdate", "ontoggle",
            "ontouchcancel", "ontouchend", "ontouchmove", "ontouchstart", "ontransitionend", "onunload",
            "onvolumechange", "onwaiting", "onwheel");

    /** URL attributes the browser navigates to (so a {@code javascript:} URL there runs), by element. */
    private static final Map<String, Set<String>> NAVIGATING_URL_ATTRIBUTES = Map.of(
            "a", Set.of("href", "xlink:href"),
            "area", Set.of("href"),
            "iframe", Set.of("src"),
            "frame", Set.of("src"),
            "form", Set.of("action"),
            "button", Set.of("formaction"),
            "input", Set.of("formaction"));

    /**
     * The named character references (terminated by ';') that decode to a
     * character the script or URL scanners below look at. Every other named
     * reference decodes to a character neither scanner reads, so it can be
     * left as written.
     */
    private static final Map<String, String> SCANNED_NAMED_REFERENCES = Map.ofEntries(
            Map.entry("apos", "'"), Map.entry("quot", "\""), Map.entry("QUOT", "\""),
            Map.entry("bsol", "\\"), Map.entry("sol", "/"), Map.entry("ast", "*"), Map.entry("midast", "*"),
            Map.entry("grave", "`"), Map.entry("DiacriticalGrave", "`"), Map.entry("NewLine", "\n"),
            Map.entry("Tab", "\t"), Map.entry("colon", ":"), Map.entry("percnt", "%"),
            Map.entry("amp", "&"), Map.entry("AMP", "&"));

    private XssPayloadLogic() {}

    public static Payload nextPayload(List<String> triedTemplates) {
        for (Payload p : PAYLOADS) if (!triedTemplates.contains(p.template())) return p;
        return null;
    }

    /**
     * CONFIRMED requires the full rendered payload -- breakout syntax and
     * the unique canary together -- to survive raw at a position where it
     * executes (see {@link Context}); any one such occurrence is enough.
     * The plain echo probe can never reach CONFIRMED, only SUPPORTED, since
     * reflecting plain text proves nothing about escaping. SUPPORTED means
     * the canary came back but no executable payload did.
     */
    public static Verdict classify(Payload payload, String canary, String body) {
        if (body == null) return Verdict.REJECTED;
        if (payload.context() != Context.ECHO) {
            String rendered = payload.render(canary);
            for (int at = body.indexOf(rendered); at >= 0; at = body.indexOf(rendered, at + 1)) {
                if (executesAt(payload.context(), body, at, rendered.length())) return Verdict.CONFIRMED;
            }
        }
        if (body.contains(canary)) return Verdict.SUPPORTED;
        return Verdict.REJECTED;
    }

    /**
     * True if a payload of the given context, {@code length} characters long
     * and reflected raw at offset {@code at}, executes there. Nothing inside
     * {@code <template>} content executes: the parser puts it in an inert
     * fragment (batch RV-Q item Q5).
     */
    static boolean executesAt(Context context, String body, int at, int length) {
        switch (context) {
            case HTML_TAG_BREAKOUT: {
                // The payload is "><script>...: scanning through its own "> must
                // leave the parser in HTML text, so its <script> opens a script.
                HtmlState s = HtmlState.scan(body, at + 2);
                return s.mode == Mode.TEXT && s.templateDepth == 0;
            }
            case JS_SINGLE_QUOTED_STRING: {
                HtmlState s = HtmlState.scan(body, at);
                if (s.templateDepth > 0) return false;
                if (s.mode == Mode.RAW_TEXT && "script".equals(s.element)) {
                    return s.scriptRuns && insideSingleQuotedJsString(body, s.rawTextStart, at);
                }
                return insideSingleQuotedStringOfAttributeScript(s, body, at, length);
            }
            case DOUBLE_QUOTED_ATTRIBUTE: {
                HtmlState s = HtmlState.scan(body, at);
                return s.mode == Mode.TAG && !s.closingTag && s.attributeQuote == '"' && s.templateDepth == 0;
            }
            default:
                return false;
        }
    }

    private enum Mode { TEXT, TAG, COMMENT, RAW_TEXT }

    /**
     * A deliberately small HTML tokenizer: enough to tell text, the inside of
     * a tag (and of a quoted or unquoted attribute value, with the
     * attribute's name), comments and raw-text elements apart. It is not a
     * full HTML5 parser; where it is unsure it stays in a non-executable mode
     * rather than guessing executable.
     */
    private static final class HtmlState {
        Mode mode = Mode.TEXT;
        String element;          // tag being read (TAG) or raw-text element (RAW_TEXT)
        boolean closingTag;
        char attributeQuote;     // 0, '"' or '\'' while inside a quoted attribute value
        int rawTextStart = -1;
        String attributeName;    // lower-case name of the attribute whose value is being read, else null
        int valueStart = -1;     // offset where that value starts
        private boolean unquotedValue;   // that value is unquoted (ends at whitespace or '>')
        int templateDepth;       // <template> elements open around this point: their content is inert
        boolean scriptRuns;      // the RAW_TEXT element is a <script> of a type the browser runs
        private boolean expectingValue;  // after "name =", before the value
        private String pendingName;      // last complete attribute name in this tag
        private int nameStart = -1;      // start of the attribute name being read, else -1
        private final Map<String, String> attributes = new HashMap<>();  // this tag's values as written, first wins

        private void enterTag() {
            mode = Mode.TAG;
            attributeQuote = 0;
            attributeName = null;
            valueStart = -1;
            unquotedValue = false;
            expectingValue = false;
            pendingName = null;
            nameStart = -1;
            attributes.clear();
        }

        private void endAttributeValue(String body, int end) {
            if (attributeName != null && valueStart >= 0) attributes.putIfAbsent(attributeName, body.substring(valueStart, end));
            attributeQuote = 0;
            attributeName = null;
            valueStart = -1;
            unquotedValue = false;
            pendingName = null;
        }

        private void endName(String body, int at) {
            if (nameStart >= 0) pendingName = body.substring(nameStart, at).toLowerCase(Locale.ROOT);
            nameStart = -1;
        }

        static HtmlState scan(String body, int end) {
            HtmlState s = new HtmlState();
            int i = 0;
            while (i < end) {
                char c = body.charAt(i);
                switch (s.mode) {
                    case TEXT -> {
                        if (body.startsWith("<!--", i)) { s.mode = Mode.COMMENT; i += 4; continue; }
                        if (c == '<' && i + 1 < body.length()) {
                            int j = i + 1;
                            boolean closing = body.charAt(j) == '/';
                            if (closing) j++;
                            if (j < body.length() && Character.isLetter(body.charAt(j))) {
                                int nameStart = j;
                                while (j < body.length() && isTagNameChar(body.charAt(j))) j++;
                                s.enterTag();
                                s.element = body.substring(nameStart, j).toLowerCase(Locale.ROOT);
                                s.closingTag = closing;
                                i = j;
                                continue;
                            }
                        }
                        i++;
                    }
                    case COMMENT -> {
                        if (body.startsWith("-->", i)) { s.mode = Mode.TEXT; i += 3; continue; }
                        i++;
                    }
                    case TAG -> {
                        if (s.attributeQuote != 0) {
                            if (c == s.attributeQuote) s.endAttributeValue(body, i);
                            i++;
                            continue;
                        }
                        if (s.unquotedValue) {
                            if (Character.isWhitespace(c)) { s.endAttributeValue(body, i); i++; continue; }
                            if (c != '>') { i++; continue; }
                            s.endAttributeValue(body, i);  // '>' ends the value and the tag, below
                        }
                        if (c == '>') {
                            s.endName(body, i);
                            if ("template".equals(s.element)) {
                                if (!s.closingTag) s.templateDepth++;
                                else if (s.templateDepth > 0) s.templateDepth--;
                            }
                            if (!s.closingTag && RAW_TEXT_ELEMENTS.contains(s.element)) {
                                s.mode = Mode.RAW_TEXT;
                                s.rawTextStart = i + 1;
                                s.scriptRuns = "script".equals(s.element) && runsAsScript(s.attributes);
                            } else {
                                s.mode = Mode.TEXT;
                                s.element = null;
                            }
                            i++;
                            continue;
                        }
                        if (s.expectingValue) {
                            if (Character.isWhitespace(c)) { i++; continue; }
                            s.expectingValue = false;
                            s.attributeName = s.pendingName;
                            if (c == '"' || c == '\'') { s.attributeQuote = c; s.valueStart = i + 1; }
                            else { s.unquotedValue = true; s.valueStart = i; }
                            i++;
                            continue;
                        }
                        if (c == '=' && (s.nameStart >= 0 || s.pendingName != null)) {
                            s.endName(body, i);
                            s.expectingValue = true;
                            i++;
                            continue;
                        }
                        if (Character.isWhitespace(c) || c == '/') { s.endName(body, i); i++; continue; }
                        if (s.nameStart < 0) { s.nameStart = i; s.pendingName = null; }
                        i++;
                    }
                    case RAW_TEXT -> {
                        String endTag = "</" + s.element;
                        if (!"plaintext".equals(s.element)
                                && body.regionMatches(true, i, endTag, 0, endTag.length())
                                && (i + endTag.length() >= body.length() || !isTagNameChar(body.charAt(i + endTag.length())))) {
                            s.enterTag();
                            s.closingTag = true;
                            i += endTag.length();
                            continue;
                        }
                        i++;
                    }
                }
            }
            return s;
        }

        private static boolean isTagNameChar(char c) {
            return Character.isLetterOrDigit(c) || c == '-' || c == ':' || c == '_';
        }
    }

    /**
     * True if a {@code <script>} start tag with these attribute values (as
     * written, by lower-case name) holds script the browser runs (batch RV-Q
     * item Q5), as the HTML spec's "prepare the script element" decides: an
     * empty or absent type, with no language or an empty one, is JavaScript;
     * otherwise the type, else "text/" plus the language, with references
     * decoded and ASCII whitespace trimmed, must be a JavaScript MIME type or
     * "module", ignoring ASCII case. Any other type -- a template, JSON, an
     * import map, a type with parameters -- is a data block, never run.
     */
    static boolean runsAsScript(Map<String, String> attributes) {
        String type = attributes.get("type");
        String language = attributes.get("language");
        String typeString;
        if (type != null) {
            if (type.isEmpty()) return true;
            typeString = decodeCharacterReferences(type);
        } else if (language != null && !language.isEmpty()) {
            typeString = "text/" + decodeCharacterReferences(language);
        } else {
            return true;
        }
        int from = 0, to = typeString.length();
        while (from < to && " \t\n\f\r".indexOf(typeString.charAt(from)) >= 0) from++;
        while (to > from && " \t\n\f\r".indexOf(typeString.charAt(to - 1)) >= 0) to--;
        StringBuilder lower = new StringBuilder(to - from);
        for (int i = from; i < to; i++) {
            char c = typeString.charAt(i);
            lower.append(c >= 'A' && c <= 'Z' ? (char) (c + ('a' - 'A')) : c);
        }
        String t = lower.toString();
        return JAVASCRIPT_MIME_TYPES.contains(t) || t.equals("module");
    }

    /**
     * True if a payload {@code length} characters long, reflected raw at
     * {@code at}, sits inside a single-quoted string of the script an
     * attribute value holds: an event-handler value, or a {@code javascript:}
     * URL in an attribute the browser navigates to (code review 02 RV-J
     * residual N4). The value as the browser hands it to the script engine
     * (character references decoded; for a URL, tabs and newlines removed and
     * percent-escapes decoded) must leave a single-quoted string open at the
     * payload, and the whole payload must lie inside that same value, so its
     * quote closes the string and its canary runs as code.
     */
    private static boolean insideSingleQuotedStringOfAttributeScript(HtmlState s, String body, int at, int length) {
        if (s.mode != Mode.TAG || s.closingTag || s.attributeName == null || s.valueStart < 0) return false;
        HtmlState end = HtmlState.scan(body, at + length);
        if (end.mode != Mode.TAG || end.attributeName == null || end.valueStart != s.valueStart) return false;
        String value = decodeCharacterReferences(body.substring(s.valueStart, at));
        String script;
        if (EVENT_HANDLER_ATTRIBUTES.contains(s.attributeName)) {
            script = value;
        } else if (NAVIGATING_URL_ATTRIBUTES.getOrDefault(s.element, Set.of()).contains(s.attributeName)) {
            script = javascriptUrlSource(value);
        } else {
            return false;
        }
        return script != null && insideSingleQuotedJsString(script, 0, script.length());
    }

    /**
     * Decodes the character references of an attribute value the way the
     * HTML parser does, as far as the scanners here care: numeric references
     * (with or without ';'), the named references in
     * {@link #SCANNED_NAMED_REFERENCES}, and the legacy semicolon-less
     * {@code &quot} and {@code &amp}, which an attribute value decodes unless
     * '=' or an alphanumeric follows. Anything else is left as written.
     */
    static String decodeCharacterReferences(String raw) {
        StringBuilder out = new StringBuilder(raw.length());
        int n = raw.length();
        int i = 0;
        while (i < n) {
            char c = raw.charAt(i);
            if (c != '&') { out.append(c); i++; continue; }
            int j = i + 1;
            if (j < n && raw.charAt(j) == '#') {
                j++;
                int radix = 10;
                if (j < n && (raw.charAt(j) == 'x' || raw.charAt(j) == 'X')) { radix = 16; j++; }
                int digits = j;
                long value = 0;
                while (j < n && Character.digit(raw.charAt(j), radix) >= 0) {
                    value = Math.min(value * radix + Character.digit(raw.charAt(j), radix), 0x110000);
                    j++;
                }
                if (j == digits) { out.append('&'); i++; continue; }  // "&#" without digits is literal
                if (j < n && raw.charAt(j) == ';') j++;
                int cp = (int) value;
                // NUL, out-of-range and surrogate references become U+FFFD; 0x80-0x9F
                // map to windows-1252 characters, none of them ASCII.
                if (cp == 0 || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF) || (cp >= 0x80 && cp <= 0x9F)) cp = 0xFFFD;
                out.appendCodePoint(cp);
                i = j;
                continue;
            }
            while (j < n && isAsciiAlphanumeric(raw.charAt(j))) j++;
            String name = raw.substring(i + 1, j);
            if (j < n && raw.charAt(j) == ';' && SCANNED_NAMED_REFERENCES.containsKey(name)) {
                out.append(SCANNED_NAMED_REFERENCES.get(name));
                i = j + 1;
                continue;
            }
            boolean legacy = name.equals("quot") || name.equals("QUOT") || name.equals("amp") || name.equals("AMP");
            if (legacy && (j >= n || raw.charAt(j) != '=')) {
                out.append(SCANNED_NAMED_REFERENCES.get(name));
                i = j;
                continue;
            }
            out.append('&');
            i++;
        }
        return out.toString();
    }

    private static boolean isAsciiAlphanumeric(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
    }

    /**
     * The script a {@code javascript:} URL runs, or null if the value is not
     * one: leading control characters and spaces stripped, tabs and newlines
     * removed (as the URL parser does), the scheme matched case-insensitively
     * and the rest percent-decoded.
     */
    static String javascriptUrlSource(String value) {
        if (value == null) return null;
        int start = 0;
        while (start < value.length() && value.charAt(start) <= ' ') start++;
        StringBuilder url = new StringBuilder(value.length());
        for (int i = start; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c != '\t' && c != '\n' && c != '\r') url.append(c);
        }
        String scheme = "javascript:";
        if (!url.toString().regionMatches(true, 0, scheme, 0, scheme.length())) return null;
        String rest = url.substring(scheme.length());
        StringBuilder out = new StringBuilder(rest.length());
        for (int i = 0; i < rest.length(); i++) {
            char c = rest.charAt(i);
            if (c == '%' && i + 2 < rest.length()
                    && Character.digit(rest.charAt(i + 1), 16) >= 0 && Character.digit(rest.charAt(i + 2), 16) >= 0) {
                int b = Character.digit(rest.charAt(i + 1), 16) * 16 + Character.digit(rest.charAt(i + 2), 16);
                out.append(b < 0x80 ? (char) b : '\uFFFD');  // a byte >= 0x80 belongs to a non-ASCII character
                i += 2;
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }

    /**
     * True if offset {@code at} of a script block that starts at
     * {@code from} lies inside a single-quoted string literal, with the
     * character at {@code at} not escaped -- so a quote there ends the
     * string. Tracks strings, template literals and comments; regex
     * literals are not modelled.
     */
    private static boolean insideSingleQuotedJsString(String body, int from, int at) {
        char quote = 0;          // 0 = code, otherwise the open string's quote
        boolean escaped = false;
        boolean lineComment = false, blockComment = false;
        for (int i = from; i < at; i++) {
            char c = body.charAt(i);
            if (lineComment) { if (c == '\n' || c == '\r') lineComment = false; continue; }
            if (blockComment) { if (c == '*' && i + 1 < at && body.charAt(i + 1) == '/') { blockComment = false; i++; } continue; }
            if (quote != 0) {
                if (escaped) { escaped = false; continue; }
                if (c == '\\') { escaped = true; continue; }
                if (c == quote) quote = 0;
                else if ((c == '\n' || c == '\r') && quote != '`') quote = 0;  // unterminated string literal
                continue;
            }
            if (c == '/' && i + 1 < at && body.charAt(i + 1) == '/') { lineComment = true; i++; continue; }
            if (c == '/' && i + 1 < at && body.charAt(i + 1) == '*') { blockComment = true; i++; continue; }
            if (c == '\'' || c == '"' || c == '`') quote = c;
        }
        return quote == '\'' && !escaped;
    }
}
