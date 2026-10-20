package com.harness.llm.logic;

import java.util.List;
import java.util.Locale;
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
        /** The payload's leading quote must close a single-quoted string inside a {@code <script>} block. */
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

    /** Elements whose content the HTML parser reads as text up to the matching end tag. */
    private static final Set<String> RAW_TEXT_ELEMENTS = Set.of(
            "script", "style", "textarea", "title", "xmp", "iframe", "noembed", "noframes", "noscript", "plaintext");

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
                if (executesAt(payload.context(), body, at)) return Verdict.CONFIRMED;
            }
        }
        if (body.contains(canary)) return Verdict.SUPPORTED;
        return Verdict.REJECTED;
    }

    /** True if a payload of the given context, reflected raw at offset {@code at}, executes there. */
    static boolean executesAt(Context context, String body, int at) {
        switch (context) {
            case HTML_TAG_BREAKOUT: {
                // The payload is "><script>...: scanning through its own "> must
                // leave the parser in HTML text, so its <script> opens a script.
                HtmlState s = HtmlState.scan(body, at + 2);
                return s.mode == Mode.TEXT;
            }
            case JS_SINGLE_QUOTED_STRING: {
                HtmlState s = HtmlState.scan(body, at);
                return s.mode == Mode.RAW_TEXT && "script".equals(s.element)
                        && insideSingleQuotedJsString(body, s.rawTextStart, at);
            }
            case DOUBLE_QUOTED_ATTRIBUTE: {
                HtmlState s = HtmlState.scan(body, at);
                return s.mode == Mode.TAG && !s.closingTag && s.attributeQuote == '"';
            }
            default:
                return false;
        }
    }

    private enum Mode { TEXT, TAG, COMMENT, RAW_TEXT }

    /**
     * A deliberately small HTML tokenizer: enough to tell text, the inside of
     * a tag (and of a quoted attribute value), comments and raw-text
     * elements apart. It is not a full HTML5 parser; where it is unsure it
     * stays in a non-executable mode rather than guessing executable.
     */
    private static final class HtmlState {
        Mode mode = Mode.TEXT;
        String element;          // tag being read (TAG) or raw-text element (RAW_TEXT)
        boolean closingTag;
        char attributeQuote;     // 0, '"' or '\'' while inside a quoted attribute value
        int rawTextStart = -1;

        static HtmlState scan(String body, int end) {
            HtmlState s = new HtmlState();
            char lastInTag = 0;  // last non-space character inside the current tag
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
                                s.mode = Mode.TAG;
                                s.element = body.substring(nameStart, j).toLowerCase(Locale.ROOT);
                                s.closingTag = closing;
                                s.attributeQuote = 0;
                                lastInTag = 0;
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
                            if (c == s.attributeQuote) { s.attributeQuote = 0; lastInTag = c; }
                            i++;
                            continue;
                        }
                        if ((c == '"' || c == '\'') && lastInTag == '=') { s.attributeQuote = c; i++; continue; }
                        if (c == '>') {
                            if (!s.closingTag && RAW_TEXT_ELEMENTS.contains(s.element)) {
                                s.mode = Mode.RAW_TEXT;
                                s.rawTextStart = i + 1;
                            } else {
                                s.mode = Mode.TEXT;
                                s.element = null;
                            }
                            i++;
                            continue;
                        }
                        if (!Character.isWhitespace(c)) lastInTag = c;
                        i++;
                    }
                    case RAW_TEXT -> {
                        String endTag = "</" + s.element;
                        if (!"plaintext".equals(s.element)
                                && body.regionMatches(true, i, endTag, 0, endTag.length())
                                && (i + endTag.length() >= body.length() || !isTagNameChar(body.charAt(i + endTag.length())))) {
                            s.mode = Mode.TAG;
                            s.closingTag = true;
                            s.attributeQuote = 0;
                            lastInTag = 0;
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
