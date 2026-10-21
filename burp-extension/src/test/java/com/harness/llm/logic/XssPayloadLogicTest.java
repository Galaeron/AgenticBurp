package com.harness.llm.logic;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static com.harness.llm.logic.XssPayloadLogic.*;
import static org.junit.jupiter.api.Assertions.*;

public final class XssPayloadLogicTest {

    @Test
    @DisplayName("nextPayload cycles through untried payloads, ends at null")
    void nextPayloadCyclesAndExhausts() {
        List<String> tried = new ArrayList<>();
        int count = 0;
        Payload p;
        while ((p = nextPayload(tried)) != null) {
            assertFalse(tried.contains(p.template()));
            tried.add(p.template());
            count++;
            if (count > 10) fail("nextPayload did not terminate");
        }
        assertEquals(PAYLOADS.size(), count);
    }

    @Test
    @DisplayName("raw tag breakout surviving unescaped -> CONFIRMED")
    void rawBreakoutIsConfirmed() {
        Payload p = PAYLOADS.get(0); // "><script>__C__</script>
        String canary = "ABC123";
        Verdict v = classify(p, canary, "<html>\"><script>ABC123</script></html>");
        assertEquals(Verdict.CONFIRMED, v);
    }

    @Test
    @DisplayName("HTML-encoded reflection is not confirmed, only the plain canary text counts as echo")
    void encodedReflectionIsNotConfirmed() {
        Payload p = PAYLOADS.get(0);
        String canary = "ABC123";
        String encoded = "&quot;&gt;&lt;script&gt;ABC123&lt;/script&gt;";
        Verdict v = classify(p, canary, encoded);
        assertEquals(Verdict.SUPPORTED, v, "canary text itself is present (as encoded-neighbor text), breakout chars are not");
    }

    @Test
    @DisplayName("nothing reflected at all -> REJECTED")
    void nothingReflectedIsRejected() {
        Payload p = PAYLOADS.get(0);
        Verdict v = classify(p, "ABC123", "<html>no match here</html>");
        assertEquals(Verdict.REJECTED, v);
    }

    @Test
    @DisplayName("null body does not throw, classified REJECTED")
    void nullBodyIsSafe() {
        assertEquals(Verdict.REJECTED, classify(PAYLOADS.get(0), "ABC123", null));
    }

    @Test
    @DisplayName("plain-echo payload (last resort) can never reach CONFIRMED, only SUPPORTED")
    void plainCanaryPayloadCapsAtSupported() {
        Payload plain = PAYLOADS.get(PAYLOADS.size() - 1);
        assertEquals("", plain.rawMarker());
        Verdict v = classify(plain, "ABC123", "<div>ABC123</div>");
        assertEquals(Verdict.SUPPORTED, v, "reflecting plain text proves nothing about escaping -- must not confirm");
    }

    @Test
    @DisplayName("JS string breakout surviving raw -> CONFIRMED")
    void jsBreakoutIsConfirmed() {
        Payload p = PAYLOADS.get(1); // '-__C__-'
        Verdict v = classify(p, "ABC123", "<script>var x=''-ABC123-'';</script>");
        assertEquals(Verdict.CONFIRMED, v);
    }

    @Test
    @DisplayName("R28: the payload as a whole JS string literal is not a breakout -> not CONFIRMED")
    void jsPayloadAsHarmlessLiteralIsNotConfirmed() {
        Payload p = PAYLOADS.get(1);
        Verdict v = classify(p, "ABC123", "<script>var x='-ABC123-'</script>");
        assertEquals(Verdict.SUPPORTED, v, "the canary came back, but inside code position it is just a string");
    }

    @Test
    @DisplayName("R28: an escaped quote does not end the JS string -> not CONFIRMED")
    void escapedJsQuoteIsNotConfirmed() {
        Payload p = PAYLOADS.get(1);
        Verdict v = classify(p, "ABC123", "<script>var x='a\\'-ABC123-'</script>");
        assertEquals(Verdict.SUPPORTED, v);
    }

    @Test
    @DisplayName("R28: an ordinary page script without the injected canary -> REJECTED")
    void ordinaryScriptWithoutCanaryIsRejected() {
        Verdict v = classify(PAYLOADS.get(0), "ABC123", "<script>console.log('ordinary application script');</script>");
        assertEquals(Verdict.REJECTED, v);
    }

    @Test
    @DisplayName("R28: the tag-breakout payload reflected inside a textarea is inert -> not CONFIRMED")
    void tagBreakoutInsideTextareaIsNotConfirmed() {
        Verdict v = classify(PAYLOADS.get(0), "ABC123", "<textarea>\"><script>ABC123</script></textarea>");
        assertEquals(Verdict.SUPPORTED, v);
    }

    @Test
    @DisplayName("R28: the tag-breakout payload reflected inside an HTML comment is inert -> not CONFIRMED")
    void tagBreakoutInsideCommentIsNotConfirmed() {
        Verdict v = classify(PAYLOADS.get(0), "ABC123", "<!-- q=\"><script>ABC123</script> -->");
        assertEquals(Verdict.SUPPORTED, v);
    }

    @Test
    @DisplayName("the tag-breakout payload closing a double-quoted attribute -> CONFIRMED")
    void tagBreakoutFromDoubleQuotedAttributeIsConfirmed() {
        Verdict v = classify(PAYLOADS.get(0), "ABC123", "<input value=\"\"><script>ABC123</script>\">");
        assertEquals(Verdict.CONFIRMED, v);
    }

    @Test
    @DisplayName("R28: the tag-breakout payload stuck inside a single-quoted attribute -> not CONFIRMED")
    void tagBreakoutInsideSingleQuotedAttributeIsNotConfirmed() {
        Verdict v = classify(PAYLOADS.get(0), "ABC123", "<input value='\"><script>ABC123</script>'>");
        assertEquals(Verdict.SUPPORTED, v);
    }

    @Test
    @DisplayName("event-handler payload closing a double-quoted attribute -> CONFIRMED")
    void eventHandlerInDoubleQuotedAttributeIsConfirmed() {
        Verdict v = classify(PAYLOADS.get(2), "ABC123", "<input value=\"\"onmouseover=\"ABC123\">");
        assertEquals(Verdict.CONFIRMED, v);
    }

    @Test
    @DisplayName("R28: event-handler payload reflected as text -> not CONFIRMED")
    void eventHandlerAsTextIsNotConfirmed() {
        Verdict v = classify(PAYLOADS.get(2), "ABC123", "<p>\"onmouseover=\"ABC123</p>");
        assertEquals(Verdict.SUPPORTED, v);
    }

    @Test
    @DisplayName("any one executable occurrence is enough, even after an inert one")
    void laterExecutableOccurrenceIsConfirmed() {
        Verdict v = classify(PAYLOADS.get(0), "ABC123",
                "<title>\"><script>ABC123</script></title><p>\"><script>ABC123</script></p>");
        assertEquals(Verdict.CONFIRMED, v);
    }

    // ---------------------------------------------------------------- RV-N N4
    private static Verdict js(String body) {
        return classify(PAYLOADS.get(1), "ABC123", body); // '-__C__-'
    }

    @Test
    @DisplayName("N4: the quote closes a single-quoted string in an event-handler attribute -> confirmed")
    void eventHandlerStringBreakoutIsConfirmed() {
        assertEquals(Verdict.CONFIRMED, js("<button onclick=\"track(''-ABC123-'')\">Go</button>"));
        assertEquals(Verdict.CONFIRMED, js("<body ONLOAD=\"init(''-ABC123-'')\">"));
        assertEquals(Verdict.CONFIRMED, js("<button onclick=track(''-ABC123-'')>Go</button>"));
        assertEquals(Verdict.CONFIRMED, js("<button onclick=\"track(&#39;'-ABC123-'&#39;)\">"),
                "the string was opened by a character reference");
        assertEquals(Verdict.CONFIRMED, js("<button onclick=\"track(&apos;'-ABC123-'&apos;)\">"));
    }

    @Test
    @DisplayName("N4: the quote closes a single-quoted string in a javascript: URL -> confirmed")
    void javascriptUrlStringBreakoutIsConfirmed() {
        assertEquals(Verdict.CONFIRMED, js("<a href=\"javascript:go(''-ABC123-'')\">Go</a>"));
        assertEquals(Verdict.CONFIRMED, js("<a href=\" \tJava&#x0A;Script:go(''-ABC123-'')\">Go</a>"));
        assertEquals(Verdict.CONFIRMED, js("<a href=\"javascript:go(%27'-ABC123-'%27)\">Go</a>"));
        assertEquals(Verdict.CONFIRMED, js("<iframe src=\"javascript:go(''-ABC123-'')\"></iframe>"));
        assertEquals(Verdict.CONFIRMED, js("<form action=\"javascript:go(''-ABC123-'')\"></form>"));
    }

    @Test
    @DisplayName("N4: inert contexts for the same reflection stay unconfirmed")
    void inertContextsAreNotConfirmed() {
        assertNotEquals(Verdict.CONFIRMED, js("<p>''-ABC123-''</p>"), "text node");
        assertNotEquals(Verdict.CONFIRMED, js("<input value=\"''-ABC123-''\">"), "ordinary attribute value");
        assertNotEquals(Verdict.CONFIRMED, js("<button title=\"track(''-ABC123-'')\">"), "not a handler");
        assertNotEquals(Verdict.CONFIRMED, js("<a href=\"/go?q=''-ABC123-''\">"), "not a javascript: URL");
        assertNotEquals(Verdict.CONFIRMED, js("<img src=\"javascript:go(''-ABC123-'')\">"), "img src does not navigate");
        assertNotEquals(Verdict.CONFIRMED, js("<button onclick='track(''-ABC123-'')'>"), "the quote ends the attribute");
        assertNotEquals(Verdict.CONFIRMED, js("<button onclick=\"track(&quot;'-ABC123-'&quot;)\">"),
                "inside a double-quoted JS string");
        assertNotEquals(Verdict.CONFIRMED, js("</button onclick=\"track(''-ABC123-'')\">"), "end tag");
        assertNotEquals(Verdict.CONFIRMED, js("<!-- <button onclick=\"track(''-ABC123-'')\"> -->"), "comment");
        assertNotEquals(Verdict.CONFIRMED, js("<textarea><b onclick=\"t(''-ABC123-'')\"></textarea>"), "RCDATA");
        assertNotEquals(Verdict.CONFIRMED, js("<button onclick=\"track('\" data-x=\"'-ABC123-'')\">"),
                "the payload sits in another attribute");
        assertNotEquals(Verdict.CONFIRMED, js("<button onclick=\"track(''-ABC123\" x=\"-'')\">"),
                "the payload is split across attributes");
    }

    @Test
    @DisplayName("N4: character references in attribute values decode as an HTML parser decodes them")
    void characterReferencesDecode() {
        assertEquals("'", decodeCharacterReferences("&#39;"));
        assertEquals("'", decodeCharacterReferences("&#x27;"));
        assertEquals("'x", decodeCharacterReferences("&#39x"));
        assertEquals("'", decodeCharacterReferences("&apos;"));
        assertEquals("\"", decodeCharacterReferences("&quot;"));
        assertEquals("\")", decodeCharacterReferences("&quot)"));
        assertEquals("&quotx", decodeCharacterReferences("&quotx"));
        assertEquals("&quot=", decodeCharacterReferences("&quot="));
        assertEquals("&apos", decodeCharacterReferences("&apos"));
        assertEquals("\uFFFD", decodeCharacterReferences("&#0;"));
        assertEquals("\uFFFD", decodeCharacterReferences("&#x110000;"));
        assertEquals("&#;", decodeCharacterReferences("&#;"));
        assertEquals("&unknown;", decodeCharacterReferences("&unknown;"));
        assertEquals("&#39;", decodeCharacterReferences("&amp;#39;"));
    }

    @Test
    @DisplayName("N4: a javascript: URL's script is found as a URL parser finds it")
    void javascriptUrlSourceParsed() {
        assertEquals("go()", javascriptUrlSource("javascript:go()"));
        assertEquals("go()", javascriptUrlSource(" \tJava\nScript:go()"));
        assertEquals("'", javascriptUrlSource("JAVASCRIPT:%27"));
        assertEquals("%zz", javascriptUrlSource("javascript:%zz"));
        assertNull(javascriptUrlSource("/go?x"));
        assertNull(javascriptUrlSource("vbscript:x"));
        assertNull(javascriptUrlSource("javascript go"));
        assertNull(javascriptUrlSource("%6Aavascript:x"));
        assertNull(javascriptUrlSource(null));
    }

    // ---------------------------------------------------------------- RV-Q Q5
    @Test
    @DisplayName("Q5: only a script type the browser runs makes a script block script")
    void scriptTypesTheBrowserRuns() {
        assertTrue(runsAsScript(Map.of()));
        assertTrue(runsAsScript(Map.of("type", "")));
        assertTrue(runsAsScript(Map.of("type", "text/javascript")));
        assertTrue(runsAsScript(Map.of("type", " \tText/JavaScript\n")), "ASCII case and whitespace ignored");
        assertTrue(runsAsScript(Map.of("type", "application/ecmascript")));
        assertTrue(runsAsScript(Map.of("type", "text/javascript1.5")));
        assertTrue(runsAsScript(Map.of("type", "MODULE")));
        assertTrue(runsAsScript(Map.of("type", "text&#47;javascript")), "the parser decodes the value");
        assertTrue(runsAsScript(Map.of("language", "")));
        assertTrue(runsAsScript(Map.of("language", "JavaScript")));
        assertTrue(runsAsScript(Map.of("type", "", "language", "vbscript")), "an empty type wins");

        assertFalse(runsAsScript(Map.of("type", "text/template")));
        assertFalse(runsAsScript(Map.of("type", "application/json")));
        assertFalse(runsAsScript(Map.of("type", "application/ld+json")));
        assertFalse(runsAsScript(Map.of("type", "importmap")));
        assertFalse(runsAsScript(Map.of("type", "speculationrules")));
        assertFalse(runsAsScript(Map.of("type", "text/babel")));
        assertFalse(runsAsScript(Map.of("type", "text/javascript; charset=utf-8")), "an essence match, no parameters");
        assertFalse(runsAsScript(Map.of("type", " ")), "whitespace only is not empty");
        assertFalse(runsAsScript(Map.of("type", "text/java\u017Fcript")), "only ASCII case is ignored");
        assertFalse(runsAsScript(Map.of("type", "text/template", "language", "javascript")), "the type wins");
        assertFalse(runsAsScript(Map.of("language", "vbscript")));
    }

    @Test
    @DisplayName("Q5: a script block of a non-JavaScript type is a data block -> not CONFIRMED")
    void dataBlockScriptIsNotConfirmed() {
        assertNotEquals(Verdict.CONFIRMED, js("<script type=\"text/template\">var q=''-ABC123-'';</script>"));
        assertNotEquals(Verdict.CONFIRMED, js("<script type=text/template>var q=''-ABC123-'';</script>"));
        assertNotEquals(Verdict.CONFIRMED, js("<SCRIPT TYPE='application/json'>{\"q\":''-ABC123-''}</SCRIPT>"));
        assertNotEquals(Verdict.CONFIRMED, js("<script type=\"text/template\" type=\"text/javascript\">var q=''-ABC123-'';</script>"),
                "the first of two type attributes counts");
        assertEquals(Verdict.CONFIRMED, js("<script type=\"module\">var q=''-ABC123-'';</script>"));
        assertEquals(Verdict.CONFIRMED, js("<script type=\"text/template\"></script><script>var q=''-ABC123-'';</script>"),
                "the next script block is typed afresh");
    }

    @Test
    @DisplayName("Q5: nothing inside <template> content executes, until the template closes")
    void templateContentIsInert() {
        assertNotEquals(Verdict.CONFIRMED, js("<template><script>var q=''-ABC123-'';</script></template>"));
        assertNotEquals(Verdict.CONFIRMED, js("<template><button onclick=\"track(''-ABC123-'')\">Go</button></template>"));
        assertNotEquals(Verdict.CONFIRMED, js("<template><a href=\"javascript:go(''-ABC123-'')\">x</a></template>"));
        assertNotEquals(Verdict.CONFIRMED, js("<TEMPLATE id=t><template></template><script>var q=''-ABC123-'';</script></TEMPLATE>"),
                "still inside the outer template");
        assertNotEquals(Verdict.CONFIRMED, classify(PAYLOADS.get(0), "ABC123",
                "<template><div title=\"\"><script>ABC123</script>\"></div></template>"));
        assertNotEquals(Verdict.CONFIRMED, classify(PAYLOADS.get(2), "ABC123",
                "<template><div title=\"\"onmouseover=\"ABC123\"></div></template>"));

        assertEquals(Verdict.CONFIRMED, js("<template><p>row</p></template><script>var q=''-ABC123-'';</script>"));
        assertEquals(Verdict.CONFIRMED, js("</template><template></template><script>var q=''-ABC123-'';</script>"),
                "a stray end tag closes nothing");
        assertEquals(Verdict.CONFIRMED, js("<script>var t='<template>';var q=''-ABC123-'';</script>"),
                "a <template> inside script text is no element");
        assertEquals(Verdict.CONFIRMED, classify(PAYLOADS.get(0), "ABC123",
                "<template></template><div title=\"\"><script>ABC123</script>\"></div>"));
    }
}
