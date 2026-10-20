package com.harness.llm.logic;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static com.harness.llm.logic.MassAssignmentLogic.*;
import static org.junit.jupiter.api.Assertions.*;

public final class MassAssignmentLogicTest {

    @Test
    @DisplayName("injectField adds the field before the closing brace of a non-empty object")
    void injectFieldNonEmptyObject() {
        String result = injectField("{\"name\":\"alice\"}", "role", "\"admin\"");
        assertEquals("{\"name\":\"alice\",\"role\":\"admin\"}", result);
    }

    @Test
    @DisplayName("injectField handles an empty object body without a stray leading comma")
    void injectFieldEmptyObject() {
        String result = injectField("{}", "role", "\"admin\"");
        assertEquals("{\"role\":\"admin\"}", result);
    }

    @Test
    @DisplayName("injectField returns null for a non-object body (array, plain text, empty)")
    void injectFieldRejectsNonObjectBodies() {
        assertNull(injectField("[1,2,3]", "role", "\"admin\""));
        assertNull(injectField("not json at all", "role", "\"admin\""));
        assertNull(injectField("", "role", "\"admin\""));
        assertNull(injectField(null, "role", "\"admin\""));
    }

    @Test
    @DisplayName("field already in the original request body -> invalid, not a useful probe")
    void fieldAlreadyPresentIsInvalid() {
        Evidence e = evaluate("role", "\"admin\"", true, "{}", 200, "{\"role\":\"admin\"}", 200, "{}", 200, "{}");
        assertEquals(Verdict.INVALID, e.verdict());
    }

    @Test
    @DisplayName("write accepted, read before lacks the field, read after shows it -> confirmed mass assignment")
    void persistedChangeIsConfirmed() {
        Evidence e = evaluate("role", "\"admin\"", false,
                "{\"id\":1,\"name\":\"alice\"}",
                200, "{\"id\":1,\"name\":\"alice\",\"role\":\"admin\"}",
                200, "{\"id\":1,\"name\":\"alice\",\"role\":\"user\"}",
                200, "{\"id\":1,\"name\":\"alice\",\"role\":\"admin\"}");
        assertEquals(Verdict.CONFIRMED, e.verdict());
        assertTrue(e.confirmed());
    }

    @Test
    @DisplayName("R27: injected field reflected back but not stored -> supported only, reflection alone is not proof")
    void reflectedWithoutPersistenceIsSupported() {
        Evidence e = evaluate("role", "\"admin\"", false,
                "{\"id\":1,\"name\":\"alice\"}",
                200, "{\"id\":1,\"name\":\"alice\",\"role\":\"admin\"}",
                200, "{\"id\":1,\"name\":\"alice\",\"role\":\"user\"}",
                200, "{\"id\":1,\"name\":\"alice\",\"role\":\"user\"}");
        assertEquals(Verdict.SUPPORTED, e.verdict());
        assertFalse(e.confirmed());
    }

    @Test
    @DisplayName("R27: a 400 that names the rejected field -> rejected")
    void refusedWriteIsRejected() {
        Evidence e = evaluate("role", "\"admin\"", false, "{\"name\":\"sample\"}",
                400, "{\"error\":\"Unknown field. Request rejected.\",\"rejected\":{\"role\":\"admin\"}}",
                200, "{\"name\":\"sample\"}", -1, null);
        assertEquals(Verdict.REJECTED, e.verdict());
        assertFalse(e.confirmed());
    }

    @Test
    @DisplayName("R27: a read after the write without a successful read before it is not persistence evidence")
    void afterReadWithoutBeforeReadIsNotConfirmed() {
        Evidence e = evaluate("role", "\"admin\"", false, "{\"name\":\"sample\"}",
                200, "{\"name\":\"sample\"}", 405, "method not allowed", 200, "{\"role\":\"admin\"}");
        assertFalse(e.confirmed());
    }

    @Test
    @DisplayName("the field must be bound to the value as one key/value pair")
    void carriesFieldBindsKeyToValue() {
        assertTrue(carriesField("{\"role\" : \"admin\"}", "role", "\"admin\""));
        assertFalse(carriesField("{\"role\":\"user\",\"title\":\"admin\"}", "role", "\"admin\""));
        assertFalse(carriesField(null, "role", "\"admin\""));
    }

    @Test
    @DisplayName("injected field absent from mutated response -> rejected")
    void notReflectedIsRejected() {
        Evidence e = evaluate("role", "\"admin\"", false,
                "{\"id\":1,\"name\":\"alice\"}", 200, "{\"id\":1,\"name\":\"alice\"}",
                200, "{\"id\":1,\"name\":\"alice\"}", 200, "{\"id\":1,\"name\":\"alice\"}");
        assertEquals(Verdict.REJECTED, e.verdict());
        assertFalse(e.confirmed());
    }

    @Test
    @DisplayName("field/value already present in baseline response too -> supported, not confirmed")
    void alreadyInBaselineIsSupportedNotConfirmed() {
        Evidence e = evaluate("role", "\"admin\"", false,
                "{\"id\":1,\"role\":\"admin\"}", 200, "{\"id\":1,\"role\":\"admin\"}",
                200, "{\"id\":1,\"role\":\"admin\"}", 200, "{\"id\":1,\"role\":\"admin\"}");
        assertEquals(Verdict.SUPPORTED, e.verdict());
        assertFalse(e.confirmed());
    }
}
