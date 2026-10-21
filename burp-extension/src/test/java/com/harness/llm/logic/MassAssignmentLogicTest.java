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

    // ---------------------------------------------------------------- RV-N N3
    @Test
    @DisplayName("N3: the created object is the Location header, else the write path plus a top-level id")
    void createdObjectReferenceFromLocationOrId() {
        assertEquals("/users/43", createdObjectReference("/users", " /users/43 ", "{\"id\":99}"));
        assertEquals("/users/44", createdObjectReference("/users?x=1", null, "{\"id\":44}"));
        assertEquals("/users/44", createdObjectReference("/users/", "", "{\"id\":44}"));
        assertEquals("/users/u_9-a", createdObjectReference("/users", null, "{\"name\":\"x\", \"id\" : \"u_9-a\"}"));
        assertNull(createdObjectReference("/users", null, "{}"));
        assertNull(createdObjectReference(null, null, "{\"id\":1}"));
    }

    @Test
    @DisplayName("N3: only a top-level id of safe characters names the created object")
    void topLevelIdOnly() {
        assertEquals("43", topLevelId("{\"id\":43}"));
        assertNull(topLevelId("{\"user\":{\"id\":5}}"));
        assertNull(topLevelId("{\"items\":[{\"id\":5}]}"));
        assertNull(topLevelId("[{\"id\":1}]"));
        assertNull(topLevelId("{\"id\":\"../admin\"}"));
        assertNull(topLevelId("{\"id\":true}"));
        assertNull(topLevelId("{\"ids\":\"5\"}"));
        assertNull(topLevelId("{\"note\":\"\\\"id\\\":9\"}"));
        assertNull(topLevelId(null));
    }

    @Test
    @DisplayName("Q4: a small fixed set of id keys, top level or under data, names the created object; ambiguity names none")
    void createdObjectIdKeys() {
        assertEquals("43", createdObjectId("{\"id\":43}", "/users"), "the base rule first");
        assertEquals("43", createdObjectId("{\"name\":\"x\",\"userId\":43}", "/users"));
        assertEquals("u-1", createdObjectId("{\"user_id\":\"u-1\"}", "/api/users/"));
        assertEquals("a-b", createdObjectId("{\"UUID\":\"a-b\"}", "/users"), "keys ignore case");
        assertEquals("5f", createdObjectId("{\"_id\":\"5f\"}", "/things"));
        assertEquals("g1", createdObjectId("{\"guid\":\"g1\"}", null), "the fixed keys need no path");
        assertEquals("43", createdObjectId("{\"data\":{\"type\":\"users\",\"id\":\"43\",\"attributes\":{\"id\":9}}}", "/users"));
        assertEquals("7", createdObjectId("{\"data\":{\"userId\":7}}", "/users"));
        assertEquals("43", createdObjectId("{\"userId\":43,\"data\":{\"id\":\"43\"}}", "/users"), "one distinct value");
        assertEquals("43", createdObjectId("{\"id\":43,\"userId\":7}", "/users"), "a top-level id keeps its priority");
        assertEquals("3", createdObjectId("{\"categoryId\":3}", "/categories"));
        assertEquals("3", createdObjectId("{\"addressId\":3}", "/addresses"));
        assertEquals("3", createdObjectId("{\"noteId\":3}", "/notes"));
        assertEquals("3", createdObjectId("{\"user_group_id\":3}", "/user_groups"));

        assertNull(createdObjectId("{\"userId\":43,\"uuid\":\"u-9\"}", "/users"), "two candidates are ambiguous");
        assertNull(createdObjectId("{\"ownerId\":5}", "/users"), "another resource's id is not this one's");
        assertNull(createdObjectId("{\"user\":{\"id\":5}}", "/users"), "nested only under data");
        assertNull(createdObjectId("{\"data\":{\"attributes\":{\"id\":5}}}", "/users"), "one level under data only");
        assertNull(createdObjectId("{\"data\":[{\"id\":5}]}", "/users"));
        assertNull(createdObjectId("{\"uuid\":\"../x\"}", "/users"), "not a safe id");
        assertNull(createdObjectId("{\"id\":\"../admin\",\"userId\":5}", "/users"), "an unsafe top-level id is not skipped");
        assertNull(createdObjectId("{\"userId\":true}", "/users"));
        assertNull(createdObjectId("{\"userId\":4.5}", "/users"));
        assertNull(createdObjectId("{\"userId\":5", "/users"), "not well-formed");
        assertNull(createdObjectId("[{\"userId\":5}]", "/users"));
        assertNull(createdObjectId("{\"note\":\"\\\"userId\\\":9\"}", "/users"), "inside a string");
        assertNull(createdObjectId("{\"v1id\":3}", "/v1"), "a version segment is no resource");
        assertNull(createdObjectId(null, "/users"));

        assertEquals("/users/43", createdObjectReference("/users", null, "{\"userId\":43}"));
        assertEquals("https://other.example/users/43", createdObjectReference("/users", "https://other.example/users/43",
                "{\"id\":43}"), "a Location always wins, so a cross-origin one leaves nothing to fall back to");
    }

    @Test
    @DisplayName("N3: the detail says which resources the before and after reads fetched")
    void readTargetsInDetail() {
        Evidence e = evaluate("role", "\"admin\"", false, "{\"id\":43}", 201, "{\"id\":44,\"role\":\"admin\"}",
                200, "{\"id\":43,\"role\":\"user\"}", 200, "{\"id\":44,\"role\":\"admin\"}",
                "read before: /users/43, read after: /users/44");
        assertEquals(Verdict.CONFIRMED, e.verdict());
        assertTrue(e.detail().contains("read after: /users/44"), e.detail());
    }
}
