package com.harness.llm.logic;

import java.util.regex.Pattern;

/**
 * Classification logic for api_security_validation's mass-assignment
 * probe. Montoya-free.
 *
 * Directly implements the specialist agent's own suggested_test for
 * this finding class (see agents/api_security_agent.py's docstring):
 * "Resend a create/update request with an extra unexpected field (e.g.
 * 'role': 'admin') added to the JSON body and check whether the
 * response reflects it back as accepted." The probe adds a field the
 * ORIGINAL request never sent. A reflection alone is not enough (code
 * review 02 R27): the write must succeed and a read of the resource
 * after it must show the field at the injected value where a read
 * before it did not -- only then has the server bound request JSON onto
 * the stored object without an allowlist of settable fields.
 *
 * Deliberately string-based, not a full JSON parse/serialize round
 * trip: injectField() only ever needs to insert one flat key before the
 * closing brace of an object-shaped body, and a full parser would need
 * to perfectly round-trip arbitrary real-world JSON (key ordering,
 * number formatting, unicode escaping) to avoid corrupting requests
 * this technique isn't even trying to test.
 */
public final class MassAssignmentLogic {

    public enum Verdict { CONFIRMED, SUPPORTED, REJECTED, INVALID }

    public record Evidence(Verdict verdict, double confidence, boolean confirmed, String summary, String detail) {}

    private MassAssignmentLogic() {}

    /**
     * @return the body with `"fieldName":fieldValueJson` inserted before the final `}`,
     *         or null if the body isn't a plain JSON object ({...}).
     */
    public static String injectField(String originalBody, String fieldName, String fieldValueJson) {
        if (originalBody == null) return null;
        String trimmed = originalBody.trim();
        if (!trimmed.startsWith("{") || !trimmed.endsWith("}")) return null;

        String withoutClosingBrace = trimmed.substring(0, trimmed.length() - 1);
        boolean emptyObject = withoutClosingBrace.trim().endsWith("{");
        String separator = emptyObject ? "" : ",";
        return withoutClosingBrace + separator + "\"" + fieldName + "\":" + fieldValueJson + "}";
    }

    /** True for a 2xx status: the server performed the request. */
    public static boolean isSuccess(int status) {
        return status >= 200 && status < 300;
    }

    /**
     * True if `body` carries `"fieldName": fieldValueJson` as one key/value
     * pair. The key and the value must be bound to each other: the key in
     * one place and the value elsewhere ({"role":"user","title":"admin"})
     * is not the field set to the value.
     */
    public static boolean carriesField(String body, String fieldName, String fieldValueJson) {
        if (body == null || fieldName == null || fieldValueJson == null) return false;
        return Pattern.compile("\"" + Pattern.quote(fieldName) + "\"\\s*:\\s*" + Pattern.quote(fieldValueJson))
                .matcher(body).find();
    }

    /**
     * Mass assignment is confirmed only by a successful change of the
     * protected field: the write carrying the injected field succeeded
     * (2xx), a read of the resource before the write did not show the field
     * at the injected value, and a read after it does. A response that only
     * echoes the request -- or names the field to reject it, as a 400 that
     * lists "rejected":{"role":"admin"} does -- proves nothing about what
     * was stored.
     *
     * @param fieldName the injected field
     * @param fieldValueJson the injected value, as JSON (e.g. "\"admin\"")
     * @param fieldAlreadyInRequestBody true if the original request already set the field
     * @param baselineResponseBody the captured (unmodified) response body, or null
     * @param mutatedStatus status of the write carrying the injected field
     * @param mutatedResponseBody body of that write's response, or null
     * @param beforeReadStatus status of a read of the resource before the write, or -1 if not sent
     * @param beforeReadBody body of that read, or null
     * @param afterReadStatus status of a read of the resource after the write, or -1 if not sent
     * @param afterReadBody body of that read, or null
     */
    public static Evidence evaluate(String fieldName, String fieldValueJson, boolean fieldAlreadyInRequestBody,
                                     String baselineResponseBody, int mutatedStatus, String mutatedResponseBody,
                                     int beforeReadStatus, String beforeReadBody,
                                     int afterReadStatus, String afterReadBody) {
        if (fieldAlreadyInRequestBody) {
            return new Evidence(Verdict.INVALID, 0.0, false,
                    "The field '" + fieldName + "' was already present in the original request body -- not a "
                            + "useful probe for blind mass assignment (the field is evidently already settable, "
                            + "intentionally or not, by the request's own author).",
                    "");
        }
        String detail = "write status=" + mutatedStatus + " | read before status=" + beforeReadStatus
                + " | read after status=" + afterReadStatus;
        if (!isSuccess(mutatedStatus)) {
            return new Evidence(Verdict.REJECTED, 0.75, false,
                    "The server refused the write carrying the injected field ('" + fieldName + "': "
                            + fieldValueJson + ") with status " + mutatedStatus + " -- a refusal, even one that "
                            + "names the field, is the field allowlist working, not mass assignment.",
                    detail);
        }
        boolean shownBefore = (isSuccess(beforeReadStatus) && carriesField(beforeReadBody, fieldName, fieldValueJson))
                || carriesField(baselineResponseBody, fieldName, fieldValueJson);
        if (shownBefore) {
            return new Evidence(Verdict.SUPPORTED, 0.4, false,
                    "The resource already showed '" + fieldName + "': " + fieldValueJson + " before the "
                            + "write -- the probe cannot show that the injected value was newly accepted.",
                    detail);
        }
        boolean persisted = isSuccess(beforeReadStatus) && isSuccess(afterReadStatus)
                && carriesField(afterReadBody, fieldName, fieldValueJson);
        if (persisted) {
            return new Evidence(Verdict.CONFIRMED, 0.85, true,
                    "Adding an unrequested field ('" + fieldName + "': " + fieldValueJson + ") to the request "
                            + "body was accepted (status " + mutatedStatus + "), and a fresh read of the resource "
                            + "now shows that value where the read before the write did not -- the server binds "
                            + "request JSON onto the stored object with no allowlist of settable fields "
                            + "(mass assignment / excessive data binding).",
                    detail);
        }
        if (carriesField(mutatedResponseBody, fieldName, fieldValueJson)
                || carriesField(afterReadBody, fieldName, fieldValueJson)) {
            return new Evidence(Verdict.SUPPORTED, 0.45, false,
                    "The write carrying '" + fieldName + "': " + fieldValueJson + " was accepted and the "
                            + "value appears in a response, but no before/after read of the resource shows it "
                            + "was stored -- an echo of request input is not a changed protected field.",
                    detail);
        }
        return new Evidence(Verdict.REJECTED, 0.7, false,
                "The write was accepted but neither its response nor a read of the resource afterwards shows "
                        + "'" + fieldName + "': " + fieldValueJson + " -- no evidence of mass assignment for "
                        + "this field.",
                detail);
    }
}
