package com.harness.llm.ui;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.harness.llm.HarnessClient;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ARC-15 follow-up: "Apply settings" must not send a throttle the user did not
 * change, and may send 0 (remove the throttle) only with confirm_unlimited --
 * the harness answers a bare 0 with 422 while a throttle is on. Builds the
 * POST /settings body exactly as the panel does (field text -> throttleToSend
 * -> HarnessClient.settingsBody) and reads it back as the wire JSON.
 */
public final class SettingsThrottleBodyTest {

    private static JsonObject wire(String fieldText, Double baseline, boolean confirmed,
                                   Map<String, Object> retry) {
        Double rps = HarnessToolsPanel.throttleToSend(fieldText, baseline);
        String json = new Gson().toJson(HarnessClient.settingsBody(rps, confirmed, retry));
        return JsonParser.parseString(json).getAsJsonObject();
    }

    @Test
    @DisplayName("an empty throttle field sends no throttle, only the retry budget")
    void emptyFieldSendsNoThrottle() {
        JsonObject body = wire("", 5.0, false, Map.of("max_retries", 2));
        assertFalse(body.has("throttle_rps"));
        assertFalse(body.has("confirm_unlimited"));
        assertEquals(2, body.getAsJsonObject("retry_budget").get("max_retries").getAsInt());
    }

    @Test
    @DisplayName("a throttle field equal to the loaded value sends no throttle")
    void unchangedFieldSendsNoThrottle() {
        assertFalse(wire("5", 5.0, false, null).has("throttle_rps"));
        assertFalse(wire(" 5.0 ", 5.0, false, null).has("throttle_rps"));
        // The throttle is already off: the field shows 0 and leaves it unchanged.
        assertFalse(wire("0", 0.0, false, null).has("throttle_rps"));
    }

    @Test
    @DisplayName("a confirmed 0 sends throttle_rps 0 plus confirm_unlimited")
    void confirmedZeroSendsZeroAndConfirm() {
        JsonObject body = wire("0", 5.0, true, null);
        assertEquals(0.0, body.get("throttle_rps").getAsDouble());
        assertTrue(body.get("confirm_unlimited").getAsBoolean());
    }

    @Test
    @DisplayName("control: an unconfirmed 0 is never sent bare")
    void unconfirmedZeroIsNotSent() {
        JsonObject body = wire("0", 5.0, false, Map.of("max_agents", 3));
        assertFalse(body.has("throttle_rps"));
        assertFalse(body.has("confirm_unlimited"));
        assertTrue(body.has("retry_budget"));
        // The old panel sent its "0" default bare via the two-arg updateSettings;
        // that path now goes through the same builder and drops it.
        assertFalse(HarnessClient.settingsBody(0.0, false, null).containsKey("throttle_rps"));
    }

    @Test
    @DisplayName("a changed positive rate is sent without the confirm field")
    void changedRateIsSentWithoutConfirm() {
        JsonObject body = wire("2.5", 5.0, false, null);
        assertEquals(2.5, body.get("throttle_rps").getAsDouble());
        assertFalse(body.has("confirm_unlimited"));
        assertEquals(7.0, wire("7", null, true, null).get("throttle_rps").getAsDouble());
        assertFalse(wire("7", null, true, null).has("confirm_unlimited"));
    }

    @Test
    @DisplayName("the loaded baseline is the live rate, or 0 when the throttle is off")
    void liveThrottleReadsGetSettings() {
        JsonObject on = JsonParser.parseString(
                "{\"throttle\": {\"enabled\": true, \"rate_per_second\": 5.0, \"burst\": 10}}").getAsJsonObject();
        JsonObject off = JsonParser.parseString(
                "{\"throttle\": {\"enabled\": false, \"rate_per_second\": 0.0}}").getAsJsonObject();
        assertEquals(5.0, HarnessToolsPanel.liveThrottle(on));
        assertEquals(0.0, HarnessToolsPanel.liveThrottle(off));
        assertNull(HarnessToolsPanel.liveThrottle(new JsonObject()));
        assertNull(HarnessToolsPanel.throttleToSend("5", HarnessToolsPanel.liveThrottle(on)));
    }
}
