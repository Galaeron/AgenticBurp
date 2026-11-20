package com.harness.llm;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * ARC-8: GET /health is liveness only ({"status": "ok"}, no auth, no names);
 * readiness, agent names and the model egress state come from the
 * authenticated GET /health/details. A loopback stub harness records which
 * paths were requested and with which Authorization header.
 */
public final class HarnessClientHealthTest {

    private static final String TOKEN = "pairing-token-for-test";
    private static final String READY = "{\"status\": \"ok\", \"agents\": [\"sqli\", \"xss\"],"
            + " \"ollama\": {\"reachable\": true, \"missing_models\": []},"
            + " \"model_egress\": {\"allow_cloud_models\": false, \"egress\": false, \"refused\": false}}";

    private HttpServer server;
    private final Map<String, String> bodies = new ConcurrentHashMap<>();
    private final Map<String, Integer> statuses = new ConcurrentHashMap<>();
    private final List<String> requests = new CopyOnWriteArrayList<>();
    private HarnessClient client;

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/", this::handle);
        server.start();
        bodies.put("/health", "{\"status\": \"ok\"}");
        bodies.put("/pairing/check", "{\"status\": \"authenticated\"}");
        bodies.put("/health/details", READY);
        client = new HarnessClient("http://127.0.0.1:" + server.getAddress().getPort(), 5);
        client.setBearerToken(TOKEN);
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    private void handle(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        String auth = exchange.getRequestHeaders().getFirst("Authorization");
        requests.add(path + " " + (auth == null ? "-" : auth));
        boolean needsAuth = !path.equals("/health");
        int status = needsAuth && !("Bearer " + TOKEN).equals(auth) ? 401
                : statuses.getOrDefault(path, bodies.containsKey(path) ? 200 : 404);
        byte[] body = (status == 200 ? bodies.get(path) : "{\"detail\": \"no\"}").getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, body.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(body);
        }
    }

    @Test
    @DisplayName("liveness sends no token; a ready harness leaves no readiness note")
    void readyHarnessHasNoNote() {
        assertTrue(client.connectionCheck());
        assertNull(client.getLastHealthCheckError());
        assertNull(client.getLastReadinessNote());
        assertTrue(requests.contains("/health -"), requests.toString());
        assertTrue(requests.contains("/health/details Bearer " + TOKEN), requests.toString());
    }

    @Test
    @DisplayName("an unreachable model backend stays authenticated but says why it is not ready")
    void degradedBackendIsANoteNotAFailure() {
        bodies.put("/health/details", "{\"status\": \"degraded\", \"ollama\": {\"reachable\": false},"
                + " \"model_egress\": {\"egress\": false, \"refused\": false}}");
        assertTrue(client.connectionCheck());
        String note = client.getLastReadinessNote();
        assertTrue(note != null && note.contains("model backend unreachable"), String.valueOf(note));
    }

    @Test
    @DisplayName("missing models are counted, not named")
    void missingModelsAreCounted() {
        bodies.put("/health/details", "{\"status\": \"degraded\", \"ollama\": {\"reachable\": true,"
                + " \"missing_models\": [\"<html><b>evil</b>\", \"qwen3:8b\"]}}");
        assertTrue(client.connectionCheck());
        String note = client.getLastReadinessNote();
        assertTrue(note != null && note.contains("2 configured model(s) not pulled"), String.valueOf(note));
        assertFalse(note.contains("evil") || note.contains("qwen3"), note);
    }

    @Test
    @DisplayName("cloud model egress (SEC-1 opt-in) and a refused cloud slot are surfaced")
    void egressStateIsSurfaced() {
        bodies.put("/health/details", "{\"status\": \"ok\", \"model_egress\": {\"egress\": true, \"refused\": false}}");
        assertTrue(client.connectionCheck());
        assertTrue(client.getLastReadinessNote().contains("cloud model egress enabled"));
        bodies.put("/health/details", "{\"status\": \"ok\", \"model_egress\": {\"egress\": false, \"refused\": true}}");
        assertTrue(client.connectionCheck());
        assertTrue(client.getLastReadinessNote().contains("will be refused"));
    }

    @Test
    @DisplayName("an older harness without /health/details still connects, readiness unavailable")
    void missingDetailsRouteIsUnavailableNotFailed() {
        bodies.remove("/health/details");
        assertTrue(client.connectionCheck());
        assertTrue(client.getLastReadinessNote().startsWith("Readiness unavailable"));
    }

    @Test
    @DisplayName("a failed pairing clears the previous readiness note")
    void failedPairingClearsTheNote() {
        bodies.put("/health/details", "{\"status\": \"degraded\", \"ollama\": {\"reachable\": false}}");
        assertTrue(client.connectionCheck());
        client.setBearerToken("wrong-token");
        assertFalse(client.connectionCheck());
        assertNull(client.getLastReadinessNote());
        assertTrue(client.getLastHealthCheckError().contains("HTTP 401"));
    }

    @Test
    @DisplayName("agent names come from the authenticated /health/details, not liveness")
    void agentNamesComeFromDetails() {
        // Negative control: GET /health carries no agents, so reading them
        // from it (the pre-ARC-8 path) would return an empty list.
        assertEquals(List.of("sqli", "xss"), client.listAgentNames());
        assertEquals(List.of("/health/details Bearer " + TOKEN), requests);
        client.setBearerToken(null);
        assertEquals(List.of(), client.listAgentNames(), "unpaired: 401 gives no names");
    }
}
