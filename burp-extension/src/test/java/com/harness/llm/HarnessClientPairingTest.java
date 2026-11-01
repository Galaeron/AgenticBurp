package com.harness.llm;

import com.harness.llm.model.AnalysisModels.AnalysisRequest;
import com.harness.llm.model.AnalysisModels.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/** Real Java HTTP caller with a benign owned loopback API spy; no target sends.
 * This fixture is not the Python production API or an inference provider.
 */
class HarnessClientPairingTest {
    private static final String TOKEN = "synthetic-r02-token";

    private static class Fixture implements AutoCloseable {
        final HttpServer server;
        final AtomicReference<String> token = new AtomicReference<>(TOKEN);
        final AtomicInteger stored = new AtomicInteger();
        final List<String> credentials = new ArrayList<>();

        Fixture() throws Exception {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", exchange -> {
                String path = exchange.getRequestURI().getPath();
                String authorization = exchange.getRequestHeaders().getFirst("Authorization");
                synchronized (credentials) { credentials.add(authorization); }
                int code = 200;
                String body;
                if (path.equals("/health")) {
                    body = "{\"status\":\"ok\",\"agents\":[]}";
                } else if (!("Bearer " + token.get()).equals(authorization)) {
                    code = 401;
                    // A hostile upstream body must not reach auth diagnostics.
                    body = "{\"detail\":\"" + TOKEN + "\"}";
                } else if (path.equals("/pairing/check")) {
                    body = "{\"status\":\"authenticated\"}";
                } else if (path.equals("/analyze")) {
                    String request = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                    if (!request.contains("Ordinary captured text")) {
                        code = 400;
                        body = "{}";
                    } else {
                        stored.incrementAndGet();
                        body = "{\"coordinator_model\":\"synthetic\",\"dispatched_agents\":[],"
                                + "\"agent_reports\":[],\"summary\":\"Benign passive analysis completed\"}";
                    }
                } else {
                    body = "{\"count\":" + stored.get() + "}";
                }
                byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(code, bytes.length);
                exchange.getResponseBody().write(bytes);
                exchange.close();
            });
            server.start();
        }

        String url() { return "http://127.0.0.1:" + server.getAddress().getPort(); }
        public void close() { server.stop(0); }
    }

    private AnalysisRequest capturedRequest() {
        HttpExchange exchange = new HttpExchange();
        exchange.url = "https://captured.example/ordinary";
        exchange.method = "GET";
        exchange.request_headers = Map.of();
        exchange.response_status = 200;
        exchange.response_body = "Ordinary captured text";
        AnalysisRequest request = new AnalysisRequest();
        request.exchange = exchange;
        request.force_agents = List.of("synthetic-passive");
        return request;
    }

    @Test void configuredCredentialPairsAnalyzesAndReadsStoredResult() throws Exception {
        try (Fixture fixture = new Fixture()) {
            HarnessClient client = new HarnessClient(fixture.url(), 3);
            client.setBearerToken(TOKEN);
            assertTrue(client.connectionCheck());
            assertEquals("Benign passive analysis completed", client.analyze(capturedRequest()).summary);
            assertEquals(1, client.getJson("/stored", Duration.ofSeconds(3)).get("count").getAsInt());
            assertNull(fixture.credentials.get(0), "Public health must not receive credentials");
            client.setBaseUrl(fixture.url() + "/");
            assertTrue(client.connectionCheck(), "Equivalent origin retains its credential");
        }
    }

    @Test void missingWrongAndRotatedCredentialsRequireReconnect() throws Exception {
        try (Fixture fixture = new Fixture()) {
            HarnessClient client = new HarnessClient(fixture.url(), 3);
            client.setBearerToken(null);
            assertTrue(client.healthCheck());
            assertFalse(client.connectionCheck());
            client.setBearerToken("synthetic-wrong");
            assertFalse(client.connectionCheck());
            assertFalse(client.getLastHealthCheckError().contains(TOKEN));
            client.setBearerToken(TOKEN);
            assertTrue(client.connectionCheck());
            fixture.token.set("synthetic-restarted-token");
            assertFalse(client.connectionCheck());
            assertTrue(client.getLastHealthCheckError().contains("reconnect"));
            HarnessClient.HarnessException denied = assertThrows(HarnessClient.HarnessException.class,
                    () -> client.analyze(capturedRequest()));
            assertFalse(denied.getMessage().contains(TOKEN));
            assertEquals(0, fixture.stored.get());
            client.setBearerToken("synthetic-restarted-token");
            assertTrue(client.connectionCheck());
        }
    }

    @Test void changingOriginNeverForwardsPreviousCredential() throws Exception {
        try (Fixture first = new Fixture(); Fixture second = new Fixture()) {
            HarnessClient client = new HarnessClient(first.url(), 3);
            client.setBearerToken(TOKEN);
            assertTrue(client.connectionCheck());
            client.setBaseUrl(second.url());
            assertFalse(client.connectionCheck());
            assertTrue(second.credentials.stream().allMatch(value -> value == null));
            client.setBearerToken(TOKEN);
            assertTrue(client.connectionCheck());
        }
    }

    @Test void insecureOrCredentialBearingUrlsAndControlCharactersAreRejected() {
        for (String url : List.of("http://remote.example", "http://user:secret@localhost:8787",
                "http://localhost:8787/path", "http://localhost:8787?token=secret",
                "http://localhost:8787#fragment", "http://localhost:0",
                "http://user:secret@localhost:bad")) {
            IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                    () -> new HarnessClient(url, 3));
            assertFalse(error.getMessage().contains("secret"));
        }
        HarnessClient client = new HarnessClient("http://localhost:8787", 3);
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> client.setBearerToken("synthetic-secret\r\nHeader: value"));
        assertFalse(error.getMessage().contains("synthetic-secret"));
    }
}
