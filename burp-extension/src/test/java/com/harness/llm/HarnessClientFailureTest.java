package com.harness.llm;

import com.harness.llm.model.AnalysisModels.AnalysisRequest;
import com.harness.llm.model.AnalysisModels.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import static org.junit.jupiter.api.Assertions.*;

/** Owned benign loopback HTTP only; no target replay or provider calls. */
class HarnessClientFailureTest {
    static final String SECRET = "R12_SYNTHETIC_SECRET";
    static final String VALID = "{\"coordinator_model\":\"synthetic\",\"dispatched_agents\":[],\"agent_reports\":[],\"summary\":\"Ordinary passive result\"}";
    static class Fixture implements AutoCloseable {
        final HttpServer server;
        final java.util.concurrent.ExecutorService executor = Executors.newCachedThreadPool();
        final CountDownLatch entered = new CountDownLatch(1), completed = new CountDownLatch(1);
        volatile int status = 200;
        volatile String body = VALID;
        volatile long delay;
        volatile boolean disconnect;
        Fixture() throws Exception {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.setExecutor(executor);
            server.createContext("/", exchange -> {
                entered.countDown();
                try {
                    if (delay > 0) Thread.sleep(delay);
                    if (disconnect) { exchange.close(); return; }
                    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
                    exchange.sendResponseHeaders(status, bytes.length);
                    exchange.getResponseBody().write(bytes);
                } catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
                catch (java.io.IOException clientStoppedWaiting) { /* expected timeout/disconnect fixture */ }
                finally { exchange.close(); completed.countDown(); }
            });
            server.start();
        }
        HarnessClient client() {
            HarnessClient client = new HarnessClient("http://127.0.0.1:" + server.getAddress().getPort(), 2);
            client.setBearerToken("synthetic-token");
            return client;
        }
        public void close() { server.stop(0); executor.shutdownNow(); }
    }
    static AnalysisRequest request() {
        AnalysisRequest request = new AnalysisRequest();
        request.exchange = new HttpExchange();
        request.exchange.url = "https://captured.invalid/ordinary?token=" + SECRET;
        request.exchange.method = "GET";
        return request;
    }
    static void sanitized(HarnessClient.HarnessException error) {
        assertFalse(error.toString().contains(SECRET));
        assertNull(error.getCause(), "Failure stack must not attach arbitrary upstream diagnostics");
    }
    @Test void validAnalysisAndGenericReadRemainUsable() throws Exception {
        try (Fixture fixture = new Fixture()) {
            HarnessClient client = fixture.client();
            var result = client.analyze(request());
            assertEquals("Ordinary passive result", result.summary);
            assertEquals(List.of(), result.agent_reports);
            assertEquals("synthetic", client.getJson("/ordinary", Duration.ofSeconds(2)).get("coordinator_model").getAsString());
        }
    }
    @Test void degradedHealthReportsModelUnavailableWithoutUpstreamDetails() throws Exception {
        try (Fixture fixture = new Fixture()) {
            fixture.body = "{\"status\":\"degraded\",\"ollama\":{\"error\":\"" + SECRET + "\"}}";
            HarnessClient client = fixture.client();
            assertFalse(client.healthCheck());
            assertTrue(client.getLastHealthCheckError().contains("model inference is unavailable"));
            assertFalse(client.getLastHealthCheckError().contains("malformed"));
            assertFalse(client.getLastHealthCheckError().contains(SECRET));
            fixture.body = "{\"status\":\"ok\"}";
            assertTrue(client.healthCheck());
            assertNull(client.getLastHealthCheckError());
        }
    }
    @Test void emptyMalformedAndIncompleteAnalysisNeverBecomeCleanResults() throws Exception {
        for (String body : List.of("{}", "null", "[]", "{\"secret\":\""+SECRET+"\"}",
                VALID.replace("\"agent_reports\":[]", "\"agent_reports\":null"),
                VALID.replace("[]", "[null]"), "{bad:"+SECRET+"}", VALID + SECRET)) {
            try (Fixture fixture = new Fixture()) {
                fixture.body = body;
                HarnessClient.HarnessException error = assertThrows(HarnessClient.HarnessException.class,
                        () -> fixture.client().analyze(request()), body);
                assertEquals("malformed", error.getFailureKind());
                sanitized(error);
            }
        }
    }
    @Test void authThrottleAndServerFailuresWithholdBodyAndCapturedQuery() throws Exception {
        for (int status : List.of(401, 429, 500)) {
            try (Fixture fixture = new Fixture()) {
                fixture.status = status;
                fixture.body = "{\"error\":\"token=" + SECRET + "\",\"confirmed\":true}";
                HarnessClient client = fixture.client();
                for (HarnessClient.HarnessException error : List.of(
                        assertThrows(HarnessClient.HarnessException.class, () -> client.analyze(request())),
                        assertThrows(HarnessClient.HarnessException.class, () -> client.getJson("/read?token="+SECRET, Duration.ofSeconds(2))))) {
                    assertEquals(status == 401 ? "authentication" : status == 429 ? "throttled" : "server_error", error.getFailureKind());
                    sanitized(error);
                    assertTrue(error.getMessage().contains("HTTP " + status));
                }
                assertFalse(client.healthCheck());
                assertFalse(client.getLastHealthCheckError().contains(SECRET));
            }
        }
    }
    @Test void genericParseAndInvalidRequestMetadataWithholdSensitivePath() throws Exception {
        try (Fixture fixture = new Fixture()) {
            fixture.body = "{bad:"+SECRET+"}";
            HarnessClient client = fixture.client();
            var error = assertThrows(HarnessClient.HarnessException.class,
                    () -> client.getJson("/read?token="+SECRET, Duration.ofSeconds(2)));
            sanitized(error);
            assertEquals("malformed", error.getFailureKind());
            var metadata = assertThrows(IllegalArgumentException.class,
                    () -> client.getJson("/read?token="+SECRET+"\n", Duration.ofSeconds(2)));
            assertFalse(metadata.getMessage().contains(SECRET));
            assertFalse(client.healthCheck());
            assertFalse(client.getLastHealthCheckError().contains(SECRET));
        }
    }
    @Test void legacyTypedEndpointsShareSanitizedFailureDiagnostics() throws Exception {
        try (Fixture fixture = new Fixture()) {
            HarnessClient client = fixture.client();
            fixture.status = 500;
            fixture.body = "{\"error\":\""+SECRET+"\"}";
            var status = assertThrows(HarnessClient.HarnessException.class, () -> client.sessionsForHost(SECRET));
            sanitized(status);
            assertEquals("server_error", status.getFailureKind());
            fixture.status = 200;
            fixture.body = "{bad:"+SECRET+"}";
            var parse = assertThrows(HarnessClient.HarnessException.class, client::effortStatus);
            sanitized(parse);
            assertEquals("malformed", parse.getFailureKind());
        }
    }
    @Test void disconnectIsNotACompletedAnalysisOrNegativeFinding() throws Exception {
        try (Fixture fixture = new Fixture()) {
            fixture.disconnect = true;
            var error = assertThrows(HarnessClient.HarnessException.class, () -> fixture.client().analyze(request()));
            sanitized(error);
            assertEquals("disconnected", error.getFailureKind());
            assertTrue(error.getMessage().contains("completion is unknown"));
        }
    }
    @Test void timeoutStopsOnlyClientWaitAndServerCanStillComplete() throws Exception {
        try (Fixture fixture = new Fixture()) {
            fixture.delay = 1800;
            HarnessClient client = fixture.client();
            client.setAnalysisTimeoutSeconds(1);
            var error = assertThrows(HarnessClient.HarnessException.class, () -> client.analyze(request()));
            sanitized(error);
            assertEquals("timeout", error.getFailureKind());
            assertTrue(error.getMessage().contains("completion and cancellation are unknown"));
            assertEquals(1, fixture.completed.getCount(), "timeout does not establish server completion");
            assertTrue(fixture.completed.await(4, TimeUnit.SECONDS), "owned server may continue after client timeout");
        }
    }
    @Test void interruptionPreservesThreadFlagAndUnknownServerOutcome() throws Exception {
        try (Fixture fixture = new Fixture()) {
            fixture.delay = 1800;
            AtomicReference<HarnessClient.HarnessException> failure = new AtomicReference<>();
            AtomicReference<Boolean> interrupted = new AtomicReference<>();
            HarnessClient client = fixture.client();
            Thread worker = new Thread(() -> {
                try { client.analyze(request()); }
                catch (HarnessClient.HarnessException error) { failure.set(error); interrupted.set(Thread.currentThread().isInterrupted()); }
            });
            worker.start();
            assertTrue(fixture.entered.await(3, TimeUnit.SECONDS));
            worker.interrupt();
            worker.join(3000);
            assertFalse(worker.isAlive());
            assertNotNull(failure.get());
            sanitized(failure.get());
            assertEquals("interrupted", failure.get().getFailureKind());
            assertEquals(Boolean.TRUE, interrupted.get());
            assertTrue(failure.get().getMessage().contains("completion and cancellation are unknown"));
        }
    }
}
