package com.harness.llm;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.harness.llm.model.AnalysisModels.AnalysisRequest;
import com.harness.llm.model.AnalysisModels.AnalysisResponse;
import com.harness.llm.model.AnalysisModels.HttpExchange;
import com.harness.llm.ui.HarnessPanel;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;

import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import java.net.InetSocketAddress;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/** Real Java HTTP caller against an owned benign API spy, never a target/provider. */
class HarnessClientEngagementTest {
    private static final String GENERATED = "synthetic-returned-engagement";
    private static final String PRINCIPAL = "opaque-synthetic-principal";

    private static class Fixture implements AutoCloseable {
        final HttpServer server;
        final AtomicReference<JsonObject> request = new AtomicReference<>();
        final AtomicReference<String> reportQuery = new AtomicReference<>();
        final AtomicReference<String> engagement = new AtomicReference<>();
        final AtomicInteger analyses = new AtomicInteger();

        Fixture() throws Exception {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", exchange -> {
                int status = 200;
                String body;
                if (!"Bearer synthetic-token".equals(exchange.getRequestHeaders().getFirst("Authorization"))) {
                    status = 401;
                    body = "{}";
                } else if (exchange.getRequestURI().getPath().equals("/analyze")) {
                    JsonObject captured = JsonParser.parseString(new String(
                            exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)).getAsJsonObject();
                    request.set(captured);
                    engagement.set(captured.has("engagement_id")
                            ? captured.get("engagement_id").getAsString() : GENERATED);
                    analyses.incrementAndGet();
                    body = "{\"coordinator_model\":\"synthetic\",\"dispatched_agents\":[],\"agent_reports\":[],"
                            + "\"summary\":\"Ordinary passive observation\",\"engagement_id\":\"" + engagement.get()
                            + "\",\"captured_principal_id\":\"" + PRINCIPAL + "\"}";
                } else if (exchange.getRequestURI().getPath().equals("/report/sarif")) {
                    reportQuery.set(exchange.getRequestURI().getRawQuery());
                    String expected = "url=https%3A%2F%2Fcaptured.example&engagement_id="
                            + URLEncoder.encode(engagement.get(), StandardCharsets.UTF_8);
                    body = "{\"runs\":[{\"results\":" + (expected.equals(reportQuery.get())
                            ? "[{\"message\":{\"text\":\"Ordinary captured observation\"}}]" : "[]") + "}]}";
                } else {
                    status = 404;
                    body = "{}";
                }
                byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(status, bytes.length);
                exchange.getResponseBody().write(bytes);
                exchange.close();
            });
            server.start();
        }

        String url() { return "http://127.0.0.1:" + server.getAddress().getPort(); }
        public void close() { server.stop(0); }
    }

    private AnalysisRequest capturedRequest(String engagement) {
        HttpExchange exchange = new HttpExchange();
        exchange.url = "https://captured.example/ordinary";
        exchange.method = "GET";
        exchange.request_headers = Map.of();
        exchange.response_body = "Ordinary captured metadata";
        AnalysisRequest request = new AnalysisRequest();
        request.exchange = exchange;
        request.engagement_id = engagement;
        return request;
    }

    private int report(HarnessClient client, String engagement) throws Exception {
        return client.getJson("/report/sarif?url=https%3A%2F%2Fcaptured.example&engagement_id="
                + URLEncoder.encode(engagement, StandardCharsets.UTF_8), Duration.ofSeconds(3))
                .getAsJsonArray("runs").get(0).getAsJsonObject().getAsJsonArray("results").size();
    }

    @Test void returnedPartitionSurvivesAnalyzeAndSelectsExplicitReportWithoutResubmission() throws Exception {
        try (Fixture fixture = new Fixture()) {
            HarnessClient client = new HarnessClient(fixture.url(), 3);
            client.setBearerToken("synthetic-token");
            AnalysisResponse result = client.analyze(capturedRequest(null));
            assertFalse(fixture.request.get().has("engagement_id"), "Optional input remains absent by default");
            assertEquals(GENERATED, result.engagement_id);
            assertEquals(PRINCIPAL, result.captured_principal_id);
            assertEquals(1, report(client, result.engagement_id));
            assertEquals(0, report(client, "different-engagement"), "Wrong partition must not recover this observation");
            assertEquals(1, fixture.analyses.get(), "Report polling never resubmits analysis");
        }
    }

    @Test void suppliedPartitionIsSentAndReturned() throws Exception {
        try (Fixture fixture = new Fixture()) {
            HarnessClient client = new HarnessClient(fixture.url(), 3);
            client.setBearerToken("synthetic-token");
            AnalysisResponse result = client.analyze(capturedRequest("synthetic-shared-engagement"));
            assertEquals("synthetic-shared-engagement", fixture.request.get().get("engagement_id").getAsString());
            assertEquals("synthetic-shared-engagement", result.engagement_id);
            assertEquals(1, report(client, result.engagement_id));
            assertEquals(1, fixture.analyses.get());
        }
    }

    @Test void panelShowsSelectableReturnedIdAndHonestLegacyAbsence() throws Exception {
        AnalysisResponse response = new AnalysisResponse();
        response.engagement_id = GENERATED;
        response.captured_principal_id = PRINCIPAL;
        response.dispatched_agents = List.of();
        response.agent_reports = List.of();
        SwingUtilities.invokeAndWait(() -> {
            try {
                HarnessPanel panel = new HarnessPanel(() -> false, () -> null, null);
                var method = HarnessPanel.class.getDeclaredMethod("showDetail", HarnessPanel.ResultEntry.class);
                method.setAccessible(true);
                var field = HarnessPanel.class.getDeclaredField("detailArea");
                field.setAccessible(true);
                method.invoke(panel, new HarnessPanel.ResultEntry("ordinary capture", response, null));
                JTextArea area = (JTextArea) field.get(panel);
                assertTrue(area.getText().contains("Engagement ID: " + GENERATED));
                assertTrue(area.getText().contains("Captured principal ID: " + PRINCIPAL));
                int start = area.getText().indexOf(GENERATED);
                area.select(start, start + GENERATED.length());
                assertEquals(GENERATED, area.getSelectedText(), "Returned report ID is copyable text");
                response.engagement_id = null;
                response.captured_principal_id = null;
                method.invoke(panel, new HarnessPanel.ResultEntry("older response", response, null));
                assertTrue(area.getText().contains("Engagement ID: unavailable (older server)"));
            } catch (ReflectiveOperationException error) { throw new RuntimeException(error); }
        });
    }
}
