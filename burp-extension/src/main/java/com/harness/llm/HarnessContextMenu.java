package com.harness.llm;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Adds "Send to LLM Harness" / "Send to LLM Harness (choose agents)" to
 * Burp's right-click menu wherever a request/response is selected
 * (Proxy history, Repeater, Target site map, etc).
 */
public class HarnessContextMenu implements ContextMenuItemsProvider {

    // Fallback only -- the picker fetches the live list from /health first.
    private static final String[] ALL_AGENTS = {
        "ai_llm","ai_security","anomaly","api_security","auth","business_logic",
        "business_logic_enhanced","command_injection","cors","crypto","csp","csrf",
        "deserialization","file_upload","graphql","header_injection","http_request_smuggling",
        "idor","info_disclosure","jwt","misconfig","nosql","oauth","open_redirect",
        "race_condition","rate_limit","recon","sqli","ssrf","ssti","subdomain_takeover",
        "supply_chain","web_cache_poisoning","websocket","xss","xxe"
    };

    private final MontoyaApi api;
    private final AnalysisRunner runner;

    public HarnessContextMenu(MontoyaApi api, AnalysisRunner runner) {
        this.api = api;
        this.runner = runner;
    }

    /** Multi-select agent picker. The agent list is fetched live from the
     * harness's /health OFF the UI thread (in a SwingWorker) so a slow or
     * unreachable harness never freezes Burp; falls back to the built-in
     * ALL_AGENTS list if the fetch returns nothing. The dialog is built and
     * shown in done() (which runs on the event thread), and the analyst's
     * choice is delivered to `onChosen` (null if they cancel). */
    private void promptForAgents(java.util.function.Consumer<java.util.List<String>> onChosen) {
        new SwingWorker<java.util.List<String>, Void>() {
            @Override
            protected java.util.List<String> doInBackground() {
                java.util.List<String> agents = runner.availableAgents();
                if (agents == null || agents.isEmpty()) {
                    return java.util.Arrays.asList(ALL_AGENTS);
                }
                return agents;
            }

            @Override
            protected void done() {
                java.util.List<String> agents;
                try {
                    agents = get();
                } catch (Exception ex) {
                    agents = java.util.Arrays.asList(ALL_AGENTS);
                }
                JPanel panel = new JPanel(new GridLayout(0, 3, 8, 2));
                java.util.List<JCheckBox> boxes = new ArrayList<>();
                for (String a : agents) {
                    JCheckBox cb = new JCheckBox(a);
                    boxes.add(cb);
                    panel.add(cb);
                }
                JScrollPane scroll = new JScrollPane(panel);
                scroll.setPreferredSize(new Dimension(520, 320));
                int res = JOptionPane.showConfirmDialog(null, scroll,
                        "Choose agents to dispatch", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
                if (res != JOptionPane.OK_OPTION) {
                    onChosen.accept(null);
                    return;
                }
                java.util.List<String> chosen = new ArrayList<>();
                for (JCheckBox cb : boxes) if (cb.isSelected()) chosen.add(cb.getText());
                onChosen.accept(chosen);
            }
        }.execute();
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<HttpRequestResponse> selected = new ArrayList<>(event.selectedRequestResponses());
        // When the user right-clicks INSIDE a message editor (Repeater,
        // Intercept, or a single-item viewer), selectedRequestResponses() is
        // empty and the request lives in messageEditorRequestResponse()
        // instead. Without this the menu silently disappears in exactly those
        // panes -- the "works sometimes, not others" bug.
        event.messageEditorRequestResponse()
             .map(m -> m.requestResponse())
             .ifPresent(selected::add);
        if (selected.isEmpty()) {
            return List.of();
        }

        List<Component> items = new ArrayList<>();

        JMenuItem sendAll = new JMenuItem("Send to LLM Harness (auto-select agents)");
        sendAll.addActionListener(e -> selected.forEach(rr -> runner.submit(rr, List.of())));
        items.add(sendAll);

        JMenuItem chooseItem = new JMenuItem("Send to LLM Harness (choose agents)...");
        chooseItem.addActionListener(e -> promptForAgents(chosen -> {
            if (chosen != null && !chosen.isEmpty()) {
                selected.forEach(rr -> runner.submit(rr, chosen));
            }
        }));
        items.add(chooseItem);

        // Only offered for a single selected request -- registering a
        // session links ONE specific captured exchange to ONE identity;
        // doing this for a multi-selection would either silently link
        // every selected request to the same identity (wrong more often
        // than right) or require per-request pickers (a poor UX for a
        // right-click menu). An analyst wanting to register several
        // exchanges does it one at a time, same as Burp's own
        // "add to scope" style single-target actions.
        if (selected.size() == 1) {
            JMenuItem registerIdentity = new JMenuItem("Register as identity session...");
            registerIdentity.addActionListener(e -> runner.registerSession(selected.get(0)));
            items.add(registerIdentity);
        }

        return items;
    }

    /**
     * Converts a Burp HttpRequestResponse into the plain HTTP exchange the
     * harness expects, submits it in the background, and routes the
     * result back to the UI. Kept separate from the menu provider so the
     * extension's main class can reuse it (e.g. for a future "auto-send
     * everything through Proxy" toggle) without duplicating this logic.
     */
    public static class AnalysisRunner {
        private final MontoyaApi api;
        private final HarnessClient client;
        private final com.harness.llm.ui.AnalysisTracker analysisTracker;
        private final java.util.function.BiConsumer<String, Object> onSuccess;
        private final java.util.function.BiConsumer<String, String> onFailure;
        private final java.util.function.BooleanSupplier attemptRediscoverySupplier;
        private java.util.function.IntSupplier analysisTimeoutSupplier = () -> 600;
        private ValidationExecutor validationExecutor;

        public AnalysisRunner(MontoyaApi api, HarnessClient client,
                               com.harness.llm.ui.AnalysisTracker analysisTracker,
                               java.util.function.BiConsumer<String, Object> onSuccess,
                               java.util.function.BiConsumer<String, String> onFailure,
                               java.util.function.BooleanSupplier attemptRediscoverySupplier) {
            this.api = api;
            this.client = client;
            this.analysisTracker = analysisTracker;
            this.onSuccess = onSuccess;
            this.onFailure = onFailure;
            this.attemptRediscoverySupplier = attemptRediscoverySupplier;
        }

        /** Read fresh from the panel's timeout field on every call, the
         * same way baseUrl is re-read on every Test Connection click --
         * so editing the field takes effect on the next send without
         * needing to reconstruct anything. Defaults to 600s if never set. */
        public void setAnalysisTimeoutSupplier(java.util.function.IntSupplier analysisTimeoutSupplier) {
            this.analysisTimeoutSupplier = analysisTimeoutSupplier;
        }

        public void setValidationExecutor(ValidationExecutor executor) {
            this.validationExecutor = executor;
        }

        public java.util.List<String> availableAgents() {
            return client.listAgentNames();
        }

        /**
         * Links `rr` to an analyst-selected identity via POST /sessions,
         * so ValidationExecutor.identityCompare()'s picker can show that
         * identity's name instead of a bare fingerprint the next time
         * this exchange (or one matching its fingerprint) shows up as a
         * candidate. This is the write side of the feature --
         * IdentityLabelResolver only has something to resolve if a
         * session was registered here first.
         *
         * Deliberately does NOT offer to create a new identity inline --
         * that's a separate, not-yet-built piece of UI. If no identities
         * exist yet, this tells the analyst to create one via the
         * harness's POST /identities endpoint (curl or equivalent) first,
         * rather than half-building a second dialog flow for that here.
         */
        public void registerSession(HttpRequestResponse rr) {
            new SwingWorker<List<com.harness.llm.model.AnalysisModels.IdentityInfo>, Void>() {
                String error;

                @Override
                protected List<com.harness.llm.model.AnalysisModels.IdentityInfo> doInBackground() {
                    try {
                        return client.listIdentities();
                    } catch (HarnessClient.HarnessException e) {
                        error = e.getMessage();
                        return null;
                    }
                }

                @Override
                protected void done() {
                    List<com.harness.llm.model.AnalysisModels.IdentityInfo> identities;
                    try {
                        identities = get();
                    } catch (Exception e) {
                        identities = null;
                    }
                    if (identities == null) {
                        JOptionPane.showMessageDialog(null,
                                "Could not fetch identities from the harness" + (error != null ? " (" + error + ")" : "") + ".\n"
                                        + "Is `python server.py` running?",
                                "Register identity session", JOptionPane.ERROR_MESSAGE);
                        return;
                    }
                    if (identities.isEmpty()) {
                        JOptionPane.showMessageDialog(null,
                                "No identities are registered yet. Create one first via POST /identities "
                                        + "(e.g. curl -X POST " + "http://.../identities -d '{\"name\":\"Alice\",\"role\":\"user\"}'), "
                                        + "then try this again.",
                                "Register identity session", JOptionPane.INFORMATION_MESSAGE);
                        return;
                    }

                    String[] labels = new String[identities.size()];
                    for (int i = 0; i < identities.size(); i++) {
                        var id = identities.get(i);
                        labels[i] = id.name + " (" + id.role + ")" + (id.notes != null && !id.notes.isBlank() ? " -- " + id.notes : "");
                    }
                    int selected = JOptionPane.showOptionDialog(null,
                            "Which identity does this captured request belong to?\n\n" + rr.request().method() + " " + rr.request().url(),
                            "Register identity session", JOptionPane.DEFAULT_OPTION, JOptionPane.PLAIN_MESSAGE, null, labels, labels[0]);
                    if (selected < 0) return;

                    var chosen = identities.get(selected);
                    String label = JOptionPane.showInputDialog(null,
                            "Optional label for this session (e.g. \"logged in via /login\"):", "");
                    String finalLabel = label == null ? "" : label;
                    String host = ValidationExecutor.netloc(rr.request().url());
                    String exchangeHash = ValidationExecutor.exchangeFingerprint(rr);

                    new SwingWorker<Object, Void>() {
                        String submitError;

                        @Override
                        protected Object doInBackground() {
                            try {
                                return client.createSession(chosen.id, host, exchangeHash, finalLabel);
                            } catch (HarnessClient.HarnessException e) {
                                submitError = e.getMessage();
                                return null;
                            }
                        }

                        @Override
                        protected void done() {
                            Object result;
                            try {
                                result = get();
                            } catch (Exception e) {
                                result = null;
                            }
                            if (result == null) {
                                api.logging().logToError("Failed to register identity session: " + submitError);
                                JOptionPane.showMessageDialog(null,
                                        "Failed to register session" + (submitError != null ? ": " + submitError : "") + ".",
                                        "Register identity session", JOptionPane.ERROR_MESSAGE);
                            } else {
                                api.logging().logToOutput("Registered session for " + chosen.name + " on " + host);
                            }
                        }
                    }.execute();
                }
            }.execute();
        }

        public void submit(HttpRequestResponse rr, List<String> forceAgents) {
            if (validationExecutor != null) validationExecutor.registerExchange(rr);
            HttpRequest req = rr.request();
            HttpResponse resp = rr.response();
            String label = req.method() + " " + req.url();
            String requestId = java.util.UUID.randomUUID().toString();

            var exchange = new com.harness.llm.model.AnalysisModels.HttpExchange();
            exchange.url = req.url();
            exchange.method = req.method();
            exchange.request_headers = headersToMap(req.headers());
            exchange.request_body = req.bodyToString();
            exchange.response_status = resp != null ? (int) resp.statusCode() : null;
            exchange.response_headers = resp != null ? headersToMap(resp.headers()) : new HashMap<>();
            exchange.response_body = responseBodyForAnalysis(resp);
            exchange.analyst_note = "";

            var analysisReq = new com.harness.llm.model.AnalysisModels.AnalysisRequest();
            analysisReq.exchange = exchange;
            analysisReq.force_agents = forceAgents;
            analysisReq.attempt_rediscovery = attemptRediscoverySupplier.getAsBoolean();

            // Agent count is a display estimate only: force_agents.size() when the
            // caller picked specific agents, otherwise 1 (auto-select), since the
            // harness doesn't report how many agents it dispatched until the
            // single blocking /analyze call returns. There's no per-agent progress
            // signal from the server today, so this tracker can only show
            // queued/analyzing/done -- not live per-agent ticks.
            if (analysisTracker != null) {
                analysisTracker.startAnalysis(label, requestId, Math.max(1, forceAgents.size()));
            }

            // Network call off the Swing/Burp event thread.
            new SwingWorker<Object, Void>() {
                String error;

                @Override
                protected Object doInBackground() {
                    if (analysisTracker != null) {
                        analysisTracker.updateStatus(requestId, com.harness.llm.ui.AnalysisStatus.Status.ANALYZING);
                    }
                    try {
                        client.setAnalysisTimeoutSeconds(analysisTimeoutSupplier.getAsInt());
                        return client.analyze(analysisReq);
                    } catch (HarnessClient.HarnessException e) {
                        error = e.getMessage();
                        api.logging().logToError("LLM Harness analysis failed for " + label + ": " + error);
                        return null;
                    }
                }

                @Override
                protected void done() {
                    try {
                        Object result = get();
                        if (result != null) {
                            var analysis = (com.harness.llm.model.AnalysisModels.AnalysisResponse) result;
                            if (validationExecutor != null && analysis.test_plans != null) {
                                validationExecutor.registerSources(rr, analysis.test_plans);
                            }
                            if (analysisTracker != null) {
                                int findingCount = 0;
                                if (analysis.agent_reports != null) {
                                    for (var ar : analysis.agent_reports) {
                                        if (ar.findings != null) findingCount += ar.findings.size();
                                    }
                                }
                                for (int i = 0; i < findingCount; i++) analysisTracker.addFinding(requestId);
                                // X08: a degraded/partial result is not shown as a clean completion.
                                analysisTracker.updateStatus(requestId,
                                        com.harness.llm.ui.AnalysisStatus.completionStatus(analysis));
                            }
                            onSuccess.accept(label, result);
                        } else {
                            if (analysisTracker != null) {
                                analysisTracker.setError(requestId, error != null ? error : "Unknown error");
                            }
                            onFailure.accept(label, error != null ? error : "Unknown error");
                        }
                    } catch (Exception e) {
                        if (analysisTracker != null) {
                            analysisTracker.setError(requestId, e.getMessage());
                        }
                        onFailure.accept(label, e.getMessage());
                    }
                }
            }.execute();
        }

        private static Map<String, String> headersToMap(List<HttpHeader> headers) {
            Map<String, String> map = new java.util.LinkedHashMap<>();
            if (headers == null) return map;
            for (HttpHeader h : headers) {
                // The wire model is a string map, so preserve duplicate values by
                // joining them rather than silently dropping security-relevant
                // headers such as multiple Set-Cookie fields.
                map.merge(h.name(), h.value(), (oldValue, newValue) -> oldValue + "\n" + newValue);
            }
            return map;
        }

        private static String responseBodyForAnalysis(HttpResponse resp) {
            if (resp == null) return "";
            String contentType = resp.headers().stream()
                    .filter(h -> "Content-Type".equalsIgnoreCase(h.name()))
                    .map(HttpHeader::value)
                    .findFirst()
                    .orElse("")
                    .toLowerCase(java.util.Locale.ROOT);
            if (!contentType.isEmpty() && !isTextContentType(contentType)) {
                return "[non-text response body omitted: " + contentType + "]";
            }
            return resp.bodyToString();
        }

        private static boolean isTextContentType(String contentType) {
            return contentType.startsWith("text/")
                    || contentType.contains("json")
                    || contentType.contains("xml")
                    || contentType.contains("javascript")
                    || contentType.contains("ecmascript")
                    || contentType.contains("x-www-form-urlencoded")
                    || contentType.contains("graphql");
        }
    }
}
