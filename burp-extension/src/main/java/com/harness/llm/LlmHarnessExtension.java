package com.harness.llm;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import com.harness.llm.model.AnalysisModels.AnalysisResponse;
import com.harness.llm.ui.AnalysisTracker;
import com.harness.llm.ui.AttackSurfacePanel;
import com.harness.llm.ui.AttackSurfacePanel.SiteMapRow;
import com.harness.llm.ui.HarnessPanel;
import com.harness.llm.ui.HarnessToolsPanel;
import com.harness.llm.ui.UnifiedHarnessView;

import javax.swing.*;
import java.util.List;

public class LlmHarnessExtension implements BurpExtension {

    private HarnessClient client;
    private HarnessPanel panel;
    private HarnessContextMenu.AnalysisRunner runner;
    private AnalysisTracker analysisTracker;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("LLM Harness");

        client = new HarnessClient("http://localhost:8787", 120);
        analysisTracker = new AnalysisTracker();

        panel = new HarnessPanel(() -> {
            client.setBaseUrl(panel.getBaseUrl());
            String token = panel.consumeBearerTokenInput();
            if (!token.isBlank()) client.setBearerToken(token);
            return client.connectionCheck();
        }, client::getLastHealthCheckError, analysisTracker);
        panel.setTokenClearHandler(() -> client.setBearerToken(null));

        ValidationExecutor validationExecutor = new ValidationExecutor(api, client);

        runner = new HarnessContextMenu.AnalysisRunner(
                api,
                client,
                analysisTracker,
                (label, result) -> SwingUtilities.invokeLater(() ->
                        panel.addSuccess(label, (AnalysisResponse) result)),
                (label, error) -> SwingUtilities.invokeLater(() ->
                        panel.addFailure(label, error)),
                () -> panel.getAttemptRediscovery()
        );
        runner.setAnalysisTimeoutSupplier(() -> panel.getAnalysisTimeoutSeconds());
        runner.setValidationExecutor(validationExecutor);
        panel.setPlanExecutor(plan -> validationExecutor.execute(plan, (status, detail) -> {
            api.logging().logToOutput("LLM Harness validation " + status + ": " + detail);
            SwingUtilities.invokeLater(() -> panel.showValidationResult(plan.capability, status, detail));
        }));

        AttackSurfacePanel surfacePanel = new AttackSurfacePanel(
                () -> buildSiteMapRows(api),
                handle -> {
                    if (handle instanceof HttpRequestResponse rr) {
                        runner.submit(rr, List.of());
                    }
                },
                client);

        UnifiedHarnessView unifiedView = new UnifiedHarnessView(surfacePanel, panel);
        api.userInterface().registerSuiteTab("LLM Harness", unifiedView);

        // Session-3 capabilities (model selection, discovery, active testing,
        // budget allocation, tools, confidential scan, live activity) live in
        // their own tab so they can't destabilize the analysis view above.
        // The site-map importer lets crawl/role-crawl results land in Burp's
        // native Target tab, not just the harness panel.
        HarnessToolsPanel toolsPanel = new HarnessToolsPanel(client,
                (baseUrl, paths) -> SiteMapImporter.importEndpoints(api, baseUrl, paths));
        api.userInterface().registerSuiteTab("Harness Tools", toolsPanel);
        api.userInterface().registerContextMenuItemsProvider(
                new HarnessContextMenu(api, runner));

        api.logging().logToOutput(
                "LLM Harness extension loaded. Configure the harness URL in the " +
                "'LLM Harness' tab, click Test Connection. Right-click any request " +
                "in Proxy/Repeater/Target for 'Send to LLM Harness', or use the " +
                "Attack Surface Map at the top of the tab to rank everything Burp has " +
                "seen so far before diving into individual requests -- results and " +
                "live progress appear in the panel below it.");
    }

    /**
     * Pulls everything in Burp's site map (populated by Proxy traffic,
     * Target crawling, Repeater, etc.) and reduces each entry to what the
     * local PathScorer needs, keeping the full HttpRequestResponse as an
     * opaque handle for the "send to harness" action.
     */
    private List<SiteMapRow> buildSiteMapRows(MontoyaApi api) {
        List<HttpRequestResponse> entries = api.siteMap().requestResponses();
        return entries.stream()
                .map(rr -> {
                    var req = rr.request();
                    List<String> paramNames;
                    try {
                        paramNames = req.parameters().stream()
                                .map(ParsedHttpParameter::name)
                                .toList();
                    } catch (Exception e) {
                        paramNames = List.of();
                    }
                    return new SiteMapRow(req.method(), req.url(), paramNames, rr);
                })
                .toList();
    }
}
