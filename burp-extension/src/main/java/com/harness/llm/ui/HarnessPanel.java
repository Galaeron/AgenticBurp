package com.harness.llm.ui;

import com.harness.llm.HarnessClient;
import com.harness.llm.model.AnalysisModels.AgentReport;
import com.harness.llm.model.AnalysisModels.AnalysisResponse;
import com.harness.llm.model.AnalysisModels.Finding;
import com.harness.llm.model.AnalysisModels.TestPlan;

import javax.swing.*;
import java.awt.*;
import java.util.List;
import java.util.function.Supplier;
import java.util.function.Consumer;

/**
 * The "LLM Harness" suite tab. Purely presentational: LlmHarnessExtension
 * owns the HarnessClient and pushes results in via addResult(). This class
 * doesn't make network calls itself, so it stays testable/reusable outside
 * a live Burp instance if needed.
 */
public class HarnessPanel extends JPanel {

    public record ResultEntry(String label, AnalysisResponse response, String error) {}

    private final DefaultListModel<ResultEntry> listModel = new DefaultListModel<>();
    private final JList<ResultEntry> resultList = new JList<>(listModel);
    private final JTextArea detailArea = new JTextArea();
    private final JTextField baseUrlField = new JTextField("http://localhost:8787", 24);
    private final JTextField analysisTimeoutField = new JTextField("600", 5);
    private final JTextArea validationResultArea = new JTextArea();
    private final JLabel statusLabel = new JLabel("Not connected");
    private final JCheckBox rediscoveryCheckbox = new JCheckBox("Attempt rediscovery of known vulnerabilities");
    private Consumer<TestPlan> planExecutor = plan -> {};
    private Supplier<String> lastConnectionError = () -> null;

    private final AnalysisTracker analysisTracker;
    private JButton executePlan;
    /** Findings below this confidence still show in the detail view but do NOT
     * drive the list's headline count or severity badge -- they are
     * low-confidence hypotheses, not confident findings. */
    private static final double MIN_REPORT_CONFIDENCE = 0.5;

    public HarnessPanel(Supplier<Boolean> onTestConnection, Supplier<String> lastConnectionError,
                         AnalysisTracker analysisTracker) {
        this.analysisTracker = analysisTracker;
        this.lastConnectionError = lastConnectionError;
        setLayout(new BorderLayout());

        // --- top bar: connection config ---
        JPanel topBar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        topBar.add(new JLabel("Harness URL:"));
        topBar.add(baseUrlField);
        topBar.add(new JLabel("Analysis timeout (s):"));
        analysisTimeoutField.setToolTipText("How long to wait for a single \"send to LLM Harness\" call to "
                + "finish before giving up client-side. A dispatch involving several agents at limited "
                + "concurrency (see config.yaml's concurrency.max_parallel_agents), each making a real LLM "
                + "call, can genuinely take a while -- this does not need to be short, and a timeout here "
                + "does not necessarily mean the harness failed; it may still be working server-side.");
        topBar.add(analysisTimeoutField);
        JButton testBtn = new JButton("Test Connection");
        testBtn.addActionListener(e -> {
            boolean ok = onTestConnection.get();
            statusLabel.setText(ok ? "Connected" : "Unreachable");
            statusLabel.setForeground(ok ? new Color(0, 128, 0) : Color.RED);
            String reason = lastConnectionError.get();
            statusLabel.setToolTipText(ok || reason == null ? null : reason);
        });
        topBar.add(testBtn);
        topBar.add(statusLabel);
        JButton saveReportBtn = new JButton("Save Report");
        saveReportBtn.addActionListener(e -> saveReport());
        topBar.add(saveReportBtn);
        rediscoveryCheckbox.setToolTipText("When a known vulnerability is confirmed via the GitHub "
                + "Advisory Database, also spend an extra model call trying to independently corroborate "
                + "it against this specific exchange. Off by default -- a confirmed match doesn't need "
                + "re-deriving.");
        topBar.add(rediscoveryCheckbox);

        // BorderLayout only takes one component per region, so the connection
        // bar and the progress panel share NORTH inside their own container.
        JPanel northContainer = new JPanel(new BorderLayout());
        northContainer.add(topBar, BorderLayout.NORTH);
        if (analysisTracker != null) {
            northContainer.add(new ProgressPanel(analysisTracker), BorderLayout.SOUTH);
        }
        add(northContainer, BorderLayout.NORTH);

        // --- main split: exchange list | detail view ---
        resultList.setCellRenderer(new ResultCellRenderer());
        resultList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                ResultEntry sel = resultList.getSelectedValue();
                showDetail(sel);
                if (executePlan != null) executePlan.setEnabled(hasRunnablePlan(sel));
            }
        });
        JScrollPane listScroll = new JScrollPane(resultList);
        listScroll.setPreferredSize(new Dimension(320, 400));

        detailArea.setEditable(false);
        detailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane detailScroll = new JScrollPane(detailArea);

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, listScroll, detailScroll);
        split.setDividerLocation(320);
        add(split, BorderLayout.CENTER);

        // Proposed validation plans are intentionally analyst-triggered.
        // The button never appears as "confirm" because a plan is not evidence.
        JPanel planBar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        executePlan = new JButton("Execute selected test plan");
        executePlan.setEnabled(false);
        executePlan.setToolTipText("Runs only an approved, declarative validation plan; the LLM cannot supply an arbitrary command or URL. This never calls the LLM/GPU -- it sends real HTTP requests via Burp's own client and checks the response deterministically.");
        executePlan.addActionListener(e -> {
            ResultEntry entry = resultList.getSelectedValue();
            if (entry == null || entry.response() == null || entry.response().test_plans == null || entry.response().test_plans.isEmpty()) {
                JOptionPane.showMessageDialog(this, "Select an analysis result containing a proposed test plan.");
                return;
            }
            TestPlan selected = choosePlan(entry.response().test_plans);
            if (selected != null) {
                int answer = JOptionPane.showConfirmDialog(this,
                        "Execute capability '" + selected.capability + "' against the captured request?\n\n"
                                + "This may generate active traffic. The plan does not grant the LLM arbitrary request or shell access.",
                        "Approve Security Test", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
                if (answer == JOptionPane.YES_OPTION) {
                    validationResultArea.append("[" + java.time.LocalTime.now().withNano(0) + "] Running '" + selected.capability + "' ...\n");
                    planExecutor.accept(selected);
                }
            }
        });
        planBar.add(executePlan);

        JPanel planSection = new JPanel(new BorderLayout());
        planSection.add(planBar, BorderLayout.NORTH);
        validationResultArea.setEditable(false);
        validationResultArea.setLineWrap(true);
        validationResultArea.setWrapStyleWord(true);
        validationResultArea.setRows(8);
        validationResultArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        validationResultArea.setBorder(BorderFactory.createTitledBorder("Test plan execution results (newest last)"));
        planSection.add(new JScrollPane(validationResultArea), BorderLayout.CENTER);
        add(planSection, BorderLayout.SOUTH);
    }

    /**
     * Shows the outcome of the most recent "Execute selected test plan"
     * run directly in this tab. Previously this only reached
     * api.logging().logToOutput() -- Burp's separate extension Output
     * log, with no visible connection to the button the analyst just
     * clicked, and no way to see a past result without going and
     * finding that log tab. Call from the EDT (or wrap in
     * SwingUtilities.invokeLater from a background callback).
     */
    public void showValidationResult(String capability, String status, String detail) {
        validationResultArea.append("[" + java.time.LocalTime.now().withNano(0) + "] ["
                + capability + "] " + status + ": " + detail + "\n");
        validationResultArea.setCaretPosition(validationResultArea.getDocument().getLength());
    }

    public void setPlanExecutor(Consumer<TestPlan> executor) {
        this.planExecutor = executor == null ? plan -> {} : executor;
    }

    /** True iff this plan can actually be run from the Execute button
     * (burp execution plane AND a real typed executor exists for it). */
    private static boolean runnableHere(TestPlan p) {
        return "burp".equalsIgnoreCase(p.execution_plane)
                && IMPLEMENTED_BURP_CAPABILITIES.contains(p.capability);
    }

    private static boolean hasRunnablePlan(ResultEntry entry) {
        if (entry == null || entry.response() == null || entry.response().test_plans == null) return false;
        for (TestPlan p : entry.response().test_plans) if (runnableHere(p)) return true;
        return false;
    }

    private TestPlan choosePlan(List<TestPlan> plans) {
        // Runnable-here plans first, so the analyst isn't led to click a plan
        // that can only ever report inconclusive.
        java.util.List<TestPlan> ordered = new java.util.ArrayList<>(plans);
        ordered.sort((a, b) -> Boolean.compare(runnableHere(b), runnableHere(a)));
        String[] labels = ordered.stream().map(p -> {
            String suffix;
            if ("burp".equalsIgnoreCase(p.execution_plane)) {
                suffix = IMPLEMENTED_BURP_CAPABILITIES.contains(p.capability) ? "" : " (not yet implemented)";
            } else {
                suffix = " (runs via the harness's active validators, not this button)";
            }
            return p.capability + " [" + p.execution_plane + "]" + suffix;
        }).toArray(String[]::new);
        int idx = JOptionPane.showOptionDialog(this, "Choose a proposed validation:", "Validation plan",
                JOptionPane.DEFAULT_OPTION, JOptionPane.PLAIN_MESSAGE, null, labels, labels[0]);
        return idx >= 0 ? ordered.get(idx) : null;
    }

    /**
     * Capabilities ValidationExecutor.java actually has a typed
     * executor for. Must be kept in sync with that file's switch
     * statement by hand -- there is no shared source of truth between
     * the two. Originally found live: planner.py (harness side)
     * declares 30 "burp"-plane capabilities as approvable/executable,
     * but only 8 had a real Java implementation. 5 more (jwt_validation,
     * csrf's sibling categories aside, csp_clickjacking_validation,
     * info_disclosure_scan, cors_misconfiguration_detection,
     * open_redirect_validation) were added afterward -- see
     * ValidationExecutor.java's switch statement for the full current
     * set and HANDOVER.md for what's still not implemented. Anything
     * NOT in this set falls to ValidationExecutor's default case and
     * reports "No typed executor exists for capability '...'." This
     * set exists so the analyst sees that BEFORE spending an approval
     * click on a plan that can only ever report inconclusive, not
     * after.
     */
    private static final java.util.Set<String> IMPLEMENTED_BURP_CAPABILITIES = java.util.Set.of(
            "reflection_context_validation", "bounded_rate_limit_probe", "workflow_replay_compare",
            "authorization_boundary_compare", "cross_identity_compare", "controlled_callback_probe",
            "session_fixation_compare", "logout_invalidation_compare",
            "csp_clickjacking_validation", "info_disclosure_scan", "cors_misconfiguration_detection",
            "open_redirect_validation", "jwt_validation", "xxe_validation", "csrf_validation",
            "ssti_validation", "deserialization_format_confirmation", "command_injection_validation",
            "race_condition_validation", "header_injection_validation", "api_security_validation",
            "file_upload_validation"
    );

    public String getBaseUrl() {
        return baseUrlField.getText().trim();
    }

    /** Parses the analysis-timeout field; falls back to 600s (and
     * resets the field to show that) on anything unparseable rather
     * than silently using a stale or nonsensical value. */
    public int getAnalysisTimeoutSeconds() {
        try {
            int value = Integer.parseInt(analysisTimeoutField.getText().trim());
            if (value > 0) return value;
        } catch (NumberFormatException ignored) {
            // fall through to default below
        }
        analysisTimeoutField.setText("600");
        return 600;
    }

    public boolean getAttemptRediscovery() {
        return rediscoveryCheckbox.isSelected();
    }

    /** Called from the Swing event thread by the extension after an analysis completes. */
    public void addSuccess(String label, AnalysisResponse response) {
        listModel.addElement(new ResultEntry(label, response, null));
        resultList.setSelectedIndex(listModel.size() - 1);
    }

    public void addFailure(String label, String error) {
        listModel.addElement(new ResultEntry(label, null, error));
        resultList.setSelectedIndex(listModel.size() - 1);
    }

    /**
     * Writes every result currently in the list to a single Markdown
     * report -- the baseline output format every comparable tool (Strix,
     * Xalgorix, PentAGI) produces and this extension previously lacked.
     * Rejected findings are already gone by the time results reach here
     * (the critique pass removes them before the extension ever sees
     * them), so nothing filtered-out shows up in the export.
     */
    private void saveReport() {
        if (listModel.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No results to export yet.");
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new java.io.File("llm-harness-report.md"));
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;

        StringBuilder sb = new StringBuilder();
        sb.append("# LLM Harness Report\n\n");
        sb.append("Generated ").append(java.time.Instant.now()).append("\n\n");

        int total = 0, critical = 0, high = 0;
        for (int i = 0; i < listModel.size(); i++) {
            ResultEntry e = listModel.get(i);
            if (e.error() != null) continue;
            for (AgentReport ar : e.response().agent_reports) {
                if (ar.findings == null) continue;
                for (Finding f : ar.findings) {
                    total++;
                    if ("critical".equals(f.severity)) critical++;
                    if ("high".equals(f.severity)) high++;
                }
            }
        }
        sb.append(String.format("**%d findings** (%d critical, %d high) across %d analyzed exchange(s).%n%n",
                total, critical, high, listModel.size()));

        for (int i = 0; i < listModel.size(); i++) {
            ResultEntry e = listModel.get(i);
            sb.append("## ").append(e.label()).append("\n\n");
            if (e.error() != null) {
                sb.append("**Error:** ").append(e.error()).append("\n\n");
                continue;
            }
            AnalysisResponse r = e.response();
            sb.append("_").append(r.summary).append("_\n\n");
            for (AgentReport ar : r.agent_reports) {
                if (ar.raw_error != null) {
                    sb.append("- **").append(ar.agent).append("**: error -- ").append(ar.raw_error).append('\n');
                    continue;
                }
                if (ar.findings == null || ar.findings.isEmpty()) continue;
                for (Finding f : ar.findings) {
                    sb.append(String.format("- **[%s] %s** (severity: %s, confidence: %.2f, confirmed: %s, basis: %s%s)%n",
                            ar.agent, f.vulnerability_class, f.severity, f.confidence, f.confirmed, f.basis,
                            f.owasp_category != null ? ", " + f.owasp_category : ""));
                    sb.append("  - Summary: ").append(f.summary).append('\n');
                    sb.append("  - Evidence: ").append(f.evidence).append('\n');
                    sb.append("  - Next step: ").append(f.suggested_test).append('\n');
                    // R06 (self-reviewed / UNBUILT, see AnalysisModels.Finding's own note --
                    // no JDK here to compile or test this file): `confirmed` only means a
                    // deterministic leg fired once; `verification_state`/`oracle_verified`
                    // is the STRICTER oracle bar (N-of-N reproduction + a clean negative
                    // control). Before this change the panel collapsed both axes into one
                    // CONFIRMED/HYPOTHESIS label, so an oracle-verified finding and a
                    // merely leg-confirmed one were shown identically.
                    String verificationLabel;
                    if (f.oracle_verified || "verified".equals(f.verification_state)) {
                        verificationLabel = "ORACLE-VERIFIED";
                    } else if (f.confirmed) {
                        verificationLabel = "CONFIRMED (leg fired, not oracle-verified)";
                    } else {
                        verificationLabel = "HYPOTHESIS / NOT CONFIRMED";
                    }
                    sb.append("  - Verification status: ").append(verificationLabel).append('\n');
                    if (f.review_verdict != null) {
                        sb.append("  - Reviewed: ").append(f.review_verdict)
                          .append(" -- ").append(f.review_note).append('\n');
                    }
                }
            }
            sb.append('\n');
        }

        try (java.io.FileWriter w = new java.io.FileWriter(chooser.getSelectedFile())) {
            w.write(sb.toString());
            JOptionPane.showMessageDialog(this, "Report saved to " + chooser.getSelectedFile());
        } catch (java.io.IOException ex) {
            JOptionPane.showMessageDialog(this, "Failed to save report: " + ex.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void showDetail(ResultEntry entry) {
        if (entry == null) {
            detailArea.setText("");
            return;
        }
        if (entry.error() != null) {
            detailArea.setText("ERROR\n=====\n" + entry.error());
            return;
        }
        AnalysisResponse r = entry.response();
        StringBuilder sb = new StringBuilder();
        sb.append("Coordinator model: ").append(r.coordinator_model).append('\n');
        sb.append("Dispatched agents: ").append(String.join(", ", r.dispatched_agents)).append('\n');
        sb.append('\n').append(r.summary).append("\n\n");
        sb.append("================\n");

        List<AgentReport> reports = r.agent_reports;
        if (reports == null || reports.isEmpty()) {
            sb.append("(no agent reports)\n");
        }
        for (AgentReport ar : reports) {
            sb.append("\n[").append(ar.agent).append("] model=").append(ar.model).append('\n');
            if (ar.raw_error != null) {
                sb.append("  ERROR: ").append(ar.raw_error).append('\n');
                continue;
            }
            if (ar.findings == null || ar.findings.isEmpty()) {
                sb.append("  (no findings)\n");
                continue;
            }
            for (Finding f : ar.findings) {
                sb.append(String.format("  - [%s] severity=%s confidence=%.2f basis=%s%s%n",
                        f.vulnerability_class, f.severity, f.confidence, f.basis,
                        f.owasp_category != null ? " owasp=" + f.owasp_category : ""));
                sb.append("    summary: ").append(f.summary).append('\n');
                sb.append("    evidence: ").append(f.evidence).append('\n');
                sb.append("    next step: ").append(f.suggested_test).append('\n');
                if (f.review_verdict != null) {
                    sb.append(String.format("    reviewed: %s (was %.2f -> %.2f) -- %s%n",
                            f.review_verdict,
                            f.original_confidence != null ? f.original_confidence : f.confidence,
                            f.confidence, f.review_note));
                }
            }
        }
        detailArea.setText(sb.toString());
        detailArea.setCaretPosition(0);
    }

    private static class ResultCellRenderer extends DefaultListCellRenderer {
        @Override
        public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                        boolean isSelected, boolean cellHasFocus) {
            JLabel label = (JLabel) super.getListCellRendererComponent(
                    list, value, index, isSelected, cellHasFocus);
            if (value instanceof ResultEntry entry) {
                if (entry.error() != null) {
                    label.setText("\u26A0 " + entry.label());
                    if (!isSelected) label.setForeground(Color.RED);
                    return label;
                }

                int n = 0;
                FindingSeverity highest = FindingSeverity.UNKNOWN;
                for (AgentReport ar : entry.response().agent_reports) {
                    if (ar.findings == null) continue;
                    for (Finding f : ar.findings) {
                        if (f.confidence < MIN_REPORT_CONFIDENCE) continue;
                        n++;
                        FindingSeverity sev = FindingSeverity.fromString(f.severity);
                        if (sev.isAtLeast(highest)) highest = sev;
                    }
                }
                int runnable = 0;
                if (entry.response().test_plans != null) {
                    for (TestPlan p : entry.response().test_plans) {
                        if (runnableHere(p)) runnable++;
                    }
                }
                label.setText(runnable > 0
                        ? String.format("[%d ▸%d] %s", n, runnable, entry.label())
                        : String.format("[%d] %s", n, entry.label()));
                if (n == 0) return label;

                JPanel row = new JPanel(new BorderLayout(6, 0));
                row.setOpaque(true);
                row.setBackground(label.getBackground());
                row.add(label, BorderLayout.CENTER);
                row.add(new SeverityBadge(highest), BorderLayout.EAST);
                return row;
            }
            return label;
        }
    }
}
