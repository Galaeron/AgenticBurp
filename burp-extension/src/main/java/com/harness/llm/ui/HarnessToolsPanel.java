package com.harness.llm.ui;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.harness.llm.HarnessClient;
import com.harness.llm.model.AnalysisModels.ActivityEvent;
import com.harness.llm.model.AnalysisModels.ActivitySnapshot;
import com.harness.llm.model.AnalysisModels.HttpExchange;
import com.harness.llm.model.AnalysisModels.ModelsInfo;
import com.harness.llm.model.AnalysisModels.SelectModelRequest;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BiConsumer;

/**
 * "Harness Tools" suite tab -- the UI for the Session-3 server capabilities
 * that don't belong to the per-exchange analysis flow: model selection, runtime
 * settings, endpoint discovery (crawl), missing-auth probing, the active
 * (iterative) agent, the per-vulnerability retry loop, the budget-allocation
 * prioritizer, tool recommendations, the confidential-info scanner, and the
 * live agent-activity feed.
 *
 * Deliberately self-contained: it owns no analysis state and only talks to the
 * shared {@link HarnessClient}, so it can't destabilize the existing
 * AttackSurface/Harness panels. Every network call runs off the EDT (see
 * {@link #runAsync}); deep/dynamic responses are shown as pretty-printed JSON
 * rather than mirrored into bespoke widgets, which keeps this one panel able to
 * surface everything the server returns without a DTO per shape.
 */
public class HarnessToolsPanel extends JPanel {

    private final HarnessClient client;
    private final Gson pretty = new GsonBuilder().setPrettyPrinting().create();
    /** (baseUrl, discovered paths) -> add them to Burp's Target site map. Null
     * when the panel is used without a Burp API (e.g. standalone). */
    private final BiConsumer<String, List<String>> siteMapImporter;

    // Model dropdowns (populated from GET /models).
    private final JComboBox<String> coordinatorCombo = new JComboBox<>();
    private final JComboBox<String> agentCombo = new JComboBox<>();

    public HarnessToolsPanel(HarnessClient client) {
        this(client, null);
    }

    public HarnessToolsPanel(HarnessClient client, BiConsumer<String, List<String>> siteMapImporter) {
        this.client = client;
        this.siteMapImporter = siteMapImporter;
        setLayout(new BorderLayout());
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Engagement", buildEngagementTab());
        tabs.addTab("Models & Settings", buildModelsTab());
        tabs.addTab("Discovery", buildDiscoveryTab());
        tabs.addTab("Active Testing", buildActiveTab());
        tabs.addTab("Cross-Identity", buildCrossIdentityTab());
        tabs.addTab("Budget", buildBudgetTab());
        tabs.addTab("Tools", buildToolsTab());
        tabs.addTab("Confidential Scan", buildConfidentialTab());
        tabs.addTab("Activity", buildActivityTab());
        add(tabs, BorderLayout.CENTER);
    }

    // ------------------------------------------------------------------
    // Shared helpers
    // ------------------------------------------------------------------

    private JTextArea outputArea() {
        JTextArea a = new JTextArea();
        a.setEditable(false);
        a.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        a.setLineWrap(true);
        a.setWrapStyleWord(true);
        return a;
    }

    /** Runs {@code call} off the EDT; renders the resulting JSON (or the error)
     * into {@code out}. Disables {@code trigger} while in flight so a slow call
     * can't be fired repeatedly. */
    private void runAsync(JButton trigger, JTextArea out, Callable<JsonObject> call) {
        if (trigger != null) trigger.setEnabled(false);
        out.setText("Running...");
        new SwingWorker<Object, Void>() {
            @Override protected Object doInBackground() {
                try {
                    return call.call();
                } catch (Exception e) {
                    return e;
                }
            }
            @Override protected void done() {
                try {
                    Object r = get();
                    if (r instanceof Exception e) {
                        out.setText("ERROR: " + (e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName()));
                    } else {
                        out.setText(pretty.toJson(r));
                    }
                } catch (Exception e) {
                    out.setText("ERROR: " + e.getMessage());
                } finally {
                    if (trigger != null) trigger.setEnabled(true);
                    out.setCaretPosition(0);
                }
            }
        }.execute();
    }

    private HttpExchange exchangeFrom(String url, String method, String responseBody) {
        HttpExchange ex = new HttpExchange();
        ex.url = url.trim();
        ex.method = method == null || method.isBlank() ? "GET" : method.trim();
        ex.request_headers = new HashMap<>();
        ex.request_body = "";
        ex.response_status = 200;
        ex.response_headers = new HashMap<>();
        ex.response_body = responseBody == null ? "" : responseBody;
        ex.analyst_note = "";
        return ex;
    }

    private static JPanel labeled(String label, Component field) {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        p.add(new JLabel(label));
        p.add(field);
        return p;
    }

    private static JPanel form(JComponent... rows) {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        for (JComponent r : rows) {
            r.setAlignmentX(Component.LEFT_ALIGNMENT);
            p.add(r);
        }
        return p;
    }

    private JPanel withOutput(JComponent north, JTextArea out) {
        JPanel p = new JPanel(new BorderLayout(4, 4));
        p.add(north, BorderLayout.NORTH);
        p.add(new JScrollPane(out), BorderLayout.CENTER);
        return p;
    }

    // ------------------------------------------------------------------
    // Models & Settings
    // ------------------------------------------------------------------

    // ------------------------------------------------------------------
    // Engagement: the fused, ranked worklist + the closed-loop advance
    // ------------------------------------------------------------------

    private JComponent buildEngagementTab() {
        JTextField hostField = new JTextField("", 20);
        DefaultTableModel model = new DefaultTableModel(
                new Object[]{"#", "score", "method", "path", "status", "why"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
        };
        JTable table = new JTable(model);
        table.getColumnModel().getColumn(0).setMaxWidth(36);
        table.getColumnModel().getColumn(1).setMaxWidth(60);
        table.getColumnModel().getColumn(2).setMaxWidth(70);
        table.getColumnModel().getColumn(4).setMaxWidth(90);
        JTextArea detail = outputArea();
        detail.setBorder(BorderFactory.createTitledBorder("Pending actions + summary"));

        JButton loadBtn = new JButton("Load worklist");
        loadBtn.addActionListener(e -> loadEngagement(hostField.getText().trim(), model, detail, loadBtn));

        // Advance: re-crawl as roles and fold new surface back into the ranking.
        JTextField advBase = new JTextField("", 28);
        JTextArea advRoles = new JTextArea(3, 28);
        advRoles.setText("anonymous |\nadmin | Authorization=Bearer <token>");
        advRoles.setBorder(BorderFactory.createTitledBorder(
                "Advance as roles -- <role> | <Header>=<value>  (re-crawl, fold back into the ranking)"));
        JButton advanceBtn = new JButton("Advance (re-crawl + re-rank)");
        advanceBtn.addActionListener(e -> {
            String host = hostField.getText().trim();
            String base = advBase.getText().trim();
            List<Map<String, Object>> roles = parseRoles(advRoles.getText());
            advanceBtn.setEnabled(false);
            detail.setText("Advancing...");
            new SwingWorker<Object, Void>() {
                @Override protected Object doInBackground() {
                    try { return client.engagementAdvance(host, base, roles); }
                    catch (Exception ex) { return ex; }
                }
                @Override protected void done() {
                    try {
                        Object r = get();
                        if (r instanceof Exception ex) { detail.setText("ERROR: " + ex.getMessage()); return; }
                        fillWorklist((JsonObject) r, model, detail);
                    } catch (Exception ex) {
                        detail.setText("ERROR: " + ex.getMessage());
                    } finally {
                        advanceBtn.setEnabled(true);
                    }
                }
            }.execute();
        });

        JPanel north = new JPanel();
        north.setLayout(new BoxLayout(north, BoxLayout.Y_AXIS));
        JPanel top = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        top.add(new JLabel("Host:"));
        top.add(hostField);
        top.add(loadBtn);
        top.setAlignmentX(Component.LEFT_ALIGNMENT);
        north.add(new JLabel("Fused worklist: every signal (path tier, LLM rating, role-access, findings) in one ranking."));
        north.add(top);
        advRoles.setAlignmentX(Component.LEFT_ALIGNMENT);
        JPanel advRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        advRow.add(new JLabel("Advance base URL:"));
        advRow.add(advBase);
        advRow.add(advanceBtn);
        advRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        north.add(advRoles);
        north.add(advRow);

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
                new JScrollPane(table), new JScrollPane(detail));
        split.setResizeWeight(0.6);
        JPanel p = new JPanel(new BorderLayout(4, 4));
        p.add(north, BorderLayout.NORTH);
        p.add(split, BorderLayout.CENTER);
        return p;
    }

    private void loadEngagement(String host, DefaultTableModel model, JTextArea detail, JButton trigger) {
        trigger.setEnabled(false);
        detail.setText("Loading...");
        new SwingWorker<Object, Void>() {
            @Override protected Object doInBackground() {
                try { return client.engagement(host, 50); } catch (Exception e) { return e; }
            }
            @Override protected void done() {
                try {
                    Object r = get();
                    if (r instanceof Exception e) { detail.setText("ERROR: " + e.getMessage()); return; }
                    fillWorklist((JsonObject) r, model, detail);
                } catch (Exception e) {
                    detail.setText("ERROR: " + e.getMessage());
                } finally {
                    trigger.setEnabled(true);
                }
            }
        }.execute();
    }

    private void fillWorklist(JsonObject resp, DefaultTableModel model, JTextArea detail) {
        model.setRowCount(0);
        if (resp.has("worklist") && resp.get("worklist").isJsonArray()) {
            int i = 1;
            for (JsonElement el : resp.getAsJsonArray("worklist")) {
                if (!el.isJsonObject()) continue;
                JsonObject e = el.getAsJsonObject();
                String why = "";
                if (e.has("reasons") && e.get("reasons").isJsonArray() && e.getAsJsonArray("reasons").size() > 0) {
                    why = e.getAsJsonArray("reasons").get(0).getAsString();
                }
                model.addRow(new Object[]{
                        i++,
                        e.has("score") ? String.format("%.2f", e.get("score").getAsDouble()) : "",
                        str(e, "method"), str(e, "path"), str(e, "status"), why});
            }
        }
        // Ready + blocked tasks and summary go to the detail area as pretty JSON.
        JsonObject slim = new JsonObject();
        if (resp.has("ready_tasks")) slim.add("ready_tasks", resp.get("ready_tasks"));
        if (resp.has("blocked_tasks")) slim.add("blocked_tasks", resp.get("blocked_tasks"));
        if (resp.has("summary")) slim.add("summary", resp.get("summary"));
        detail.setText(pretty.toJson(slim));
        detail.setCaretPosition(0);
    }

    private static String str(JsonObject o, String k) {
        return (o.has(k) && !o.get(k).isJsonNull()) ? o.get(k).getAsString() : "";
    }

    private JComponent buildModelsTab() {
        JTextArea out = outputArea();

        JButton refresh = new JButton("Refresh models");
        refresh.addActionListener(e -> reloadModels(out));

        JButton applyModels = new JButton("Apply model selection");
        applyModels.addActionListener(e -> {
            SelectModelRequest req = new SelectModelRequest();
            Object coord = coordinatorCombo.getSelectedItem();
            Object agent = agentCombo.getSelectedItem();
            req.coordinator = coord == null ? "" : coord.toString();
            req.agent_model = agent == null ? "" : agent.toString();
            runAsync(applyModels, out, () -> client.selectModel(req));
        });

        JTextField throttleField = new JTextField("0", 6);
        JTextField retriesField = new JTextField("", 4);
        JTextField agentsField = new JTextField("", 4);
        JTextField perVulnField = new JTextField("", 8);
        JButton applySettings = new JButton("Apply settings");
        applySettings.addActionListener(e -> {
            Double rps = parseDoubleOrNull(throttleField.getText());
            Map<String, Object> retry = new HashMap<>();
            putIntIfPresent(retry, "max_retries", retriesField.getText());
            putIntIfPresent(retry, "max_agents", agentsField.getText());
            putIntIfPresent(retry, "max_tokens_per_vuln", perVulnField.getText());
            runAsync(applySettings, out, () -> client.updateSettings(rps, retry.isEmpty() ? null : retry));
        });
        JButton loadSettings = new JButton("Load current settings");
        loadSettings.addActionListener(e -> runAsync(loadSettings, out, client::getSettings));

        JComponent north = form(
                new JLabel("Model selection (the two dropdowns): coordinator/governor and agent model."),
                labeled("Coordinator model:", coordinatorCombo),
                labeled("Agent model (all agents):", agentCombo),
                buttonRow(refresh, applyModels),
                new JSeparator(),
                new JLabel("Runtime settings: throttle (req/s, 0 = unlimited) and default retry budget."),
                labeled("Throttle req/s:", throttleField),
                labeled("Retry budget -- max_retries:", retriesField),
                labeled("max_agents:", agentsField),
                labeled("max_tokens_per_vuln (0 = none):", perVulnField),
                buttonRow(loadSettings, applySettings));
        return withOutput(north, out);
    }

    private void reloadModels(JTextArea out) {
        new SwingWorker<Object, Void>() {
            @Override protected Object doInBackground() {
                try { return client.listModels(); } catch (Exception e) { return e; }
            }
            @Override protected void done() {
                try {
                    Object r = get();
                    if (r instanceof Exception e) {
                        out.setText("ERROR loading models: " + e.getMessage());
                        return;
                    }
                    ModelsInfo m = (ModelsInfo) r;
                    coordinatorCombo.removeAllItems();
                    agentCombo.removeAllItems();
                    List<String> all = m.all != null ? m.all : List.of();
                    for (String name : all) {
                        coordinatorCombo.addItem(name);
                        agentCombo.addItem(name);
                    }
                    if (m.coordinator_model != null) coordinatorCombo.setSelectedItem(m.coordinator_model);
                    out.setText(pretty.toJson(m));
                    out.setCaretPosition(0);
                } catch (Exception e) {
                    out.setText("ERROR: " + e.getMessage());
                }
            }
        }.execute();
    }

    // ------------------------------------------------------------------
    // Discovery (crawl + missing-auth)
    // ------------------------------------------------------------------

    private JComponent buildDiscoveryTab() {
        JTextArea out = outputArea();

        // --- plain crawl (+ optional Target import) ---
        JTextField crawlUrl = new JTextField("", 30);
        JTextField maxPages = new JTextField("40", 5);
        JCheckBox crawlImport = new JCheckBox("Add discovered endpoints to Target site map", true);
        crawlImport.setEnabled(siteMapImporter != null);
        JButton crawlBtn = new JButton("Crawl");
        crawlBtn.addActionListener(e -> {
            String base = crawlUrl.getText().trim();
            runAndMaybeImport(crawlBtn, out,
                    () -> client.crawl(base, null, parseIntOr(maxPages.getText(), 40), 2),
                    crawlImport.isSelected(), base, HarnessToolsPanel::pathsFromStringArray);
        });

        // --- role-aware crawl -> access matrix ---
        JTextArea rolesArea = new JTextArea(4, 30);
        rolesArea.setText("anonymous |\nadmin | Authorization=Bearer <token>");
        rolesArea.setBorder(BorderFactory.createTitledBorder(
                "Roles -- one per line: <role> | <Header>=<value>; <Header2>=<value2>   (blank headers = anonymous)"));
        JTextField roleBase = new JTextField("", 30);
        JCheckBox roleImport = new JCheckBox("Add discovered endpoints to Target site map", true);
        roleImport.setEnabled(siteMapImporter != null);
        JButton roleBtn = new JButton("Role crawl -> access matrix");
        roleBtn.addActionListener(e -> {
            String base = roleBase.getText().trim();
            List<Map<String, Object>> roles = parseRoles(rolesArea.getText());
            runAndMaybeImport(roleBtn, out,
                    () -> client.crawlRoles(base, roles, parseIntOr(maxPages.getText(), 40)),
                    roleImport.isSelected(), base, HarnessToolsPanel::pathsFromEndpointObjects);
        });

        // --- missing-auth probe ---
        JTextField maUrl = new JTextField("", 30);
        JTextArea maPaths = new JTextArea(4, 30);
        maPaths.setBorder(BorderFactory.createTitledBorder("Paths to probe (one per line; blank -> use discover)"));
        JCheckBox discover = new JCheckBox("Discover endpoints first (crawl)");
        JButton probeBtn = new JButton("Probe missing auth");
        probeBtn.addActionListener(e -> {
            Map<String, Object> body = new HashMap<>();
            body.put("base_url", maUrl.getText().trim());
            List<String> paths = new ArrayList<>();
            for (String line : maPaths.getText().split("\\R")) {
                if (!line.isBlank()) paths.add(line.trim());
            }
            if (!paths.isEmpty()) body.put("paths", paths);
            body.put("discover", discover.isSelected());
            runAsync(probeBtn, out, () -> client.probeMissingAuth(body));
        });

        JComponent north = form(
                new JLabel("Crawl: mine the app's JS bundles for its real endpoint surface (POST /crawl)."),
                labeled("Base URL:", crawlUrl),
                labeled("Max pages:", maxPages),
                buttonRow(crawlImport, crawlBtn),
                new JSeparator(),
                new JLabel("Role crawl: per-role access matrix -> IDOR + auth-bypass candidates (POST /crawl-roles)."),
                labeled("Base URL:", roleBase),
                rolesArea,
                buttonRow(roleImport, roleBtn),
                new JSeparator(),
                new JLabel("Missing-auth probe: fire endpoints with credentials stripped, flag substantive 2xx."),
                labeled("Base URL:", maUrl),
                maPaths,
                buttonRow(discover, probeBtn));
        return withOutput(north, out);
    }

    /** Runs {@code call}, renders the JSON, and -- when {@code doImport} and a
     * site-map importer are present -- feeds the extracted endpoint paths into
     * Burp's Target site map. */
    private void runAndMaybeImport(JButton trigger, JTextArea out, Callable<JsonObject> call,
                                   boolean doImport, String baseUrl,
                                   java.util.function.Function<JsonObject, List<String>> extractor) {
        trigger.setEnabled(false);
        out.setText("Running...");
        new SwingWorker<Object, Void>() {
            @Override protected Object doInBackground() {
                try { return call.call(); } catch (Exception e) { return e; }
            }
            @Override protected void done() {
                try {
                    Object r = get();
                    if (r instanceof Exception e) {
                        out.setText("ERROR: " + (e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName()));
                        return;
                    }
                    JsonObject obj = (JsonObject) r;
                    out.setText(pretty.toJson(obj));
                    out.setCaretPosition(0);
                    if (doImport && siteMapImporter != null) {
                        List<String> paths = extractor.apply(obj);
                        if (!paths.isEmpty()) {
                            siteMapImporter.accept(baseUrl, paths);
                            out.append("\n\n[added " + paths.size() + " endpoint(s) to the Target site map]");
                        }
                    }
                } catch (Exception e) {
                    out.setText("ERROR: " + e.getMessage());
                } finally {
                    trigger.setEnabled(true);
                }
            }
        }.execute();
    }

    /** Parse the roles text area into [{role, headers}]. Each line:
     * {@code <role> | Header=value; Header2=value2}. */
    private static List<Map<String, Object>> parseRoles(String text) {
        List<Map<String, Object>> roles = new ArrayList<>();
        for (String line : text.split("\\R")) {
            if (line.isBlank()) continue;
            String[] halves = line.split("\\|", 2);
            String role = halves[0].trim();
            if (role.isEmpty()) continue;
            Map<String, String> headers = new HashMap<>();
            if (halves.length == 2) {
                for (String pair : halves[1].split(";")) {
                    if (pair.isBlank()) continue;
                    int eq = pair.indexOf('=');
                    if (eq <= 0) continue;
                    headers.put(pair.substring(0, eq).trim(), pair.substring(eq + 1).trim());
                }
            }
            Map<String, Object> r = new HashMap<>();
            r.put("role", role);
            r.put("headers", headers);
            roles.add(r);
        }
        return roles;
    }

    /** endpoints from a /crawl result: a JSON array of path strings. */
    private static List<String> pathsFromStringArray(JsonObject o) {
        List<String> out = new ArrayList<>();
        if (o.has("endpoints") && o.get("endpoints").isJsonArray()) {
            for (JsonElement el : o.getAsJsonArray("endpoints")) {
                if (el.isJsonPrimitive()) out.add(el.getAsString());
            }
        }
        return out;
    }

    /** endpoints from a /crawl-roles result: a JSON array of objects each with a "path". */
    private static List<String> pathsFromEndpointObjects(JsonObject o) {
        List<String> out = new ArrayList<>();
        if (o.has("endpoints") && o.get("endpoints").isJsonArray()) {
            for (JsonElement el : o.getAsJsonArray("endpoints")) {
                if (el.isJsonObject()) {
                    JsonObject e = el.getAsJsonObject();
                    if (e.has("path")) out.add(e.get("path").getAsString());
                }
            }
        }
        return out;
    }

    // ------------------------------------------------------------------
    // Active testing (active-probe + retry-agents)
    // ------------------------------------------------------------------

    private JComponent buildActiveTab() {
        JTextArea out = outputArea();

        JTextField url = new JTextField("", 30);
        JComboBox<String> method = new JComboBox<>(new String[]{"GET", "POST", "PUT", "PATCH", "DELETE"});
        JTextField hypothesis = new JTextField("IDOR on the id parameter", 30);
        JTextField specialty = new JTextField("idor", 12);
        JTextField stepBudget = new JTextField("20", 5);
        JButton probeBtn = new JButton("Run active probe");
        probeBtn.addActionListener(e -> {
            HttpExchange ex = exchangeFrom(url.getText(), (String) method.getSelectedItem(), "");
            runAsync(probeBtn, out, () -> client.activeProbe(ex, hypothesis.getText().trim(),
                    specialty.getText().trim(), "", parseIntOr(stepBudget.getText(), 20)));
        });

        JTextField retryClass = new JTextField("sqli", 12);
        JTextField retryCount = new JTextField("3", 4);
        JButton retryBtn = new JButton("Retry agents");
        retryBtn.addActionListener(e -> {
            HttpExchange ex = exchangeFrom(url.getText(), (String) method.getSelectedItem(), "");
            Map<String, Object> overrides = new HashMap<>();
            putIntIfPresent(overrides, "max_retries", retryCount.getText());
            runAsync(retryBtn, out, () -> client.retryAgents(ex, retryClass.getText().trim(),
                    overrides.isEmpty() ? null : overrides));
        });

        JComponent north = form(
                new JLabel("Active testing drives real adaptive traffic (server: iterative_agent.enabled + safety gate)."),
                labeled("URL:", url),
                labeled("Method:", method),
                new JLabel("Active probe (F4+F2): iterate, then validate/remember/pivot."),
                labeled("Hypothesis:", hypothesis),
                labeled("Specialty:", specialty),
                labeled("Step budget:", stepBudget),
                buttonRow(probeBtn),
                new JSeparator(),
                new JLabel("Retry loop (F5): re-run one agent up to N times, stop on a finding."),
                labeled("Agent class:", retryClass),
                labeled("Max retries:", retryCount),
                buttonRow(retryBtn));
        return withOutput(north, out);
    }

    // ------------------------------------------------------------------
    // Cross-Identity (Autorize-style access-control confirmation)
    // ------------------------------------------------------------------

    private JComponent buildCrossIdentityTab() {
        JTextArea out = outputArea();

        // --- runtime toggles (POST /settings; in-memory, gone on restart) ---
        JCheckBox activeToggle = new JCheckBox("Enable active validators (validators.active_enabled)");
        JCheckBox xidToggle = new JCheckBox("Arm the cross-identity validator");
        JButton loadState = new JButton("Load current state");
        loadState.addActionListener(e -> {
            loadState.setEnabled(false);
            out.setText("Loading...");
            new SwingWorker<Object, Void>() {
                @Override protected Object doInBackground() {
                    try { return client.getSettings(); } catch (Exception ex) { return ex; }
                }
                @Override protected void done() {
                    try {
                        Object r = get();
                        if (r instanceof Exception ex) { out.setText("ERROR: " + ex.getMessage()); return; }
                        JsonObject o = (JsonObject) r;
                        if (o.has("validators") && o.get("validators").isJsonObject()) {
                            JsonObject v = o.getAsJsonObject("validators");
                            activeToggle.setSelected(v.has("active_enabled") && v.get("active_enabled").getAsBoolean());
                            xidToggle.setSelected(v.has("cross_identity_enabled")
                                    && v.get("cross_identity_enabled").getAsBoolean());
                        }
                        out.setText(pretty.toJson(o));
                        out.setCaretPosition(0);
                    } catch (Exception ex) {
                        out.setText("ERROR: " + ex.getMessage());
                    } finally {
                        loadState.setEnabled(true);
                    }
                }
            }.execute();
        });
        JButton applyToggle = new JButton("Apply toggles");
        applyToggle.addActionListener(e -> runAsync(applyToggle, out,
                () -> client.setValidators(activeToggle.isSelected(), xidToggle.isSelected())));

        // --- supply another identity's session headers (Autorize low-priv cookie) ---
        JTextField host = new JTextField("", 20);
        JTextField name = new JTextField("victim", 14);
        JTextField role = new JTextField("user", 10);
        JTextArea headers = new JTextArea(5, 30);
        headers.setText("Authorization: Bearer <another identity's token>\nCookie: session=<value>");
        headers.setBorder(BorderFactory.createTitledBorder(
                "Session headers -- one per line: <Header>: <value>   (split at the first colon; "
                + "a Cookie value's own '=' and ';' are preserved)"));
        JButton addBtn = new JButton("Add identity");
        addBtn.addActionListener(e -> {
            Map<String, String> hdrs = parseHeaderLines(headers.getText());
            if (hdrs.isEmpty()) { out.setText("ERROR: supply at least one header line (e.g. Authorization: ...)"); return; }
            runAsync(addBtn, out, () -> client.setSessionHeaders(
                    host.getText().trim(), name.getText().trim(), role.getText().trim(), hdrs));
        });

        JComponent north = form(
                new JLabel("Cross-identity replays an object-scoped GET as ANOTHER identity (+ anon) and compares --"),
                new JLabel("the Autorize move: it tells a real IDOR from your own 200. GET-only, scoped to allowed_hosts."),
                new JSeparator(),
                new JLabel("1) Arm it (runtime, in-memory -- resets on server restart):"),
                activeToggle,
                xidToggle,
                buttonRow(loadState, applyToggle),
                new JSeparator(),
                new JLabel("2) Supply another identity's real session headers (in memory only, never persisted):"),
                labeled("Host:", host),
                labeled("Identity name:", name),
                labeled("Role:", role),
                headers,
                buttonRow(addBtn));
        return withOutput(north, out);
    }

    /** Parse pasted HTTP header lines into a name->value map. Each non-blank line
     * is split at its FIRST ':' so a Cookie value's own '=' and ';' survive
     * intact. Lines without a ':' are ignored. */
    private static Map<String, String> parseHeaderLines(String text) {
        Map<String, String> headers = new HashMap<>();
        for (String line : text.split("\\R")) {
            if (line.isBlank()) continue;
            int colon = line.indexOf(':');
            if (colon <= 0) continue;
            String key = line.substring(0, colon).trim();
            String value = line.substring(colon + 1).trim();
            if (!key.isEmpty()) headers.put(key, value);
        }
        return headers;
    }

    // ------------------------------------------------------------------
    // Budget allocation
    // ------------------------------------------------------------------

    private JComponent buildBudgetTab() {
        JTextArea out = outputArea();
        JTextArea candidates = new JTextArea(6, 30);
        candidates.setText("critical sqli https://shop.test/rest/user/login\nlow xss https://shop.test/search");
        candidates.setBorder(BorderFactory.createTitledBorder(
                "Candidates -- one per line: <severity> <vulnerability_class> <url>"));
        JCheckBox useLlm = new JCheckBox("Use LLM (cloud model) to rank for this app");
        JButton planBtn = new JButton("Plan allocation");
        planBtn.addActionListener(e -> {
            List<Map<String, Object>> cands = new ArrayList<>();
            int i = 0;
            for (String line : candidates.getText().split("\\R")) {
                String[] parts = line.trim().split("\\s+", 3);
                if (parts.length < 3) continue;
                Map<String, Object> c = new HashMap<>();
                c.put("id", "c" + (i++));
                c.put("severity", parts[0]);
                c.put("vulnerability_class", parts[1]);
                c.put("url", parts[2]);
                cands.add(c);
            }
            runAsync(planBtn, out, () -> client.planAllocation(cands, useLlm.isSelected()));
        });
        JComponent north = form(
                new JLabel("F5 prioritizer: spread the remaining token budget across competing vulnerabilities."),
                candidates,
                buttonRow(useLlm, planBtn));
        return withOutput(north, out);
    }

    // ------------------------------------------------------------------
    // Tools
    // ------------------------------------------------------------------

    private JComponent buildToolsTab() {
        JTextArea out = outputArea();
        JTextField vc = new JTextField("sqli", 14);
        JTextField url = new JTextField("https://shop.test/item?id=1", 30);
        JButton recommend = new JButton("Recommend tools");
        recommend.addActionListener(e ->
                runAsync(recommend, out, () -> client.recommendTools(vc.getText().trim(), url.getText().trim())));
        JButton listAll = new JButton("List catalog");
        listAll.addActionListener(e -> runAsync(listAll, out, () -> client.tools("")));
        JComponent north = form(
                new JLabel("A3 tool catalog: which external tool to reach for, with a command templated to the URL."),
                labeled("Vulnerability class:", vc),
                labeled("Target URL:", url),
                buttonRow(recommend, listAll));
        return withOutput(north, out);
    }

    // ------------------------------------------------------------------
    // Confidential scan
    // ------------------------------------------------------------------

    private JComponent buildConfidentialTab() {
        JTextArea out = outputArea();
        JTextField url = new JTextField("https://shop.test/api/x", 30);
        JTextArea body = new JTextArea(8, 30);
        body.setBorder(BorderFactory.createTitledBorder("Response body to scan"));
        JButton scanBtn = new JButton("Scan response");
        scanBtn.addActionListener(e -> {
            HttpExchange ex = exchangeFrom(url.getText(), "GET", body.getText());
            runAsync(scanBtn, out, () -> client.scanConfidential(ex));
        });
        JComponent north = form(
                new JLabel("A4: deterministic secret/PII/internal-infra scan (values are redacted server-side)."),
                labeled("URL:", url),
                body,
                buttonRow(scanBtn));
        return withOutput(north, out);
    }

    // ------------------------------------------------------------------
    // Activity feed (live poll)
    // ------------------------------------------------------------------

    private long lastSeq = 0;
    private final AtomicBoolean polling = new AtomicBoolean(false);

    private JComponent buildActivityTab() {
        JTextArea out = outputArea();
        out.setLineWrap(false);
        JButton startBtn = new JButton("Start live view");
        JButton stopBtn = new JButton("Stop");
        stopBtn.setEnabled(false);
        JButton clearBtn = new JButton("Clear");
        clearBtn.addActionListener(e -> out.setText(""));

        // A Swing timer ticks on the EDT and launches a short background fetch;
        // an in-flight guard prevents overlapping polls from piling up.
        javax.swing.Timer timer = new javax.swing.Timer(1500, null);
        timer.addActionListener(e -> {
            if (!polling.compareAndSet(false, true)) return;
            long since = lastSeq;
            new SwingWorker<Object, Void>() {
                @Override protected Object doInBackground() {
                    try { return client.activitySince(since); } catch (Exception ex) { return ex; }
                }
                @Override protected void done() {
                    try {
                        Object r = get();
                        if (r instanceof ActivitySnapshot snap) {
                            if (snap.dropped > 0) {
                                out.append("... (" + snap.dropped + " events aged out of the buffer) ...\n");
                            }
                            if (snap.events != null) {
                                for (ActivityEvent ev : snap.events) {
                                    out.append(formatEvent(ev) + "\n");
                                }
                            }
                            lastSeq = Math.max(lastSeq, snap.latest_seq);
                            out.setCaretPosition(out.getDocument().getLength());
                        } else if (r instanceof Exception ex) {
                            out.append("[feed error] " + ex.getMessage() + "\n");
                        }
                    } catch (Exception ignore) {
                        // never let a rendering hiccup kill the timer
                    } finally {
                        polling.set(false);
                    }
                }
            }.execute();
        });

        startBtn.addActionListener(e -> {
            lastSeq = 0;
            timer.start();
            startBtn.setEnabled(false);
            stopBtn.setEnabled(true);
        });
        stopBtn.addActionListener(e -> {
            timer.stop();
            startBtn.setEnabled(true);
            stopBtn.setEnabled(false);
        });

        JComponent north = form(
                new JLabel("V1 live agent-activity feed: dispatch, iterative steps, and completions in real time."),
                buttonRow(startBtn, stopBtn, clearBtn));
        return withOutput(north, out);
    }

    private static String formatEvent(ActivityEvent ev) {
        String agent = ev.agent == null || ev.agent.isEmpty() ? "" : " {" + ev.agent + "}";
        return "#" + ev.seq + " [" + ev.kind + "]" + agent + " " + ev.message;
    }

    // ------------------------------------------------------------------
    // Small parsing/layout utilities
    // ------------------------------------------------------------------

    private static JPanel buttonRow(Component... buttons) {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 2));
        for (Component b : buttons) p.add(b);
        return p;
    }

    private static Double parseDoubleOrNull(String s) {
        if (s == null || s.isBlank()) return null;
        try { return Double.parseDouble(s.trim()); } catch (NumberFormatException e) { return null; }
    }

    private static int parseIntOr(String s, int fallback) {
        try { return Integer.parseInt(s.trim()); } catch (Exception e) { return fallback; }
    }

    private static void putIntIfPresent(Map<String, Object> m, String key, String text) {
        if (text == null || text.isBlank()) return;
        try { m.put(key, Integer.parseInt(text.trim())); } catch (NumberFormatException ignore) { }
    }
}
