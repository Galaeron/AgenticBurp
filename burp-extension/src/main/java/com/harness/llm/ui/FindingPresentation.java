package com.harness.llm.ui;

import com.harness.llm.model.AnalysisModels.Finding;
import java.util.Collection;
import java.util.Set;

/**
 * Server-derived evidence and next action; raw confidence never establishes proof.
 *
 * <p>R16: the single place the Burp panel decides how a finding's verification state reads,
 * so the list row, the detail view and the exported report cannot disagree. The three axes
 * stay separate: impact severity ({@code severity}/{@code impact_severity}), evidence maturity
 * and triage priority (server-derived), and the model's uncalibrated {@code confidence}.
 * A maturity string alone never presents a finding as confirmed: a {@code confirmed*} maturity
 * is honoured only when the harness-owned {@code confirmed} boolean agrees, and missing or
 * unknown values fail safe to {@code unverified}. Vocabulary mirrors
 * {@code harness/confirmation_gate.finding_triage} (checked by a Python parity test).
 *
 * <p>UNBUILT: no JDK was available when this was written; source review only.
 */
public final class FindingPresentation {
    private FindingPresentation() {}
    private static final Set<String> STATES = Set.of("confirmed", "confirmed_observation",
            "controlled_negative", "review_rejected", "unverified", "unverified_no_leg");
    private static final Set<String> PRIORITIES = Set.of("review_confirmed", "review_negative", "manual_verification");

    /** Normalised, fail-safe maturity: unknown/missing -> unverified; confirmed* needs {@code confirmed}. */
    public static String maturity(Finding finding) {
        String maturity = finding.evidence_maturity == null ? "" : finding.evidence_maturity;
        if (!STATES.contains(maturity)) return "unverified";
        if (maturity.startsWith("confirmed") && !finding.confirmed) return "unverified";
        return maturity;
    }

    public static boolean isConfirmed(Finding finding) { return maturity(finding).startsWith("confirmed"); }

    public static boolean isUnverified(Finding finding) { return maturity(finding).startsWith("unverified"); }

    public static String priority(Finding finding) {
        String priority = finding.triage_priority == null ? "" : finding.triage_priority;
        if (!PRIORITIES.contains(priority) || isUnverified(finding)) return "manual_verification";
        return priority;
    }

    public static String evidenceLine(Finding finding) {
        String impact = finding.impact_severity == null ? finding.severity : finding.impact_severity;
        return "Evidence maturity: " + maturity(finding) + "; Triage priority: " + priority(finding)
                + "; Impact severity: " + impact;
    }

    /** Human-readable verification status; same words as the Markdown/SARIF surfaces. */
    public static String stateLabel(Finding finding) {
        if (finding.oracle_verified || "verified".equals(finding.verification_state)) return "ORACLE-VERIFIED";
        switch (maturity(finding)) {
            case "confirmed": return "CONFIRMED (leg fired, not oracle-verified)";
            case "confirmed_observation": return "CONFIRMED OBSERVATION (passive check, not a live exploit)";
            case "controlled_negative": return "NOT CONFIRMED (controlled negative)";
            case "review_rejected": return "NOT CONFIRMED (review rejected or downgraded)";
            case "unverified_no_leg": return "UNVERIFIED (no confirmation leg; manual verification)";
            default: return "UNVERIFIED (confirmation not established; manual verification)";
        }
    }

    /** Per-state counts for the export headline; impact counts are by severity, not by proof. */
    public record Tally(int total, int critical, int high, int confirmed, int unverified, int other) {
        public String headline(int exchanges) {
            return String.format("**%d findings** (%d critical, %d high by impact severity) across %d analyzed exchange(s): "
                    + "**%d confirmed**, **%d unverified (manual verification)**, %d reviewed-negative or rejected.",
                    total, critical, high, exchanges, confirmed, unverified, other);
        }
    }

    public static Tally tally(Collection<Finding> findings) {
        int total = 0, critical = 0, high = 0, confirmed = 0, unverified = 0, other = 0;
        for (Finding finding : findings) {
            total++;
            if ("critical".equals(finding.severity)) critical++;
            if ("high".equals(finding.severity)) high++;
            if (isConfirmed(finding)) confirmed++;
            else if (isUnverified(finding)) unverified++;
            else other++;
        }
        return new Tally(total, critical, high, confirmed, unverified, other);
    }
}
