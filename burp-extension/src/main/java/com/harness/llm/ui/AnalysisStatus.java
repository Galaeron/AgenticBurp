package com.harness.llm.ui;

/**
 * Tracks the status of an ongoing or completed analysis.
 * Used to provide real-time feedback to the operator.
 */
public class AnalysisStatus {
    
    public enum Status {
        QUEUED("Queued", "Waiting in queue"),
        ANALYZING("Analyzing", "Analysis in progress"),
        COMPLETED("Completed", "Analysis finished"),
        // X08: the harness returned a result but flagged it degraded -- some
        // model agents or stages failed, so an absent finding is not a clean miss.
        DEGRADED("Degraded", "Analysis finished, but model agents or stages failed"),
        ERROR("Error", "Analysis failed"),
        CANCELLED("Cancelled", "Analysis was cancelled");
        
        private final String displayName;
        private final String description;
        
        Status(String displayName, String description) {
            this.displayName = displayName;
            this.description = description;
        }
        
        public String getDisplayName() { return displayName; }
        public String getDescription() { return description; }

        public boolean isTerminal() {
            return this == COMPLETED || this == DEGRADED || this == ERROR || this == CANCELLED;
        }
    }

    /**
     * Terminal status for a returned analysis: DEGRADED when the harness flagged
     * the result degraded or partial (X08), otherwise COMPLETED. An older server
     * that sends neither field reads as COMPLETED, as before.
     */
    public static Status completionStatus(com.harness.llm.model.AnalysisModels.AnalysisResponse response) {
        if (response != null && (response.degraded || response.partial_inference)) {
            return Status.DEGRADED;
        }
        return Status.COMPLETED;
    }
    
    private final String requestLabel;
    private final String requestId;
    private Status status;
    private int progress; // 0-100
    private String currentAgent;
    private long startTime;
    private long lastUpdateTime;
    private String errorMessage;
    private int findingsCount;
    private int agentsCompleted;
    private int totalAgents;
    
    public AnalysisStatus(String requestLabel, String requestId, int totalAgents) {
        this.requestLabel = requestLabel;
        this.requestId = requestId;
        this.status = Status.QUEUED;
        this.progress = 0;
        this.startTime = System.currentTimeMillis();
        this.lastUpdateTime = this.startTime;
        this.totalAgents = totalAgents;
        this.agentsCompleted = 0;
        this.findingsCount = 0;
    }
    
    public String getRequestLabel() { return requestLabel; }
    public String getRequestId() { return requestId; }
    public Status getStatus() { return status; }
    public int getProgress() { return progress; }
    public String getCurrentAgent() { return currentAgent; }
    public long getStartTime() { return startTime; }
    public long getLastUpdateTime() { return lastUpdateTime; }
    public String getErrorMessage() { return errorMessage; }
    public int getFindingsCount() { return findingsCount; }
    public int getAgentsCompleted() { return agentsCompleted; }
    public int getTotalAgents() { return totalAgents; }
    
    public void setStatus(Status status) {
        this.status = status;
        this.lastUpdateTime = System.currentTimeMillis();
    }
    
    public void setProgress(int progress) {
        this.progress = Math.max(0, Math.min(100, progress));
        this.lastUpdateTime = System.currentTimeMillis();
    }
    
    public void setCurrentAgent(String agent) {
        this.currentAgent = agent;
        this.lastUpdateTime = System.currentTimeMillis();
    }
    
    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
        this.status = Status.ERROR;
        this.lastUpdateTime = System.currentTimeMillis();
    }
    
    public void incrementAgentsCompleted() {
        this.agentsCompleted++;
        this.progress = (int) (((float) agentsCompleted / totalAgents) * 100);
        this.lastUpdateTime = System.currentTimeMillis();
    }
    
    public void addFinding() {
        this.findingsCount++;
        this.lastUpdateTime = System.currentTimeMillis();
    }
    
    public long getElapsedTimeMs() {
        return System.currentTimeMillis() - startTime;
    }
    
    public String getElapsedTimeString() {
        long ms = getElapsedTimeMs();
        if (ms < 1000) {
            return String.format("%dms", ms);
        } else if (ms < 60000) {
            return String.format("%.1fs", ms / 1000.0);
        } else {
            return String.format("%d:%02d", ms / 60000, (ms % 60000) / 1000);
        }
    }
    
    public String getEstimatedTimeRemaining() {
        if (status.isTerminal()) {
            return "";
        }
        if (agentsCompleted == 0) {
            return "Calculating...";
        }
        long avgTimePerAgent = getElapsedTimeMs() / agentsCompleted;
        long remainingAgents = totalAgents - agentsCompleted;
        long estimatedMs = avgTimePerAgent * remainingAgents;
        
        if (estimatedMs < 1000) {
            return String.format("~%dms", estimatedMs);
        } else if (estimatedMs < 60000) {
            return String.format("~%.1fs", estimatedMs / 1000.0);
        } else {
            return String.format("~%d:%02d", estimatedMs / 60000, (estimatedMs % 60000) / 1000);
        }
    }
    
    @Override
    public String toString() {
        return String.format("AnalysisStatus[%s: %s (%d%%) - %s]", 
                requestLabel, status.getDisplayName(), progress, currentAgent);
    }
}
