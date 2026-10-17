package com.harness.llm.ui;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

/**
 * Tracks all ongoing and completed analyses.
 * Provides real-time status updates to the UI.
 */
public class AnalysisTracker {
    
    private final Map<String, AnalysisStatus> activeAnalyses = new ConcurrentHashMap<>();
    private final List<AnalysisStatus> completedAnalyses = new ArrayList<>();
    private final List<Consumer<AnalysisStatus>> statusListeners = new ArrayList<>();
    private final List<Consumer<List<AnalysisStatus>>> bulkListeners = new ArrayList<>();
    
    private int maxCompletedToKeep = 100;
    
    /**
     * Start tracking a new analysis.
     * @param requestLabel Human-readable label for the request
     * @param requestId Unique identifier for the request
     * @param totalAgents Total number of agents that will be run
     * @return The new AnalysisStatus object
     */
    public AnalysisStatus startAnalysis(String requestLabel, String requestId, int totalAgents) {
        AnalysisStatus status = new AnalysisStatus(requestLabel, requestId, totalAgents);
        activeAnalyses.put(requestId, status);
        notifyStatusUpdate(status);
        notifyBulkUpdate();
        return status;
    }
    
    /**
     * Update the status of an ongoing analysis.
     */
    public void updateStatus(String requestId, AnalysisStatus.Status status) {
        AnalysisStatus analysis = activeAnalyses.get(requestId);
        if (analysis != null) {
            analysis.setStatus(status);
            if (status.isTerminal()) {
                activeAnalyses.remove(requestId);
                completedAnalyses.add(0, analysis); // Add to front
                if (completedAnalyses.size() > maxCompletedToKeep) {
                    completedAnalyses.subList(maxCompletedToKeep, completedAnalyses.size()).clear();
                }
            }
            notifyStatusUpdate(analysis);
            notifyBulkUpdate();
        }
    }
    
    /**
     * Update progress for an analysis.
     */
    public void updateProgress(String requestId, int progress) {
        AnalysisStatus analysis = activeAnalyses.get(requestId);
        if (analysis != null) {
            analysis.setProgress(progress);
            notifyStatusUpdate(analysis);
        }
    }
    
    /**
     * Update the current agent being run.
     */
    public void updateCurrentAgent(String requestId, String agent) {
        AnalysisStatus analysis = activeAnalyses.get(requestId);
        if (analysis != null) {
            analysis.setCurrentAgent(agent);
            notifyStatusUpdate(analysis);
        }
    }
    
    /**
     * Increment the count of completed agents.
     */
    public void incrementAgentsCompleted(String requestId) {
        AnalysisStatus analysis = activeAnalyses.get(requestId);
        if (analysis != null) {
            analysis.incrementAgentsCompleted();
            notifyStatusUpdate(analysis);
            notifyBulkUpdate();
        }
    }
    
    /**
     * Add a finding to the analysis.
     */
    public void addFinding(String requestId) {
        AnalysisStatus analysis = activeAnalyses.get(requestId);
        if (analysis != null) {
            analysis.addFinding();
            notifyStatusUpdate(analysis);
        }
    }
    
    /**
     * Set an error message for an analysis.
     */
    public void setError(String requestId, String errorMessage) {
        AnalysisStatus analysis = activeAnalyses.get(requestId);
        if (analysis != null) {
            analysis.setErrorMessage(errorMessage);
            analysis.setStatus(AnalysisStatus.Status.ERROR);
            activeAnalyses.remove(requestId);
            completedAnalyses.add(0, analysis);
            notifyStatusUpdate(analysis);
            notifyBulkUpdate();
        }
    }
    
    /**
     * Cancel an ongoing analysis.
     */
    public void cancelAnalysis(String requestId) {
        AnalysisStatus analysis = activeAnalyses.get(requestId);
        if (analysis != null) {
            analysis.setStatus(AnalysisStatus.Status.CANCELLED);
            activeAnalyses.remove(requestId);
            notifyStatusUpdate(analysis);
            notifyBulkUpdate();
        }
    }
    
    /**
     * Get all active (ongoing) analyses.
     */
    public List<AnalysisStatus> getActiveAnalyses() {
        return new ArrayList<>(activeAnalyses.values());
    }
    
    /**
     * Get all completed analyses.
     */
    public List<AnalysisStatus> getCompletedAnalyses() {
        return new ArrayList<>(completedAnalyses);
    }
    
    /**
     * Get all analyses (active + completed).
     */
    public List<AnalysisStatus> getAllAnalyses() {
        List<AnalysisStatus> all = new ArrayList<>(getActiveAnalyses());
        all.addAll(getCompletedAnalyses());
        return all;
    }
    
    /**
     * Get the status for a specific request.
     */
    public AnalysisStatus getAnalysisStatus(String requestId) {
        AnalysisStatus status = activeAnalyses.get(requestId);
        if (status != null) {
            return status;
        }
        for (AnalysisStatus completed : completedAnalyses) {
            if (completed.getRequestId().equals(requestId)) {
                return completed;
            }
        }
        return null;
    }
    
    /**
     * Check if there are any active analyses.
     */
    public boolean hasActiveAnalyses() {
        return !activeAnalyses.isEmpty();
    }
    
    /**
     * Get the count of active analyses.
     */
    public int getActiveCount() {
        return activeAnalyses.size();
    }
    
    /**
     * Get the count of completed analyses in this session.
     */
    public int getCompletedCount() {
        return completedAnalyses.size();
    }
    
    /**
     * Register a listener for individual status updates.
     */
    public void addStatusListener(Consumer<AnalysisStatus> listener) {
        statusListeners.add(listener);
    }
    
    /**
     * Remove a status listener.
     */
    public void removeStatusListener(Consumer<AnalysisStatus> listener) {
        statusListeners.remove(listener);
    }
    
    /**
     * Register a listener for bulk updates (all analyses).
     */
    public void addBulkListener(Consumer<List<AnalysisStatus>> listener) {
        bulkListeners.add(listener);
    }
    
    /**
     * Remove a bulk listener.
     */
    public void removeBulkListener(Consumer<List<AnalysisStatus>> listener) {
        bulkListeners.remove(listener);
    }
    
    /**
     * Clear all completed analyses.
     */
    public void clearCompleted() {
        completedAnalyses.clear();
        notifyBulkUpdate();
    }
    
    /**
     * Clear all analyses (active and completed).
     */
    public void clearAll() {
        activeAnalyses.clear();
        completedAnalyses.clear();
        notifyBulkUpdate();
    }
    
    private void notifyStatusUpdate(AnalysisStatus status) {
        for (Consumer<AnalysisStatus> listener : statusListeners) {
            try {
                listener.accept(status);
            } catch (Exception e) {
                // Don't let listener exceptions break tracking
            }
        }
    }
    
    private void notifyBulkUpdate() {
        List<AnalysisStatus> all = getAllAnalyses();
        for (Consumer<List<AnalysisStatus>> listener : bulkListeners) {
            try {
                listener.accept(all);
            } catch (Exception e) {
                // Don't let listener exceptions break tracking
            }
        }
    }
    
    /**
     * Set the maximum number of completed analyses to keep in memory.
     */
    public void setMaxCompletedToKeep(int max) {
        this.maxCompletedToKeep = max;
        while (completedAnalyses.size() > maxCompletedToKeep) {
            completedAnalyses.remove(completedAnalyses.size() - 1);
        }
    }
}
