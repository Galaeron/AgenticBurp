package com.harness.llm.ui;

import javax.swing.*;
import java.awt.*;
import java.util.List;
import java.util.function.Consumer;

/**
 * Panel that displays real-time progress of ongoing analyses.
 * Shows active analyses with progress bars and status.
 */
public class ProgressPanel extends JPanel {
    
    private final AnalysisTracker tracker;
    private final DefaultListModel<AnalysisStatus> listModel;
    private final JList<AnalysisStatus> progressList;
    private final JLabel statusLabel;
    
    public ProgressPanel(AnalysisTracker tracker) {
        this.tracker = tracker;
        this.listModel = new DefaultListModel<>();
        this.progressList = new JList<>(listModel);
        this.statusLabel = new JLabel("No active analyses", SwingConstants.CENTER);
        
        setLayout(new BorderLayout());
        setBorder(BorderFactory.createTitledBorder("Active Analysis"));
        setPreferredSize(new Dimension(400, 200));
        
        // Setup list
        progressList.setCellRenderer(new ProgressCellRenderer());
        progressList.setVisibleRowCount(5);
        JScrollPane scrollPane = new JScrollPane(progressList);
        add(scrollPane, BorderLayout.CENTER);
        
        // Setup status label
        statusLabel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        add(statusLabel, BorderLayout.SOUTH);
        
        // Register listeners
        tracker.addStatusListener(this::updateStatus);
        tracker.addBulkListener(this::updateAll);
        
        // Initial update
        updateAll(tracker.getAllAnalyses());
    }
    
    private void updateStatus(AnalysisStatus status) {
        SwingUtilities.invokeLater(() -> {
            updateList();
            updateStatusLabel();
        });
    }
    
    private void updateAll(List<AnalysisStatus> analyses) {
        SwingUtilities.invokeLater(() -> {
            updateList();
            updateStatusLabel();
        });
    }
    
    private void updateList() {
        listModel.clear();
        for (AnalysisStatus status : tracker.getActiveAnalyses()) {
            listModel.addElement(status);
        }
        
        if (listModel.isEmpty()) {
            statusLabel.setText("No active analyses");
        }
    }
    
    private void updateStatusLabel() {
        int activeCount = tracker.getActiveCount();
        int completedCount = tracker.getCompletedCount();
        
        if (activeCount > 0) {
            statusLabel.setText(String.format("%d analysis(es) in progress, %d completed", 
                    activeCount, completedCount));
        } else if (completedCount > 0) {
            statusLabel.setText(String.format("All analyses complete (%d total)", completedCount));
        } else {
            statusLabel.setText("No analyses yet");
        }
    }
    
    /**
     * Custom cell renderer for progress items.
     */
    private static class ProgressCellRenderer extends DefaultListCellRenderer {
        @Override
        public Component getListCellRendererComponent(JList<?> list, Object value, 
                                                        int index, boolean isSelected, boolean cellHasFocus) {
            if (value instanceof AnalysisStatus status) {
                return new ProgressCell(status, isSelected, cellHasFocus, list.getBackground());
            }
            return super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
        }
    }
    
    /**
     * Custom cell component for displaying analysis progress.
     */
    private static class ProgressCell extends JPanel {
        public ProgressCell(AnalysisStatus status, boolean isSelected, boolean hasFocus, Color listBackground) {
            setLayout(new BorderLayout(5, 5));
            setBorder(BorderFactory.createEmptyBorder(2, 2, 2, 2));
            
            if (isSelected) {
                setBackground(new Color(200, 220, 255));
            } else {
                setBackground(listBackground);
            }
            
            // Left side: status icon and label
            JPanel leftPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
            leftPanel.setOpaque(false);
            
            // Status icon
            JLabel iconLabel = new JLabel(getStatusIcon(status.getStatus()));
            leftPanel.add(iconLabel);
            
            // Request label
            JLabel label = new JLabel(status.getRequestLabel());
            leftPanel.add(label);
            
            add(leftPanel, BorderLayout.WEST);
            
            // Center: progress bar
            JProgressBar progressBar = new JProgressBar(0, 100);
            progressBar.setValue(status.getProgress());
            progressBar.setStringPainted(true);
            progressBar.setString(String.format("%d%%", status.getProgress()));
            
            // Color based on status
            if (status.getStatus() == AnalysisStatus.Status.ERROR) {
                progressBar.setForeground(Color.RED);
            } else if (status.getStatus() == AnalysisStatus.Status.CANCELLED) {
                progressBar.setForeground(Color.GRAY);
            } else if (status.getStatus() == AnalysisStatus.Status.DEGRADED) {
                progressBar.setForeground(Color.ORANGE);
            } else {
                progressBar.setForeground(new Color(0, 128, 0));
            }
            
            add(progressBar, BorderLayout.CENTER);
            
            // Right side: details
            JPanel rightPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
            rightPanel.setOpaque(false);
            
            // Elapsed time
            JLabel timeLabel = new JLabel(status.getElapsedTimeString());
            rightPanel.add(timeLabel);
            
            // Current agent
            if (status.getCurrentAgent() != null && !status.getCurrentAgent().isEmpty()) {
                JLabel agentLabel = new JLabel("Agent: " + status.getCurrentAgent());
                agentLabel.setFont(new Font(agentLabel.getFont().getName(), Font.ITALIC, 
                        agentLabel.getFont().getSize() - 1));
                rightPanel.add(agentLabel);
            }
            
            // Findings count
            if (status.getFindingsCount() > 0) {
                JLabel findingsLabel = new JLabel(String.format("%d findings", status.getFindingsCount()));
                findingsLabel.setForeground(new Color(0, 100, 0));
                rightPanel.add(findingsLabel);
            }
            
            // Estimated time remaining
            String eta = status.getEstimatedTimeRemaining();
            if (!eta.isEmpty()) {
                JLabel etaLabel = new JLabel("ETA: " + eta);
                etaLabel.setFont(new Font(etaLabel.getFont().getName(), Font.ITALIC, 
                        etaLabel.getFont().getSize() - 1));
                rightPanel.add(etaLabel);
            }
            
            add(rightPanel, BorderLayout.EAST);
        }
        
        private String getStatusIcon(AnalysisStatus.Status status) {
            return switch (status) {
                case QUEUED -> "⏳";
                case ANALYZING -> "🔄";
                case COMPLETED -> "✅";
                case DEGRADED -> "⚠️";
                case ERROR -> "❌";
                case CANCELLED -> "⏹️";
            };
        }
    }
}
