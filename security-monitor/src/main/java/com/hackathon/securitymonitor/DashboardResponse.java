package com.hackathon.securitymonitor;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

public class DashboardResponse {

    private SystemStatus systemStatus;
    private Summary summary;
    private List<RecentAuditEvent> recentActivity;
    private List<RecentIncident> recentIncidents;

    public SystemStatus getSystemStatus() {
        return systemStatus;
    }

    public void setSystemStatus(SystemStatus systemStatus) {
        this.systemStatus = systemStatus;
    }

    public Summary getSummary() {
        return summary;
    }

    public void setSummary(Summary summary) {
        this.summary = summary;
    }

    public List<RecentAuditEvent> getRecentActivity() {
        return recentActivity;
    }

    public void setRecentActivity(List<RecentAuditEvent> recentActivity) {
        this.recentActivity = recentActivity;
    }

    public List<RecentIncident> getRecentIncidents() {
        return recentIncidents;
    }

    public void setRecentIncidents(List<RecentIncident> recentIncidents) {
        this.recentIncidents = recentIncidents;
    }

    public static class SystemStatus {
        private String monitoringStatus;
        private String auditChainVerificationStatus;

        public String getMonitoringStatus() {
            return monitoringStatus;
        }

        public void setMonitoringStatus(String monitoringStatus) {
            this.monitoringStatus = monitoringStatus;
        }

        public String getAuditChainVerificationStatus() {
            return auditChainVerificationStatus;
        }

        public void setAuditChainVerificationStatus(String auditChainVerificationStatus) {
            this.auditChainVerificationStatus = auditChainVerificationStatus;
        }
    }

    public static class Summary {
        private long totalAuditEvents;
        private long totalIncidents;
        private Map<String, Long> severityCounts;
        private long latestAuditSequenceNumber;

        public long getTotalAuditEvents() {
            return totalAuditEvents;
        }

        public void setTotalAuditEvents(long totalAuditEvents) {
            this.totalAuditEvents = totalAuditEvents;
        }

        public long getTotalIncidents() {
            return totalIncidents;
        }

        public void setTotalIncidents(long totalIncidents) {
            this.totalIncidents = totalIncidents;
        }

        public Map<String, Long> getSeverityCounts() {
            return severityCounts;
        }

        public void setSeverityCounts(Map<String, Long> severityCounts) {
            this.severityCounts = severityCounts;
        }

        public long getLatestAuditSequenceNumber() {
            return latestAuditSequenceNumber;
        }

        public void setLatestAuditSequenceNumber(long latestAuditSequenceNumber) {
            this.latestAuditSequenceNumber = latestAuditSequenceNumber;
        }
    }

    public static class RecentAuditEvent {
        private long sequenceNumber;
        private LocalDateTime timestamp;
        private String incidentId;
        private String eventType;
        private String filePath;
        private String severity;

        public RecentAuditEvent() {
        }

        public RecentAuditEvent(long sequenceNumber, LocalDateTime timestamp, String incidentId,
                                String eventType, String filePath, String severity) {
            this.sequenceNumber = sequenceNumber;
            this.timestamp = timestamp;
            this.incidentId = incidentId;
            this.eventType = eventType;
            this.filePath = filePath;
            this.severity = severity;
        }

        public long getSequenceNumber() {
            return sequenceNumber;
        }

        public void setSequenceNumber(long sequenceNumber) {
            this.sequenceNumber = sequenceNumber;
        }

        public LocalDateTime getTimestamp() {
            return timestamp;
        }

        public void setTimestamp(LocalDateTime timestamp) {
            this.timestamp = timestamp;
        }

        public String getIncidentId() {
            return incidentId;
        }

        public void setIncidentId(String incidentId) {
            this.incidentId = incidentId;
        }

        public String getEventType() {
            return eventType;
        }

        public void setEventType(String eventType) {
            this.eventType = eventType;
        }

        public String getFilePath() {
            return filePath;
        }

        public void setFilePath(String filePath) {
            this.filePath = filePath;
        }

        public String getSeverity() {
            return severity;
        }

        public void setSeverity(String severity) {
            this.severity = severity;
        }
    }

    public static class RecentIncident {
        private String incidentId;
        private LocalDateTime startTime;
        private LocalDateTime lastEventTime;
        private int eventCount;
        private List<String> affectedFiles;
        private String severity;
        private String severityReason;

        public RecentIncident() {
        }

        public RecentIncident(String incidentId, LocalDateTime startTime, LocalDateTime lastEventTime,
                             int eventCount, List<String> affectedFiles, String severity, String severityReason) {
            this.incidentId = incidentId;
            this.startTime = startTime;
            this.lastEventTime = lastEventTime;
            this.eventCount = eventCount;
            this.affectedFiles = affectedFiles;
            this.severity = severity;
            this.severityReason = severityReason;
        }

        public String getIncidentId() {
            return incidentId;
        }

        public void setIncidentId(String incidentId) {
            this.incidentId = incidentId;
        }

        public LocalDateTime getStartTime() {
            return startTime;
        }

        public void setStartTime(LocalDateTime startTime) {
            this.startTime = startTime;
        }

        public LocalDateTime getLastEventTime() {
            return lastEventTime;
        }

        public void setLastEventTime(LocalDateTime lastEventTime) {
            this.lastEventTime = lastEventTime;
        }

        public int getEventCount() {
            return eventCount;
        }

        public void setEventCount(int eventCount) {
            this.eventCount = eventCount;
        }

        public List<String> getAffectedFiles() {
            return affectedFiles;
        }

        public void setAffectedFiles(List<String> affectedFiles) {
            this.affectedFiles = affectedFiles;
        }

        public String getSeverity() {
            return severity;
        }

        public void setSeverity(String severity) {
            this.severity = severity;
        }

        public String getSeverityReason() {
            return severityReason;
        }

        public void setSeverityReason(String severityReason) {
            this.severityReason = severityReason;
        }
    }
}
