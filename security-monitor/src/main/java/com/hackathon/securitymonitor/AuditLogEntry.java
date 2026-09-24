package com.hackathon.securitymonitor;

import java.time.LocalDateTime;

public class AuditLogEntry {

    private long sequenceNumber;
    private LocalDateTime timestamp;
    private String incidentId;
    private String eventType;
    private String filePath;
    private String severity;
    private String previousHash;
    private String currentHash;

    public AuditLogEntry() {
    }

    public AuditLogEntry(long sequenceNumber, LocalDateTime timestamp, String incidentId, String eventType,
                         String filePath, String severity, String previousHash, String currentHash) {
        this.sequenceNumber = sequenceNumber;
        this.timestamp = timestamp;
        this.incidentId = incidentId;
        this.eventType = eventType;
        this.filePath = filePath;
        this.severity = severity;
        this.previousHash = previousHash;
        this.currentHash = currentHash;
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

    public String getPreviousHash() {
        return previousHash;
    }

    public void setPreviousHash(String previousHash) {
        this.previousHash = previousHash;
    }

    public String getCurrentHash() {
        return currentHash;
    }

    public void setCurrentHash(String currentHash) {
        this.currentHash = currentHash;
    }
}
