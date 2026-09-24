package com.hackathon.securitymonitor;

import java.time.LocalDateTime;
import java.util.LinkedHashSet;
import java.util.Set;

public class Incident {

    private String incidentId;
    private LocalDateTime startTime;
    private LocalDateTime lastEventTime;
    private int eventCount;
    private Set<String> affectedFiles = new LinkedHashSet<>();

    public Incident() {
    }

    public Incident(String incidentId, LocalDateTime startTime, LocalDateTime lastEventTime, int eventCount, Set<String> affectedFiles) {
        this.incidentId = incidentId;
        this.startTime = startTime;
        this.lastEventTime = lastEventTime;
        this.eventCount = eventCount;
        this.affectedFiles = affectedFiles;
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

    public Set<String> getAffectedFiles() {
        return affectedFiles;
    }

    public void setAffectedFiles(Set<String> affectedFiles) {
        this.affectedFiles = affectedFiles;
    }

    public void addFile(String filePath) {
        affectedFiles.add(filePath);
    }

    public void incrementEventCount() {
        eventCount++;
    }
}
