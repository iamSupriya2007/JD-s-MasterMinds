package com.hackathon.securitymonitor;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.file.Path;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class IncidentService {

    private final Duration groupingWindow;
    private final SeverityService severityService;
    private final List<Incident> incidents = new ArrayList<>();
    private final AtomicLong incidentCounter = new AtomicLong(1);

    public IncidentService(@Value("${security-monitor.grouping-window-seconds:10}") long groupingWindowSeconds) {
        this(groupingWindowSeconds, new SeverityService());
    }

    public IncidentService(long groupingWindowSeconds, SeverityService severityService) {
        this.groupingWindow = Duration.ofSeconds(groupingWindowSeconds);
        this.severityService = severityService;
    }

    public IncidentService() {
        this(10, new SeverityService());
    }

    public Incident recordEvent(Path filePath, LocalDateTime eventTime) {
        String normalizedPath = filePath.toAbsolutePath().normalize().toString();
        Incident activeIncident = findActiveIncident(eventTime);

        if (activeIncident != null) {
            activeIncident.addFile(normalizedPath);
            activeIncident.incrementEventCount();
            activeIncident.setLastEventTime(eventTime);
            severityService.applySeverity(activeIncident);
            return activeIncident;
        }

        Incident incident = new Incident(
                "INC-" + incidentCounter.getAndIncrement(),
                eventTime,
                eventTime,
                1,
                new LinkedHashSet<>()
        );
        incident.addFile(normalizedPath);
        incidents.add(incident);
        severityService.applySeverity(incident);
        return incident;
    }

    private Incident findActiveIncident(LocalDateTime eventTime) {
        for (int index = incidents.size() - 1; index >= 0; index--) {
            Incident incident = incidents.get(index);
            Duration elapsed = Duration.between(incident.getLastEventTime(), eventTime);

            if (!elapsed.isNegative() && elapsed.compareTo(groupingWindow) <= 0) {
                return incident;
            }
        }

        return null;
    }

    public List<Incident> getIncidents() {
        return new ArrayList<>(incidents);
    }

    public Duration getGroupingWindow() {
        return groupingWindow;
    }
}
