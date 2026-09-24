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
    private final List<Incident> incidents = new ArrayList<>();
    private final AtomicLong incidentCounter = new AtomicLong(1);

    public IncidentService(@Value("${security-monitor.grouping-window-seconds:10}") long groupingWindowSeconds) {
        this.groupingWindow = Duration.ofSeconds(groupingWindowSeconds);
    }

    public IncidentService() {
        this(10);
    }

    public Incident recordEvent(Path filePath, LocalDateTime eventTime) {
        String normalizedPath = filePath.toAbsolutePath().normalize().toString();
        Incident activeIncident = findActiveIncident(eventTime);

        if (activeIncident != null) {
            activeIncident.addFile(normalizedPath);
            activeIncident.incrementEventCount();
            activeIncident.setLastEventTime(eventTime);
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
