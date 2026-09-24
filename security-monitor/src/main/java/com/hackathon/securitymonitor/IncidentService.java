package com.hackathon.securitymonitor;

import org.bson.Document;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.data.mongodb.core.FindAndModifyOptions;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.stereotype.Service;

import java.nio.file.Path;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class IncidentService {

    private static final String INCIDENT_SEQUENCE_COUNTER_ID = "incident_sequence";
    private static final String INCIDENT_COUNTER_COLLECTION = "incident_counters";
    private static final Pattern INCIDENT_ID_PATTERN = Pattern.compile("INC-(\\d+)");

    private final Duration groupingWindow;
    private final SeverityService severityService;
    private final AuditLogService auditLogService;
    private final MongoTemplate mongoTemplate;
    private final List<Incident> incidents = new ArrayList<>();
    private final AtomicLong incidentCounter = new AtomicLong(1);

    @Autowired
    public IncidentService(@Value("${security-monitor.grouping-window-seconds:10}") long groupingWindowSeconds,
                           AuditLogService auditLogService,
                           MongoTemplate mongoTemplate) {
        this(groupingWindowSeconds, new SeverityService(), auditLogService, mongoTemplate);
    }

    public IncidentService(@Value("${security-monitor.grouping-window-seconds:10}") long groupingWindowSeconds,
                           AuditLogService auditLogService) {
        this(groupingWindowSeconds, new SeverityService(), auditLogService, null);
    }

    public IncidentService(@Value("${security-monitor.grouping-window-seconds:10}") long groupingWindowSeconds) {
        this(groupingWindowSeconds, new SeverityService(), null, null);
    }

    public IncidentService(long groupingWindowSeconds, SeverityService severityService) {
        this(groupingWindowSeconds, severityService, null, null);
    }

    public IncidentService(long groupingWindowSeconds, SeverityService severityService, AuditLogService auditLogService) {
        this(groupingWindowSeconds, severityService, auditLogService, null);
    }

    public IncidentService(long groupingWindowSeconds, SeverityService severityService, AuditLogService auditLogService, MongoTemplate mongoTemplate) {
        this.groupingWindow = Duration.ofSeconds(groupingWindowSeconds);
        this.severityService = severityService;
        this.auditLogService = auditLogService;
        this.mongoTemplate = mongoTemplate;
    }

    public IncidentService() {
        this(10, new SeverityService(), null, null);
    }

    public Incident recordEvent(Path filePath, LocalDateTime eventTime) {
        return recordEvent(filePath, eventTime, "EVENT");
    }

    public Incident recordEvent(Path filePath, LocalDateTime eventTime, String eventType) {
        String normalizedPath = filePath.toAbsolutePath().normalize().toString();
        Incident activeIncident = findActiveIncident(eventTime);

        if (activeIncident != null) {
            activeIncident.addFile(normalizedPath);
            activeIncident.incrementEventCount();
            activeIncident.setLastEventTime(eventTime);
            severityService.applySeverity(activeIncident);
            appendAuditEntry(activeIncident, eventType, normalizedPath);
            return activeIncident;
        }

        long nextIncidentNumber = nextIncidentNumber();
        Incident incident = new Incident(
                "INC-" + nextIncidentNumber,
                eventTime,
                eventTime,
                1,
                new LinkedHashSet<>()
        );
        incident.addFile(normalizedPath);
        incidents.add(incident);
        severityService.applySeverity(incident);
        appendAuditEntry(incident, eventType, normalizedPath);
        return incident;
    }

    private void appendAuditEntry(Incident incident, String eventType, String normalizedPath) {
        String resolvedEventType = (eventType == null || eventType.trim().isEmpty()) ? "EVENT" : eventType.trim();
        if (incident == null || incident.getIncidentId() == null || incident.getSeverity() == null) {
            return;
        }
        auditLogService.appendEntry(incident.getIncidentId(), resolvedEventType, normalizedPath, incident.getSeverity());
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

    private long nextIncidentNumber() {
        long maxIncidentNumber = 0L;
        if (auditLogService != null) {
            for (AuditLogEntry entry : auditLogService.getAuditLog()) {
                Matcher matcher = INCIDENT_ID_PATTERN.matcher(entry.getIncidentId() == null ? "" : entry.getIncidentId());
                if (matcher.matches()) {
                    maxIncidentNumber = Math.max(maxIncidentNumber, Long.parseLong(matcher.group(1)));
                }
            }
        }

        long resolvedStart = Math.max(maxIncidentNumber, incidentCounter.get() - 1);

        if (mongoTemplate == null) {
            long nextValue = resolvedStart + 1;
            incidentCounter.set(nextValue);
            return nextValue;
        }

        for (int attempt = 0; attempt < 10; attempt++) {
            Document existing = mongoTemplate.findOne(
                    Query.query(Criteria.where("_id").is(INCIDENT_SEQUENCE_COUNTER_ID)),
                    Document.class,
                    INCIDENT_COUNTER_COLLECTION
            );

            if (existing == null) {
                try {
                    long nextValue = resolvedStart + 1;
                    mongoTemplate.insert(
                            new Document("_id", INCIDENT_SEQUENCE_COUNTER_ID).append("value", nextValue),
                            INCIDENT_COUNTER_COLLECTION
                    );
                    incidentCounter.set(nextValue);
                    return nextValue;
                } catch (DuplicateKeyException ignored) {
                    // another request created the counter between the findOne and insert.
                }
                continue;
            }

            long currentCounterValue = ((Number) existing.get("value")).longValue();
            if (currentCounterValue <= resolvedStart) {
                Document corrected = mongoTemplate.findAndModify(
                        Query.query(Criteria.where("_id").is(INCIDENT_SEQUENCE_COUNTER_ID)),
                        new Update().set("value", resolvedStart + 1),
                        FindAndModifyOptions.options().returnNew(true),
                        Document.class,
                        INCIDENT_COUNTER_COLLECTION
                );
                if (corrected != null && corrected.get("value") != null) {
                    long nextValue = ((Number) corrected.get("value")).longValue();
                    incidentCounter.set(nextValue);
                    return nextValue;
                }
            }

            Document updated = mongoTemplate.findAndModify(
                    Query.query(Criteria.where("_id").is(INCIDENT_SEQUENCE_COUNTER_ID)),
                    new Update().inc("value", 1),
                    FindAndModifyOptions.options().returnNew(true),
                    Document.class,
                    INCIDENT_COUNTER_COLLECTION
            );

            if (updated != null && updated.get("value") != null) {
                long nextValue = ((Number) updated.get("value")).longValue();
                incidentCounter.set(nextValue);
                return nextValue;
            }
        }

        throw new IllegalStateException("Unable to allocate a unique incident number for " + INCIDENT_SEQUENCE_COUNTER_ID);
    }

    public List<Incident> getIncidents() {
        return new ArrayList<>(incidents);
    }

    public List<Incident> getRecentIncidentsFromAuditLog() {
        if (auditLogService == null) {
            return new ArrayList<>(incidents);
        }

        List<AuditLogEntry> auditLog = auditLogService.getAuditLog();
        if (auditLog == null || auditLog.isEmpty()) {
            return new ArrayList<>(incidents);
        }

        java.util.Map<String, Incident> incidentById = new java.util.LinkedHashMap<>();
        for (AuditLogEntry entry : auditLog) {
            if (entry == null || entry.getIncidentId() == null || entry.getIncidentId().isBlank()) {
                continue;
            }

            Incident incident = incidentById.computeIfAbsent(
                    entry.getIncidentId(),
                    id -> new Incident(id, entry.getTimestamp(), entry.getTimestamp(), 0, new LinkedHashSet<>())
            );

            incident.addFile(entry.getFilePath());
            incident.incrementEventCount();
            if (entry.getTimestamp() != null) {
                if (incident.getStartTime() == null || entry.getTimestamp().isBefore(incident.getStartTime())) {
                    incident.setStartTime(entry.getTimestamp());
                }
                if (incident.getLastEventTime() == null || entry.getTimestamp().isAfter(incident.getLastEventTime())) {
                    incident.setLastEventTime(entry.getTimestamp());
                }
            }
            severityService.applySeverity(incident);
        }

        return incidentById.values().stream()
                .sorted(java.util.Comparator.comparing(Incident::getLastEventTime, java.util.Comparator.nullsLast(java.util.Comparator.naturalOrder())).reversed())
                .toList();
    }

    public Duration getGroupingWindow() {
        return groupingWindow;
    }
}
