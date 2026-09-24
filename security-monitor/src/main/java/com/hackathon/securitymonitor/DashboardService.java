package com.hackathon.securitymonitor;

import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class DashboardService {

    private final AuditLogService auditLogService;
    private final IncidentService incidentService;
    private final FileSystemWatcher fileSystemWatcher;

    public DashboardService(AuditLogService auditLogService, IncidentService incidentService, FileSystemWatcher fileSystemWatcher) {
        this.auditLogService = auditLogService;
        this.incidentService = incidentService;
        this.fileSystemWatcher = fileSystemWatcher;
    }

    public DashboardResponse getDashboard() {
        List<AuditLogEntry> auditLog = auditLogService.getAuditLog();
        List<Incident> incidents = incidentService.getIncidents();
        if (incidents == null || incidents.isEmpty()) {
            incidents = incidentService.getRecentIncidentsFromAuditLog();
        }

        Map<String, Long> severityCounts = new LinkedHashMap<>();
        for (String severity : List.of("LOW", "MEDIUM", "HIGH", "CRITICAL")) {
            severityCounts.put(severity, 0L);
        }

        for (AuditLogEntry entry : auditLog) {
            String severity = entry.getSeverity() == null ? "LOW" : entry.getSeverity().toUpperCase();
            if (severityCounts.containsKey(severity)) {
                severityCounts.put(severity, severityCounts.get(severity) + 1L);
            }
        }

        long totalIncidentCount = incidents.size();
        if (totalIncidentCount == 0) {
            Set<String> uniqueIncidentIds = auditLog.stream()
                    .map(AuditLogEntry::getIncidentId)
                    .filter(id -> id != null && !id.isBlank())
                    .collect(Collectors.toCollection(java.util.LinkedHashSet::new));
            totalIncidentCount = uniqueIncidentIds.size();
        }

        DashboardResponse.SystemStatus systemStatus = new DashboardResponse.SystemStatus();
        systemStatus.setMonitoringStatus(fileSystemWatcher != null && fileSystemWatcher.isMonitoringActive() ? "ACTIVE" : "INACTIVE");
        systemStatus.setAuditChainVerificationStatus(auditLogService.verifyChain() ? "VALID" : "INVALID");

        DashboardResponse.Summary summary = new DashboardResponse.Summary();
        summary.setTotalAuditEvents(auditLog.size());
        summary.setTotalIncidents(totalIncidentCount);
        summary.setSeverityCounts(severityCounts);
        summary.setLatestAuditSequenceNumber(
                auditLog.stream().mapToLong(AuditLogEntry::getSequenceNumber).max().orElse(0L)
        );

        List<DashboardResponse.RecentAuditEvent> recentActivity = auditLog.stream()
                .sorted(Comparator.comparingLong(AuditLogEntry::getSequenceNumber).reversed())
                .limit(10)
                .map(entry -> new DashboardResponse.RecentAuditEvent(
                        entry.getSequenceNumber(),
                        entry.getTimestamp(),
                        entry.getIncidentId(),
                        entry.getEventType(),
                        entry.getFilePath(),
                        entry.getSeverity()))
                .toList();

        List<DashboardResponse.RecentIncident> recentIncidents = incidents.stream()
                .sorted(Comparator.comparing(Incident::getLastEventTime, Comparator.nullsLast(Comparator.naturalOrder())).reversed())
                .limit(10)
                .map(incident -> new DashboardResponse.RecentIncident(
                        incident.getIncidentId(),
                        incident.getStartTime(),
                        incident.getLastEventTime(),
                        incident.getEventCount(),
                        incident.getAffectedFiles() == null ? List.of() : List.copyOf(incident.getAffectedFiles()),
                        incident.getSeverity(),
                        incident.getSeverityReason()))
                .toList();

        DashboardResponse response = new DashboardResponse();
        response.setSystemStatus(systemStatus);
        response.setSummary(summary);
        response.setRecentActivity(recentActivity);
        response.setRecentIncidents(recentIncidents);
        return response;
    }
}
