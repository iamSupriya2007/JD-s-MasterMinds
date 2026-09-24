package com.hackathon.securitymonitor;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DashboardServiceTest {

    @Mock
    private AuditLogService auditLogService;

    @Mock
    private IncidentService incidentService;

    @Mock
    private FileSystemWatcher fileSystemWatcher;

    @InjectMocks
    private DashboardService dashboardService;

    @Test
    void getDashboardReturnsSummaryAndRecentEvents() {
        LocalDateTime first = LocalDateTime.of(2026, 9, 24, 12, 0, 0);

        AuditLogEntry firstEntry = new AuditLogEntry(
                1L,
                first,
                "INC-1",
                "ENTRY_CREATE",
                "/tmp/example.txt",
                "LOW",
                "GENESIS",
                "hash-1"
        );
        AuditLogEntry secondEntry = new AuditLogEntry(
                2L,
                first.plusMinutes(1),
                "INC-1",
                "ENTRY_MODIFY",
                "/tmp/example.txt",
                "HIGH",
                "hash-1",
                "hash-2"
        );

        when(auditLogService.getAuditLog()).thenReturn(List.of(firstEntry, secondEntry));
        when(auditLogService.verifyChain()).thenReturn(true);
        when(fileSystemWatcher.isMonitoringActive()).thenReturn(true);

        Incident incident = new Incident(
                "INC-1",
                first,
                first.plusMinutes(1),
                2,
                new java.util.LinkedHashSet<>(Set.of("/tmp/example.txt"))
        );
        incident.setSeverity("HIGH");
        incident.setSeverityReason("Multiple file changes detected within a short time window.");
        when(incidentService.getIncidents()).thenReturn(List.of());
        when(incidentService.getRecentIncidentsFromAuditLog()).thenReturn(List.of(incident));

        DashboardResponse response = dashboardService.getDashboard();

        assertEquals("ACTIVE", response.getSystemStatus().getMonitoringStatus());
        assertEquals("VALID", response.getSystemStatus().getAuditChainVerificationStatus());
        assertEquals(2L, response.getSummary().getTotalAuditEvents());
        assertEquals(1L, response.getSummary().getTotalIncidents());
        assertEquals(1L, response.getSummary().getSeverityCounts().get("LOW"));
        assertEquals(1L, response.getSummary().getSeverityCounts().get("HIGH"));
        assertEquals(2L, response.getSummary().getLatestAuditSequenceNumber());
        assertEquals(2, response.getRecentActivity().size());
        assertEquals("INC-1", response.getRecentIncidents().get(0).getIncidentId());
    }
}
