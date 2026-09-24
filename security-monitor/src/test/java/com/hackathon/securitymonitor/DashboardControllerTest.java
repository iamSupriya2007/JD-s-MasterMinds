package com.hackathon.securitymonitor;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(DashboardController.class)
class DashboardControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private DashboardService dashboardService;

    @Test
    void dashboardEndpointReturnsJsonPayload() throws Exception {
        DashboardResponse response = new DashboardResponse();

        DashboardResponse.SystemStatus systemStatus = new DashboardResponse.SystemStatus();
        systemStatus.setMonitoringStatus("ACTIVE");
        systemStatus.setAuditChainVerificationStatus("VALID");

        DashboardResponse.Summary summary = new DashboardResponse.Summary();
        summary.setTotalAuditEvents(2L);
        summary.setTotalIncidents(1L);
        summary.setSeverityCounts(Map.of("LOW", 1L, "MEDIUM", 0L, "HIGH", 1L, "CRITICAL", 0L));
        summary.setLatestAuditSequenceNumber(2L);

        DashboardResponse.RecentAuditEvent event = new DashboardResponse.RecentAuditEvent(
                2L,
                LocalDateTime.of(2026, 9, 24, 12, 0, 0),
                "INC-1",
                "ENTRY_MODIFY",
                "/tmp/example.txt",
                "HIGH"
        );

        DashboardResponse.RecentIncident incident = new DashboardResponse.RecentIncident(
                "INC-1",
                LocalDateTime.of(2026, 9, 24, 11, 55, 0),
                LocalDateTime.of(2026, 9, 24, 12, 0, 0),
                2,
                List.of("/tmp/example.txt"),
                "HIGH",
                "Multiple file changes detected within a short time window."
        );

        response.setSystemStatus(systemStatus);
        response.setSummary(summary);
        response.setRecentActivity(List.of(event));
        response.setRecentIncidents(List.of(incident));

        when(dashboardService.getDashboard()).thenReturn(response);

        mockMvc.perform(get("/api/dashboard"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.systemStatus.monitoringStatus").value("ACTIVE"))
                .andExpect(jsonPath("$.systemStatus.auditChainVerificationStatus").value("VALID"))
                .andExpect(jsonPath("$.summary.totalAuditEvents").value(2))
                .andExpect(jsonPath("$.summary.totalIncidents").value(1))
                .andExpect(jsonPath("$.recentActivity[0].incidentId").value("INC-1"))
                .andExpect(jsonPath("$.recentIncidents[0].incidentId").value("INC-1"));
    }
}
