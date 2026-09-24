package com.hackathon.securitymonitor;

import org.bson.Document;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.data.mongodb.core.FindAndModifyOptions;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;

import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;

class IncidentServiceTest {

    private IncidentService newIncidentService() {
        AuditLogService auditLogService = Mockito.mock(AuditLogService.class);
        return new IncidentService(10, new SeverityService(), auditLogService);
    }

    @Test
    void incidentNumberingContinuesAfterPersistedIncidentIds() {
        AuditLogService auditLogService = Mockito.mock(AuditLogService.class);
        MongoTemplate mongoTemplate = Mockito.mock(MongoTemplate.class);
        Mockito.when(auditLogService.getAuditLog()).thenReturn(List.of(
                new AuditLogEntry(1L, LocalDateTime.of(2026, 9, 24, 10, 0, 0), "INC-1", "FILE_CHANGED", "/tmp/fileA.txt", "LOW", "GENESIS", "hash-1"),
                new AuditLogEntry(2L, LocalDateTime.of(2026, 9, 24, 10, 0, 1), "INC-2", "FILE_CHANGED", "/tmp/fileB.txt", "LOW", "hash-1", "hash-2")
        ));
        Mockito.when(mongoTemplate.findAndModify(
                org.mockito.ArgumentMatchers.any(Query.class),
                org.mockito.ArgumentMatchers.any(Update.class),
                org.mockito.ArgumentMatchers.any(FindAndModifyOptions.class),
                org.mockito.ArgumentMatchers.eq(Document.class),
                org.mockito.ArgumentMatchers.eq("incident_counters")))
                .thenReturn(new Document("_id", "incident_sequence").append("value", 3L));

        IncidentService incidentService = new IncidentService(10, new SeverityService(), auditLogService, mongoTemplate);
        Incident incident = incidentService.recordEvent(Path.of("/tmp/fileC.txt"), LocalDateTime.of(2026, 9, 24, 10, 0, 2));

        assertEquals("INC-3", incident.getIncidentId());
    }

    @Test
    void multipleEventsWithinTenSecondsAreGroupedIntoOneIncident() {
        IncidentService incidentService = newIncidentService();
        LocalDateTime baseTime = LocalDateTime.of(2026, 9, 24, 10, 0, 0);

        Incident firstIncident = incidentService.recordEvent(Path.of("/tmp/fileA.txt"), baseTime.plusSeconds(1));
        Incident secondIncident = incidentService.recordEvent(Path.of("/tmp/fileB.txt"), baseTime.plusSeconds(3));
        Incident thirdIncident = incidentService.recordEvent(Path.of("/tmp/fileC.txt"), baseTime.plusSeconds(6));

        assertSame(firstIncident, secondIncident);
        assertSame(firstIncident, thirdIncident);
        assertEquals(3, firstIncident.getEventCount());
        assertEquals(3, firstIncident.getAffectedFiles().size());
    }

    @Test
    void eventAfterTenSecondWindowCreatesNewIncident() {
        IncidentService incidentService = newIncidentService();
        LocalDateTime baseTime = LocalDateTime.of(2026, 9, 24, 10, 0, 0);

        Incident firstIncident = incidentService.recordEvent(Path.of("/tmp/fileA.txt"), baseTime.plusSeconds(1));
        Incident secondIncident = incidentService.recordEvent(Path.of("/tmp/fileB.txt"), baseTime.plusSeconds(12));

        assertNotSame(firstIncident, secondIncident);
        assertEquals(1, firstIncident.getEventCount());
        assertEquals(1, secondIncident.getEventCount());
    }

    @Test
    void sameFileDoesNotDuplicateInAffectedFiles() {
        IncidentService incidentService = newIncidentService();
        LocalDateTime baseTime = LocalDateTime.of(2026, 9, 24, 10, 0, 0);

        Incident firstIncident = incidentService.recordEvent(Path.of("/tmp/fileA.txt"), baseTime.plusSeconds(1));
        Incident secondIncident = incidentService.recordEvent(Path.of("/tmp/fileA.txt"), baseTime.plusSeconds(4));
        Incident thirdIncident = incidentService.recordEvent(Path.of("/tmp/fileB.txt"), baseTime.plusSeconds(7));

        assertSame(firstIncident, secondIncident);
        assertSame(firstIncident, thirdIncident);
        assertEquals(2, firstIncident.getAffectedFiles().size());
        assertEquals(3, firstIncident.getEventCount());
    }

    @Test
    void oneEventOneFileIsLowSeverity() {
        IncidentService incidentService = newIncidentService();
        Incident incident = incidentService.recordEvent(Path.of("/tmp/fileA.txt"), LocalDateTime.of(2026, 9, 24, 10, 0, 1));

        assertEquals("LOW", incident.getSeverity());
    }

    @Test
    void threeEventsThreeFilesIsMediumSeverity() {
        IncidentService incidentService = newIncidentService();
        LocalDateTime baseTime = LocalDateTime.of(2026, 9, 24, 10, 0, 0);

        Incident incident = incidentService.recordEvent(Path.of("/tmp/fileA.txt"), baseTime.plusSeconds(1));
        incidentService.recordEvent(Path.of("/tmp/fileB.txt"), baseTime.plusSeconds(2));
        incidentService.recordEvent(Path.of("/tmp/fileC.txt"), baseTime.plusSeconds(3));

        assertEquals("MEDIUM", incident.getSeverity());
    }

    @Test
    void sixEventsSixFilesIsHighSeverity() {
        IncidentService incidentService = newIncidentService();
        LocalDateTime baseTime = LocalDateTime.of(2026, 9, 24, 10, 0, 0);

        Incident incident = null;
        for (int i = 1; i <= 6; i++) {
            incident = incidentService.recordEvent(Path.of("/tmp/file" + i + ".txt"), baseTime.plusSeconds(i));
        }

        assertEquals("HIGH", incident.getSeverity());
    }

    @Test
    void moreThanTenEventsIsCriticalSeverity() {
        IncidentService incidentService = newIncidentService();
        LocalDateTime baseTime = LocalDateTime.of(2026, 9, 24, 10, 0, 0);

        Incident incident = null;
        for (int i = 1; i <= 11; i++) {
            incident = incidentService.recordEvent(Path.of("/tmp/event" + i + ".txt"), baseTime.plusSeconds(i));
        }

        assertEquals("CRITICAL", incident.getSeverity());
    }

    @Test
    void moreThanTenAffectedFilesIsCriticalSeverity() {
        IncidentService incidentService = newIncidentService();
        LocalDateTime baseTime = LocalDateTime.of(2026, 9, 24, 10, 0, 0);

        Incident incident = null;
        for (int i = 1; i <= 11; i++) {
            incident = incidentService.recordEvent(Path.of("/tmp/file" + i + ".txt"), baseTime.plusSeconds(i));
        }

        assertEquals("CRITICAL", incident.getSeverity());
    }

    @Test
    void severityReasonIsNotEmpty() {
        IncidentService incidentService = newIncidentService();
        LocalDateTime baseTime = LocalDateTime.of(2026, 9, 24, 10, 0, 0);

        Incident incident = incidentService.recordEvent(Path.of("/tmp/fileA.txt"), baseTime.plusSeconds(1));
        incidentService.recordEvent(Path.of("/tmp/fileB.txt"), baseTime.plusSeconds(2));
        incidentService.recordEvent(Path.of("/tmp/fileC.txt"), baseTime.plusSeconds(3));

        assertFalse(incident.getSeverityReason().isBlank());
    }

    @Test
    void eventCountTwoAndAffectedFilesSevenResultsInHighSeverity() {
        IncidentService incidentService = newIncidentService();
        LocalDateTime baseTime = LocalDateTime.of(2026, 9, 24, 10, 0, 0);

        Incident incident = incidentService.recordEvent(Path.of("/tmp/fileA.txt"), baseTime.plusSeconds(1));
        incidentService.recordEvent(Path.of("/tmp/fileB.txt"), baseTime.plusSeconds(2));
        for (int i = 3; i <= 8; i++) {
            incidentService.recordEvent(Path.of("/tmp/file" + i + ".txt"), baseTime.plusSeconds(i));
        }

        assertEquals("HIGH", incident.getSeverity());
    }

    @Test
    void eventCountTwelveAndAffectedFilesOneResultsInCriticalSeverity() {
        IncidentService incidentService = newIncidentService();
        LocalDateTime baseTime = LocalDateTime.of(2026, 9, 24, 10, 0, 0);

        Incident incident = null;
        for (int i = 1; i <= 12; i++) {
            incident = incidentService.recordEvent(Path.of("/tmp/event" + i + ".txt"), baseTime.plusSeconds(i));
        }

        assertEquals("CRITICAL", incident.getSeverity());
    }

    @Test
    void eventCountTwoAndAffectedFilesElevenResultsInCriticalSeverity() {
        IncidentService incidentService = newIncidentService();
        LocalDateTime baseTime = LocalDateTime.of(2026, 9, 24, 10, 0, 0);

        Incident incident = incidentService.recordEvent(Path.of("/tmp/fileA.txt"), baseTime.plusSeconds(1));
        incidentService.recordEvent(Path.of("/tmp/fileB.txt"), baseTime.plusSeconds(2));
        for (int i = 3; i <= 11; i++) {
            incidentService.recordEvent(Path.of("/tmp/file" + i + ".txt"), baseTime.plusSeconds(i));
        }

        assertEquals("CRITICAL", incident.getSeverity());
    }

    @Test
    void eventCountElevenAndAffectedFilesOneResultsInCriticalSeverity() {
        IncidentService incidentService = newIncidentService();
        LocalDateTime baseTime = LocalDateTime.of(2026, 9, 24, 10, 0, 0);

        Incident incident = null;
        for (int i = 1; i <= 11; i++) {
            incident = incidentService.recordEvent(Path.of("/tmp/file" + i + ".txt"), baseTime.plusSeconds(i));
        }

        assertEquals("CRITICAL", incident.getSeverity());
    }
}
