package com.hackathon.securitymonitor;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;

class IncidentServiceTest {

    @Test
    void multipleEventsWithinTenSecondsAreGroupedIntoOneIncident() {
        IncidentService incidentService = new IncidentService(10);
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
        IncidentService incidentService = new IncidentService(10);
        LocalDateTime baseTime = LocalDateTime.of(2026, 9, 24, 10, 0, 0);

        Incident firstIncident = incidentService.recordEvent(Path.of("/tmp/fileA.txt"), baseTime.plusSeconds(1));
        Incident secondIncident = incidentService.recordEvent(Path.of("/tmp/fileB.txt"), baseTime.plusSeconds(12));

        assertNotSame(firstIncident, secondIncident);
        assertEquals(1, firstIncident.getEventCount());
        assertEquals(1, secondIncident.getEventCount());
    }

    @Test
    void sameFileDoesNotDuplicateInAffectedFiles() {
        IncidentService incidentService = new IncidentService(10);
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
        IncidentService incidentService = new IncidentService(10);
        Incident incident = incidentService.recordEvent(Path.of("/tmp/fileA.txt"), LocalDateTime.of(2026, 9, 24, 10, 0, 1));

        assertEquals("LOW", incident.getSeverity());
    }

    @Test
    void threeEventsThreeFilesIsMediumSeverity() {
        IncidentService incidentService = new IncidentService(10);
        LocalDateTime baseTime = LocalDateTime.of(2026, 9, 24, 10, 0, 0);

        Incident incident = incidentService.recordEvent(Path.of("/tmp/fileA.txt"), baseTime.plusSeconds(1));
        incidentService.recordEvent(Path.of("/tmp/fileB.txt"), baseTime.plusSeconds(2));
        incidentService.recordEvent(Path.of("/tmp/fileC.txt"), baseTime.plusSeconds(3));

        assertEquals("MEDIUM", incident.getSeverity());
    }

    @Test
    void sixEventsSixFilesIsHighSeverity() {
        IncidentService incidentService = new IncidentService(10);
        LocalDateTime baseTime = LocalDateTime.of(2026, 9, 24, 10, 0, 0);

        Incident incident = null;
        for (int i = 1; i <= 6; i++) {
            incident = incidentService.recordEvent(Path.of("/tmp/file" + i + ".txt"), baseTime.plusSeconds(i));
        }

        assertEquals("HIGH", incident.getSeverity());
    }

    @Test
    void moreThanTenEventsIsCriticalSeverity() {
        IncidentService incidentService = new IncidentService(10);
        LocalDateTime baseTime = LocalDateTime.of(2026, 9, 24, 10, 0, 0);

        Incident incident = null;
        for (int i = 1; i <= 11; i++) {
            incident = incidentService.recordEvent(Path.of("/tmp/event" + i + ".txt"), baseTime.plusSeconds(i));
        }

        assertEquals("CRITICAL", incident.getSeverity());
    }

    @Test
    void moreThanTenAffectedFilesIsCriticalSeverity() {
        IncidentService incidentService = new IncidentService(10);
        LocalDateTime baseTime = LocalDateTime.of(2026, 9, 24, 10, 0, 0);

        Incident incident = null;
        for (int i = 1; i <= 11; i++) {
            incident = incidentService.recordEvent(Path.of("/tmp/file" + i + ".txt"), baseTime.plusSeconds(i));
        }

        assertEquals("CRITICAL", incident.getSeverity());
    }

    @Test
    void severityReasonIsNotEmpty() {
        IncidentService incidentService = new IncidentService(10);
        LocalDateTime baseTime = LocalDateTime.of(2026, 9, 24, 10, 0, 0);

        Incident incident = incidentService.recordEvent(Path.of("/tmp/fileA.txt"), baseTime.plusSeconds(1));
        incidentService.recordEvent(Path.of("/tmp/fileB.txt"), baseTime.plusSeconds(2));
        incidentService.recordEvent(Path.of("/tmp/fileC.txt"), baseTime.plusSeconds(3));

        assertFalse(incident.getSeverityReason().isBlank());
    }

    @Test
    void eventCountTwoAndAffectedFilesSevenResultsInHighSeverity() {
        IncidentService incidentService = new IncidentService(10);
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
        IncidentService incidentService = new IncidentService(10);
        LocalDateTime baseTime = LocalDateTime.of(2026, 9, 24, 10, 0, 0);

        Incident incident = null;
        for (int i = 1; i <= 12; i++) {
            incident = incidentService.recordEvent(Path.of("/tmp/event" + i + ".txt"), baseTime.plusSeconds(i));
        }

        assertEquals("CRITICAL", incident.getSeverity());
    }

    @Test
    void eventCountTwoAndAffectedFilesElevenResultsInCriticalSeverity() {
        IncidentService incidentService = new IncidentService(10);
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
        IncidentService incidentService = new IncidentService(10);
        LocalDateTime baseTime = LocalDateTime.of(2026, 9, 24, 10, 0, 0);

        Incident incident = null;
        for (int i = 1; i <= 11; i++) {
            incident = incidentService.recordEvent(Path.of("/tmp/file" + i + ".txt"), baseTime.plusSeconds(i));
        }

        assertEquals("CRITICAL", incident.getSeverity());
    }
}
