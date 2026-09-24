package com.hackathon.securitymonitor;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.time.LocalDateTime;

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
}
