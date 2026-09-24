package com.hackathon.securitymonitor;

import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuditLogServiceTest {

    @Test
    void firstEntryUsesGenesisHash() {
        AuditLogService auditLogService = new AuditLogService();

        AuditLogEntry entry = auditLogService.appendEntry("INC-1", "FILE_CHANGED", "/tmp/fileA.txt", "HIGH");

        assertEquals("GENESIS", entry.getPreviousHash());
    }

    @Test
    void secondEntryPointsToFirstEntryHash() {
        AuditLogService auditLogService = new AuditLogService();

        AuditLogEntry firstEntry = auditLogService.appendEntry("INC-1", "FILE_CHANGED", "/tmp/fileA.txt", "HIGH");
        AuditLogEntry secondEntry = auditLogService.appendEntry("INC-1", "FILE_CHANGED", "/tmp/fileB.txt", "MEDIUM");

        assertEquals(firstEntry.getCurrentHash(), secondEntry.getPreviousHash());
    }

    @Test
    void validChainReturnsTrue() {
        AuditLogService auditLogService = new AuditLogService();

        auditLogService.appendEntry("INC-1", "FILE_CHANGED", "/tmp/fileA.txt", "HIGH");
        auditLogService.appendEntry("INC-1", "FILE_CHANGED", "/tmp/fileB.txt", "MEDIUM");

        assertTrue(auditLogService.verifyChain());
    }

    @Test
    void tamperedEntryCausesVerifyChainToReturnFalse() {
        AuditLogService auditLogService = new AuditLogService();

        AuditLogEntry firstEntry = auditLogService.appendEntry("INC-1", "FILE_CHANGED", "/tmp/fileA.txt", "HIGH");
        auditLogService.appendEntry("INC-1", "FILE_CHANGED", "/tmp/fileB.txt", "MEDIUM");

        firstEntry.setFilePath("/tmp/tampered.txt");

        assertFalse(auditLogService.verifyChain());
    }

    @Test
    void wrongPreviousHashCausesVerifyChainToReturnFalse() {
        AuditLogService auditLogService = new AuditLogService();

        auditLogService.appendEntry("INC-1", "FILE_CHANGED", "/tmp/fileA.txt", "HIGH");
        AuditLogEntry secondEntry = auditLogService.appendEntry("INC-1", "FILE_CHANGED", "/tmp/fileB.txt", "MEDIUM");
        secondEntry.setPreviousHash("TAMPERED");

        assertFalse(auditLogService.verifyChain());
    }
}
