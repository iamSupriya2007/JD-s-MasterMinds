package com.hackathon.securitymonitor;

import org.bson.Document;
import org.junit.jupiter.api.Test;
import org.springframework.data.domain.Sort;
import org.springframework.data.mongodb.core.FindAndModifyOptions;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuditLogServiceTest {

    private AuditLogService createAuditLogService() {
        AuditLogRepository auditLogRepository = mock(AuditLogRepository.class);
        List<AuditLogEntry> entries = new ArrayList<>();

        when(auditLogRepository.findAll(any(Sort.class))).thenAnswer(invocation -> {
            Sort sort = invocation.getArgument(0);
            List<AuditLogEntry> ordered = new ArrayList<>(entries);
            ordered.sort(Comparator.comparingLong(AuditLogEntry::getSequenceNumber));
            if (sort.getOrderFor("sequenceNumber") != null && sort.getOrderFor("sequenceNumber").isDescending()) {
                ordered.sort(Comparator.comparingLong(AuditLogEntry::getSequenceNumber).reversed());
            }
            return ordered;
        });

        when(auditLogRepository.save(any(AuditLogEntry.class))).thenAnswer(invocation -> {
            AuditLogEntry entry = invocation.getArgument(0);
            entries.removeIf(existing -> existing.getSequenceNumber() == entry.getSequenceNumber());
            entries.add(entry);
            return entry;
        });

        return new AuditLogService(auditLogRepository, mock(MongoTemplate.class));
    }

    @Test
    void firstEntryUsesGenesisHash() {
        AuditLogService auditLogService = createAuditLogService();

        AuditLogEntry entry = auditLogService.appendEntry("INC-1", "FILE_CHANGED", "/tmp/fileA.txt", "HIGH");

        assertEquals("GENESIS", entry.getPreviousHash());
    }

    @Test
    void secondEntryPointsToFirstEntryHash() {
        AuditLogService auditLogService = createAuditLogService();

        AuditLogEntry firstEntry = auditLogService.appendEntry("INC-1", "FILE_CHANGED", "/tmp/fileA.txt", "HIGH");
        AuditLogEntry secondEntry = auditLogService.appendEntry("INC-1", "FILE_CHANGED", "/tmp/fileB.txt", "MEDIUM");

        assertEquals(firstEntry.getCurrentHash(), secondEntry.getPreviousHash());
    }

    @Test
    void verifyChainRemainsTrueAfterTimestampRoundTrip() {
        AuditLogService auditLogService = createAuditLogService();

        AuditLogEntry entry = auditLogService.appendEntry("INC-1", "FILE_CHANGED", "/tmp/fileA.txt", "HIGH");
        entry.setTimestamp(entry.getTimestamp().truncatedTo(ChronoUnit.MILLIS));

        assertTrue(auditLogService.verifyChain());
    }

    @Test
    void legacyAuditChainCanBeMigratedWithoutDeletingRecords() {
        AuditLogRepository auditLogRepository = mock(AuditLogRepository.class);
        List<AuditLogEntry> persistedEntries = new ArrayList<>();

        LocalDateTime firstTimestamp = LocalDateTime.of(2024, 1, 2, 3, 4, 5, 123_456_789);
        LocalDateTime secondTimestamp = LocalDateTime.of(2024, 1, 2, 3, 5, 6, 987_654_321);

        String legacyFirstHash = calculateHashForLegacyTimestamp(1L, firstTimestamp, "INC-1", "FILE_CHANGED", "/tmp/fileA.txt", "HIGH", "GENESIS");
        String legacySecondHash = calculateHashForLegacyTimestamp(2L, secondTimestamp, "INC-1", "FILE_CHANGED", "/tmp/fileB.txt", "MEDIUM", legacyFirstHash);

        AuditLogEntry firstLeg = new AuditLogEntry(1L, firstTimestamp, "INC-1", "FILE_CHANGED", "/tmp/fileA.txt", "HIGH", "GENESIS", legacyFirstHash);
        AuditLogEntry secondLeg = new AuditLogEntry(2L, secondTimestamp, "INC-1", "FILE_CHANGED", "/tmp/fileB.txt", "MEDIUM", legacyFirstHash, legacySecondHash);
        persistedEntries.add(firstLeg);
        persistedEntries.add(secondLeg);

        when(auditLogRepository.findAll(any(Sort.class))).thenAnswer(invocation -> {
            Sort sort = invocation.getArgument(0);
            List<AuditLogEntry> ordered = new ArrayList<>(persistedEntries);
            ordered.sort(Comparator.comparingLong(AuditLogEntry::getSequenceNumber));
            if (sort.getOrderFor("sequenceNumber") != null && sort.getOrderFor("sequenceNumber").isDescending()) {
                ordered.sort(Comparator.comparingLong(AuditLogEntry::getSequenceNumber).reversed());
            }
            return ordered;
        });
        when(auditLogRepository.save(any(AuditLogEntry.class))).thenAnswer(invocation -> {
            AuditLogEntry entry = invocation.getArgument(0);
            persistedEntries.removeIf(existing -> existing.getSequenceNumber() == entry.getSequenceNumber());
            persistedEntries.add(entry);
            return entry;
        });

        AuditLogService auditLogService = new AuditLogService(auditLogRepository, mock(MongoTemplate.class));

        assertTrue(auditLogService.migrateLegacyChain());
        assertTrue(auditLogService.verifyChain());
        assertEquals("GENESIS", persistedEntries.get(0).getPreviousHash());
        assertEquals(persistedEntries.get(0).getCurrentHash(), persistedEntries.get(1).getPreviousHash());
    }

    @Test
    void duplicateSequenceNumbersAreRebuiltAndVerifiedWithoutLosingRecords() {
        AuditLogRepository auditLogRepository = mock(AuditLogRepository.class);
        List<AuditLogEntry> persistedEntries = new ArrayList<>();

        LocalDateTime firstTimestamp = LocalDateTime.of(2024, 1, 2, 3, 4, 5, 123_456_789);
        LocalDateTime secondTimestamp = LocalDateTime.of(2024, 1, 2, 3, 5, 6, 987_654_321);
        LocalDateTime thirdTimestamp = LocalDateTime.of(2024, 1, 2, 3, 6, 7, 222_333_444);

        String firstHash = calculateHashForLegacyTimestamp(1L, firstTimestamp, "INC-1", "FILE_CHANGED", "/tmp/fileA.txt", "HIGH", "GENESIS");
        String secondHash = calculateHashForLegacyTimestamp(2L, secondTimestamp, "INC-1", "FILE_CHANGED", "/tmp/fileB.txt", "MEDIUM", firstHash);
        String thirdHash = calculateHashForLegacyTimestamp(3L, thirdTimestamp, "INC-1", "FILE_CHANGED", "/tmp/fileC.txt", "LOW", secondHash);

        persistedEntries.add(new AuditLogEntry(1L, firstTimestamp, "INC-1", "FILE_CHANGED", "/tmp/fileA.txt", "HIGH", "GENESIS", firstHash));
        persistedEntries.add(new AuditLogEntry(2L, secondTimestamp, "INC-1", "FILE_CHANGED", "/tmp/fileB.txt", "MEDIUM", firstHash, secondHash));
        persistedEntries.add(new AuditLogEntry(2L, thirdTimestamp, "INC-1", "FILE_CHANGED", "/tmp/fileC.txt", "LOW", secondHash, thirdHash));

        when(auditLogRepository.findAll(any(Sort.class))).thenAnswer(invocation -> {
            Sort sort = invocation.getArgument(0);
            List<AuditLogEntry> ordered = new ArrayList<>(persistedEntries);
            ordered.sort(Comparator.comparing(AuditLogEntry::getTimestamp).thenComparingLong(AuditLogEntry::getSequenceNumber));
            if (sort.getOrderFor("sequenceNumber") != null && sort.getOrderFor("sequenceNumber").isDescending()) {
                ordered.sort(Comparator.comparing(AuditLogEntry::getTimestamp).thenComparingLong(AuditLogEntry::getSequenceNumber).reversed());
            }
            return ordered;
        });
        when(auditLogRepository.save(any(AuditLogEntry.class))).thenAnswer(invocation -> {
            AuditLogEntry entry = invocation.getArgument(0);
            persistedEntries.removeIf(existing -> existing.getFilePath().equals(entry.getFilePath()) && existing.getTimestamp().equals(entry.getTimestamp()));
            persistedEntries.add(entry);
            return entry;
        });

        AuditLogService auditLogService = new AuditLogService(auditLogRepository, mock(MongoTemplate.class));

        assertTrue(auditLogService.verifyChain());
        assertEquals(List.of(1L, 2L, 3L), persistedEntries.stream().map(AuditLogEntry::getSequenceNumber).sorted().toList());
    }

    @Test
    void sequenceNumberContinuesFromPersistedEntriesAndUsesPreviousHash() {
        AuditLogRepository auditLogRepository = mock(AuditLogRepository.class);
        MongoTemplate mongoTemplate = mock(MongoTemplate.class);

        AuditLogEntry existingEntry = new AuditLogEntry(
                7L,
                LocalDateTime.of(2026, 9, 24, 10, 0, 0).truncatedTo(ChronoUnit.MILLIS),
                "INC-2",
                "FILE_CHANGED",
                "/tmp/fileB.txt",
                "MEDIUM",
                "previous-value",
                "persisted-hash"
        );

        when(auditLogRepository.findAll(any(Sort.class))).thenReturn(List.of(existingEntry));
        when(auditLogRepository.save(any(AuditLogEntry.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(mongoTemplate.findAndModify(any(Query.class), any(Update.class), any(FindAndModifyOptions.class), eq(Document.class), eq("audit_counters")))
                .thenReturn(new Document("_id", "audit_sequence").append("value", 8L));

        AuditLogService auditLogService = new AuditLogService(auditLogRepository, mongoTemplate);
        AuditLogEntry newEntry = auditLogService.appendEntry("INC-2", "FILE_CHANGED", "/tmp/fileC.txt", "HIGH");

        assertEquals(8L, newEntry.getSequenceNumber());
        assertEquals(existingEntry.getCurrentHash(), newEntry.getPreviousHash());
    }

    @Test
    void validChainReturnsTrue() {
        AuditLogService auditLogService = createAuditLogService();

        auditLogService.appendEntry("INC-1", "FILE_CHANGED", "/tmp/fileA.txt", "HIGH");
        auditLogService.appendEntry("INC-1", "FILE_CHANGED", "/tmp/fileB.txt", "MEDIUM");

        assertTrue(auditLogService.verifyChain());
    }

    @Test
    void tamperedCurrentHashCausesVerifyChainToReturnFalse() {
        AuditLogService auditLogService = createAuditLogService();

        AuditLogEntry firstEntry = auditLogService.appendEntry("INC-1", "FILE_CHANGED", "/tmp/fileA.txt", "HIGH");
        AuditLogEntry secondEntry = auditLogService.appendEntry("INC-1", "FILE_CHANGED", "/tmp/fileB.txt", "MEDIUM");

        secondEntry.setCurrentHash("TAMPERED_HASH");

        assertFalse(auditLogService.verifyChain());
    }

    @Test
    void wrongPreviousHashCausesVerifyChainToReturnFalse() {
        AuditLogService auditLogService = createAuditLogService();

        auditLogService.appendEntry("INC-1", "FILE_CHANGED", "/tmp/fileA.txt", "HIGH");
        AuditLogEntry secondEntry = auditLogService.appendEntry("INC-1", "FILE_CHANGED", "/tmp/fileB.txt", "MEDIUM");
        secondEntry.setPreviousHash("TAMPERED");

        assertFalse(auditLogService.verifyChain());
    }

    private String calculateHashForLegacyTimestamp(long sequenceNumber, LocalDateTime timestamp, String incidentId,
                                                  String eventType, String filePath, String severity,
                                                  String previousHash) {
        String payload = sequenceNumber + "|" + timestamp + "|" + incidentId + "|" + eventType + "|"
                + filePath + "|" + severity + "|" + previousHash;
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(payload.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (byte hashByte : hashBytes) {
                String hexValue = Integer.toHexString(0xff & hashByte);
                if (hexValue.length() == 1) {
                    hex.append('0');
                }
                hex.append(hexValue);
            }
            return hex.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not available", e);
        }
    }
}
