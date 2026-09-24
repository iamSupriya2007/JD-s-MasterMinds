package com.hackathon.securitymonitor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.bson.Document;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.data.domain.Sort;
import org.springframework.data.mongodb.core.FindAndModifyOptions;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;

@Service
public class AuditLogService {

    private static final Logger log = LoggerFactory.getLogger(AuditLogService.class);
    private static final String AUDIT_SEQUENCE_COUNTER_ID = "audit_sequence";
    private static final String AUDIT_COUNTER_COLLECTION = "audit_counters";

    private final AuditLogRepository auditLogRepository;
    private final MongoTemplate mongoTemplate;

    public AuditLogService(AuditLogRepository auditLogRepository, MongoTemplate mongoTemplate) {
        this.auditLogRepository = auditLogRepository;
        this.mongoTemplate = mongoTemplate;
    }

    public AuditLogEntry appendEntry(String incidentId, String eventType, String filePath, String severity) {
        AuditLogEntry latestEntry = auditLogRepository.findAll(Sort.by(Sort.Direction.DESC, "sequenceNumber"))
                .stream()
                .findFirst()
                .orElse(null);
        long sequenceNumber = nextSequenceNumber(latestEntry);
        LocalDateTime timestamp = normalizeTimestamp(LocalDateTime.now());
        String previousHash = latestEntry == null ? "GENESIS" : latestEntry.getCurrentHash();
        String currentHash = calculateHash(sequenceNumber, timestamp, incidentId, eventType, filePath, severity, previousHash);

        AuditLogEntry entry = new AuditLogEntry(sequenceNumber, timestamp, incidentId, eventType, filePath, severity, previousHash, currentHash);
        return auditLogRepository.save(entry);
    }

    public List<AuditLogEntry> getAuditLog() {
        return auditLogRepository.findAll(Sort.by(Sort.Direction.ASC, "sequenceNumber"));
    }

    public boolean verifyChain() {
        List<AuditLogEntry> auditLog = getAuditLog();
        if (auditLog.isEmpty()) {
            return true;
        }

        if (hasDuplicateSequenceNumbers(auditLog) || detectLegacyPrefixLength(auditLog) > 0) {
            log.warn("Detected duplicate or legacy audit sequence data; rebuilding the hash chain using the canonical timestamp format and stable sequence order.");
            boolean migrated = migrateLegacyChain();
            if (!migrated) {
                log.warn("Audit chain migration was not possible; refusing to accept an invalid chain.");
                return false;
            }
            auditLog = getAuditLog();
        }

        for (int index = 0; index < auditLog.size(); index++) {
            AuditLogEntry entry = auditLog.get(index);
            String expectedPreviousHash = index == 0 ? "GENESIS" : auditLog.get(index - 1).getCurrentHash();

            if (entry.getSequenceNumber() != index + 1L) {
                log.warn("Verification failed for sequenceNumber={} due to sequenceNumber/order issue: expected sequenceNumber at index {} to be {}, but record had {}.",
                        entry.getSequenceNumber(), index, index + 1L, entry.getSequenceNumber());
                return false;
            }

            if (index == 0 && !"GENESIS".equals(entry.getPreviousHash())) {
                log.warn("Verification failed for sequenceNumber={} due to GENESIS/previousHash mismatch. Expected GENESIS, but found {}.",
                        entry.getSequenceNumber(), entry.getPreviousHash());
                return false;
            }

            if (index > 0 && !expectedPreviousHash.equals(entry.getPreviousHash())) {
                log.warn("Verification failed for sequenceNumber={} due to previousHash linkage mismatch. Expected previousHash={}, but found {}.",
                        entry.getSequenceNumber(), expectedPreviousHash, entry.getPreviousHash());
                return false;
            }

            LocalDateTime normalizedTimestamp = normalizeTimestamp(entry.getTimestamp());
            String expectedHash = calculateHash(
                    entry.getSequenceNumber(),
                    normalizedTimestamp,
                    entry.getIncidentId(),
                    entry.getEventType(),
                    entry.getFilePath(),
                    entry.getSeverity(),
                    entry.getPreviousHash()
            );

            if (!expectedHash.equals(entry.getCurrentHash())) {
                log.warn("Verification failed for sequenceNumber={} due to recalculated currentHash mismatch. Expected currentHash={}, but found {}.",
                        entry.getSequenceNumber(), expectedHash, entry.getCurrentHash());
                return false;
            }
        }

        return true;
    }

    public boolean migrateLegacyChain() {
        List<AuditLogEntry> auditLog = getAuditLog();
        if (auditLog.isEmpty()) {
            return true;
        }

        if (!hasDuplicateSequenceNumbers(auditLog) && detectLegacyPrefixLength(auditLog) <= 0) {
            log.warn("Legacy audit-chain migration requested, but the stored records do not include a legacy timestamp-precision prefix or duplicate sequence data; refusing migration.");
            return false;
        }

        List<AuditLogEntry> orderedEntries = new java.util.ArrayList<>(auditLog);
        orderedEntries.sort(java.util.Comparator
                .comparing(AuditLogEntry::getTimestamp, java.util.Comparator.nullsLast(java.util.Comparator.naturalOrder()))
                .thenComparingLong(AuditLogEntry::getSequenceNumber));

        String previousHash = "GENESIS";
        long nextSequence = 1L;
        for (AuditLogEntry entry : orderedEntries) {
            entry.setSequenceNumber(nextSequence++);
            entry.setPreviousHash(previousHash);
            entry.setCurrentHash(calculateHash(
                    entry.getSequenceNumber(),
                    normalizeTimestamp(entry.getTimestamp()),
                    entry.getIncidentId(),
                    entry.getEventType(),
                    entry.getFilePath(),
                    entry.getSeverity(),
                    previousHash
            ));
            previousHash = entry.getCurrentHash();
            auditLogRepository.save(entry);
        }

        log.info("Rebuilt {} audit records using the canonical millisecond timestamp format and stable sequence ordering.", orderedEntries.size());
        return true;
    }

    private boolean hasDuplicateSequenceNumbers(List<AuditLogEntry> auditLog) {
        java.util.Set<Long> seenSequences = new java.util.HashSet<>();
        for (AuditLogEntry entry : auditLog) {
            if (!seenSequences.add(entry.getSequenceNumber())) {
                return true;
            }
        }
        return false;
    }

    private int detectLegacyPrefixLength(List<AuditLogEntry> auditLog) {
        int legacyPrefixLength = 0;
        String previousHash = "GENESIS";
        boolean sawValidRecord = false;

        for (int index = 0; index < auditLog.size(); index++) {
            AuditLogEntry entry = auditLog.get(index);
            if (entry.getSequenceNumber() != index + 1L) {
                return 0;
            }

            if (index == 0 && !"GENESIS".equals(entry.getPreviousHash())) {
                return 0;
            }

            if (index > 0 && !previousHash.equals(entry.getPreviousHash())) {
                return 0;
            }

            boolean matchesLegacyHash = calculateHash(
                    entry.getSequenceNumber(),
                    entry.getTimestamp(),
                    entry.getIncidentId(),
                    entry.getEventType(),
                    entry.getFilePath(),
                    entry.getSeverity(),
                    previousHash,
                    false
            ).equals(entry.getCurrentHash());

            boolean matchesCanonicalHash = calculateHash(
                    entry.getSequenceNumber(),
                    normalizeTimestamp(entry.getTimestamp()),
                    entry.getIncidentId(),
                    entry.getEventType(),
                    entry.getFilePath(),
                    entry.getSeverity(),
                    previousHash
            ).equals(entry.getCurrentHash());

            if (matchesLegacyHash || matchesCanonicalHash) {
                sawValidRecord = true;
                legacyPrefixLength = index + 1;
                previousHash = entry.getCurrentHash();
                continue;
            }

            if (sawValidRecord) {
                return 0;
            }

            previousHash = entry.getCurrentHash();
        }

        return sawValidRecord ? legacyPrefixLength : 0;
    }

    private long nextSequenceNumber(AuditLogEntry latestEntry) {
        long currentMaxSequence = latestEntry == null
                ? auditLogRepository.findAll(Sort.by(Sort.Direction.DESC, "sequenceNumber"))
                    .stream()
                    .mapToLong(AuditLogEntry::getSequenceNumber)
                    .findFirst()
                    .orElse(0L)
                : latestEntry.getSequenceNumber();

        if (mongoTemplate == null) {
            return currentMaxSequence + 1;
        }

        for (int attempt = 0; attempt < 10; attempt++) {
            Document existing = mongoTemplate.findOne(
                    Query.query(Criteria.where("_id").is(AUDIT_SEQUENCE_COUNTER_ID)),
                    Document.class,
                    AUDIT_COUNTER_COLLECTION
            );

            if (existing == null) {
                try {
                    long nextValue = currentMaxSequence + 1;
                    mongoTemplate.insert(
                            new Document("_id", AUDIT_SEQUENCE_COUNTER_ID).append("value", nextValue),
                            AUDIT_COUNTER_COLLECTION
                    );
                    return nextValue;
                } catch (DuplicateKeyException ignored) {
                    // Another request created the counter while we were initializing it.
                }
                continue;
            }

            long currentCounterValue = ((Number) existing.get("value")).longValue();
            if (currentCounterValue <= currentMaxSequence) {
                Document corrected = mongoTemplate.findAndModify(
                        Query.query(Criteria.where("_id").is(AUDIT_SEQUENCE_COUNTER_ID)),
                        new Update().set("value", currentMaxSequence + 1),
                        FindAndModifyOptions.options().returnNew(true),
                        Document.class,
                        AUDIT_COUNTER_COLLECTION
                );
                if (corrected != null && corrected.get("value") != null) {
                    return ((Number) corrected.get("value")).longValue();
                }
            }

            Document updated = mongoTemplate.findAndModify(
                    Query.query(Criteria.where("_id").is(AUDIT_SEQUENCE_COUNTER_ID)),
                    new Update().inc("value", 1),
                    FindAndModifyOptions.options().returnNew(true),
                    Document.class,
                    AUDIT_COUNTER_COLLECTION
            );

            if (updated != null && updated.get("value") != null) {
                return ((Number) updated.get("value")).longValue();
            }
        }

        throw new IllegalStateException("Unable to allocate a unique audit sequence number for " + AUDIT_SEQUENCE_COUNTER_ID);
    }

    private LocalDateTime normalizeTimestamp(LocalDateTime timestamp) {
        return timestamp == null ? null : timestamp.truncatedTo(ChronoUnit.MILLIS);
    }

    private String calculateHash(long sequenceNumber, LocalDateTime timestamp, String incidentId,
                                String eventType, String filePath, String severity, String previousHash) {
        return calculateHash(sequenceNumber, timestamp, incidentId, eventType, filePath, severity, previousHash, true);
    }

    private String calculateHash(long sequenceNumber, LocalDateTime timestamp, String incidentId,
                                String eventType, String filePath, String severity, String previousHash,
                                boolean normalizeToMilliseconds) {
        LocalDateTime effectiveTimestamp = normalizeToMilliseconds ? normalizeTimestamp(timestamp) : timestamp;
        String payload = sequenceNumber + "|" + effectiveTimestamp + "|" + incidentId + "|" + eventType + "|"
                + filePath + "|" + severity + "|" + previousHash;

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(payload.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();

            for (byte hashByte : hashBytes) {
                String hexValue = Integer.toHexString(0xff & hashByte);
                if (hexValue.length() == 1) {
                    hex.append('0');
                }
                hex.append(hexValue);
            }

            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not available", e);
        }
    }
}
