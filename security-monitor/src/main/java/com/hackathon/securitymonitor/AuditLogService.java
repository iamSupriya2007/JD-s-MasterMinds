package com.hackathon.securitymonitor;

import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class AuditLogService {

    private final List<AuditLogEntry> auditLog = new ArrayList<>();
    private final AtomicLong sequenceCounter = new AtomicLong(1);

    public AuditLogEntry appendEntry(String incidentId, String eventType, String filePath, String severity) {
        long sequenceNumber = sequenceCounter.getAndIncrement();
        LocalDateTime timestamp = LocalDateTime.now();
        String previousHash = auditLog.isEmpty() ? "GENESIS" : auditLog.get(auditLog.size() - 1).getCurrentHash();
        String currentHash = calculateHash(sequenceNumber, timestamp, incidentId, eventType, filePath, severity, previousHash);

        AuditLogEntry entry = new AuditLogEntry(sequenceNumber, timestamp, incidentId, eventType, filePath, severity, previousHash, currentHash);
        auditLog.add(entry);
        return entry;
    }

    public List<AuditLogEntry> getAuditLog() {
        return new ArrayList<>(auditLog);
    }

    public boolean verifyChain() {
        if (auditLog.isEmpty()) {
            return true;
        }

        for (int index = 0; index < auditLog.size(); index++) {
            AuditLogEntry entry = auditLog.get(index);
            String expectedPreviousHash = index == 0 ? "GENESIS" : auditLog.get(index - 1).getCurrentHash();

            if (index == 0 && !"GENESIS".equals(entry.getPreviousHash())) {
                return false;
            }

            if (index > 0 && !expectedPreviousHash.equals(entry.getPreviousHash())) {
                return false;
            }

            String expectedHash = calculateHash(
                    entry.getSequenceNumber(),
                    entry.getTimestamp(),
                    entry.getIncidentId(),
                    entry.getEventType(),
                    entry.getFilePath(),
                    entry.getSeverity(),
                    entry.getPreviousHash()
            );

            if (!expectedHash.equals(entry.getCurrentHash())) {
                return false;
            }
        }

        return true;
    }

    private String calculateHash(long sequenceNumber, LocalDateTime timestamp, String incidentId,
                                String eventType, String filePath, String severity, String previousHash) {
        String payload = sequenceNumber + "|" + timestamp + "|" + incidentId + "|" + eventType + "|"
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
